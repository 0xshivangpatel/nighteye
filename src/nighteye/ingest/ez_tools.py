"""EZ Tools runner — executes Zimmerman tools and streams CSV output.

Wraps RECmd, MFTECmd, PECmd, AmcacheParser, AppCompatCacheParser,
and SrumECmd. Executes the tool against an evidence file, captures
the CSV output, and yields rows as dictionaries.
"""

from __future__ import annotations

import csv
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterator

from nighteye.ingest.dispatch import EvidenceType

__all__ = ["run_ez_tool", "is_tool_available"]

logger = logging.getLogger("nighteye.ingest.ez_tools")

# Map evidence types to their respective EZ Tool executable names
_TOOL_MAP: dict[EvidenceType, str] = {
    EvidenceType.REGISTRY_HIVE: "RECmd",
    EvidenceType.MFT: "MFTECmd",
    EvidenceType.PREFETCH: "PECmd",
    EvidenceType.AMCACHE: "AmcacheParser",
    EvidenceType.SHIMCACHE: "AppCompatCacheParser",
    EvidenceType.SRUM: "SrumECmd",
}


def is_tool_available(evidence_type: EvidenceType) -> bool:
    """Check if the required EZ Tool is available on PATH."""
    tool_name = _TOOL_MAP.get(evidence_type)
    if not tool_name:
        # Some types (like KAPE_ZIP or EVTX_FOLDER) don't use a single EZ Tool directly
        return evidence_type in {EvidenceType.EVTX_FOLDER, EvidenceType.EVTX_FILE, EvidenceType.KAPE_ZIP}
        
    # Check standard PATH
    if shutil.which(tool_name) or shutil.which(f"{tool_name}.exe") or shutil.which(f"{tool_name}.sh"):
        return True
        
    # Check common SIFT/Linux locations explicitly
    extra_paths = ["/usr/local/bin", "/opt/zimmerman", "/opt/zimmermantools", "/opt/eztools"]
    for p in extra_paths:
        for ext in ["", ".exe", ".sh"]:
            if (Path(p) / f"{tool_name}{ext}").exists():
                return True
                
    return False


def run_ez_tool(
    evidence_type: EvidenceType,
    evidence_path: Path,
) -> Iterator[dict[str, Any]]:
    """Run an EZ Tool and stream its CSV output.

    Executes the tool, instructing it to write a CSV to a temporary
    directory. Once complete, streams the CSV rows back to the caller
    as dictionaries, and cleans up the temporary files.

    Args:
        evidence_type: The type of evidence (determines which tool to run).
        evidence_path: Path to the evidence file/directory.

    Yields:
        Dictionaries representing CSV rows.
    """
    tool_name = _TOOL_MAP.get(evidence_type)
    if not tool_name:
        logger.error("No EZ Tool mapped for evidence type: %s", evidence_type)
        return

    # Find the executable
    exe_path = shutil.which(tool_name) or shutil.which(f"{tool_name}.exe") or shutil.which(f"{tool_name}.sh")
    if not exe_path:
        # Check common SIFT/Linux locations explicitly
        extra_paths = ["/usr/local/bin", "/opt/zimmerman", "/opt/eztools"]
        for p in extra_paths:
            for ext in ["", ".exe", ".sh"]:
                candidate = Path(p) / f"{tool_name}{ext}"
                if candidate.exists():
                    exe_path = str(candidate)
                    break
            if exe_path:
                break
                
    if not exe_path:
        logger.error("EZ Tool not found: %s", tool_name)
        return

    with tempfile.TemporaryDirectory(prefix=f"nighteye_{tool_name}_") as tmpdir:
        # Standard EZ Tools arguments: -f <file> --csv <dir>
        # SrumECmd uses -d for directory if it's pointing to the SoftwareDistribution folder,
        # but usually -f for the srudb.dat file. We assume -f for all files.
        cmd = [
            exe_path,
            "-f" if evidence_path.is_file() else "-d",
            str(evidence_path),
            "--csv", tmpdir,
        ]

        logger.debug("Running: %s", " ".join(cmd))
        try:
            # We don't need the stdout, but we capture it in case of errors
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout per file
            )
            if result.returncode != 0:
                # Some EZ Tools return non-zero even on success if they hit minor errors.
                # We'll log it but still try to read the CSV if it was generated.
                logger.debug("%s returned %d: %s", tool_name, result.returncode, result.stderr[:500])
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.error("%s failed to execute: %s", tool_name, exc)
            return

        # Find the generated CSV file
        csv_files = list(Path(tmpdir).glob("*.csv"))
        if not csv_files:
            logger.warning("%s did not produce a CSV output for %s", tool_name, evidence_path.name)
            return

        # There should only be one CSV, but we'll process any found
        for csv_file in csv_files:
            logger.debug("Streaming CSV: %s", csv_file)
            try:
                # EZ Tools output UTF-8 with BOM
                with open(csv_file, "r", encoding="utf-8-sig") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        yield row
            except Exception as exc:
                logger.error("Failed to read CSV output %s: %s", csv_file, exc)
