"""YARA scanner integration — scans extracted filesystem for malware signatures.

Runs YARA against extracted evidence directories and indexes matches
as ECS alert documents. YARA hits feed into constructor confidence scoring
as supporting evidence.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterator

from nighteye.ingest.ecs import build_ecs_doc

__all__ = [
    "is_yara_available",
    "run_yara",
    "parse_yara_output",
]

logger = logging.getLogger("nighteye.ingest.yara")

# Default YARA rule paths to check on SIFT
_YARA_RULE_PATHS: list[str] = [
    "/usr/share/yara-rules",
    "/opt/yara-rules",
    "/opt/signature-base",     # Florian Roth's signature-base
    "/opt/yara-forensics",     # Community forensics rules
    "/opt/neo23x0-yara",       # Florian Roth's signature-base
]


def is_yara_available() -> bool:
    return shutil.which("yara") is not None or shutil.which("yara64") is not None


def find_yara_rules() -> Path | None:
    """Find a directory containing YARA rule files."""
    for p in _YARA_RULE_PATHS:
        path = Path(p)
        if path.is_dir():
            for rule_file in path.rglob("*.yar*"):
                if rule_file.is_file():
                    return path
    return None


def run_yara(
    scan_path: Path,
    host_name: str,
    case_id: str,
    rule_dirs: list[Path] | None = None,
) -> Iterator[dict[str, Any]]:
    """Run YARA against a directory or file and yield ECS-mapped matches.

    Args:
        scan_path: Directory or file to scan.
        host_name: Host name for the events.
        case_id: Case ID.
        rule_dirs: Optional list of YARA rule directories.

    Yields:
        ECS alert documents, one per rule match.
    """
    exe = shutil.which("yara") or shutil.which("yara64")
    if not exe:
        logger.warning("YARA not found — skipping. Install: sudo apt install yara")
        return

    if rule_dirs is None:
        rules_root = find_yara_rules()
        if rules_root is None:
            logger.warning(
                "No YARA rules directory found. Download rules to one of: %s",
                ", ".join(_YARA_RULE_PATHS[:3]),
            )
            return
        rule_dirs = [rules_root]

    # Build rule file list — limit to 200MB of rules
    rule_files: list[Path] = []
    total_rules_size = 0
    for rd in rule_dirs:
        if not rd.is_dir():
            continue
        for rule_file in sorted(rd.rglob("*.yar*")):
            if rule_file.is_file():
                size = rule_file.stat().st_size
                total_rules_size += size
                rule_files.append(rule_file)
            if total_rules_size > 200_000_000:
                break
        if total_rules_size > 200_000_000:
            break

    if not rule_files:
        logger.warning("No YARA rule files found")
        return

    logger.info(
        "Running YARA with %d rule files against %s...",
        len(rule_files), scan_path.name,
    )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
        for rf in rule_files:
            if rf.suffix in (".yar", ".yara"):
                try:
                    rules = rf.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    try:
                        rules = rf.read_text(encoding="latin-1", errors="ignore")
                    except Exception:
                        continue
                # Strip C-style include directives that yara can't handle
                import re
                rules = re.sub(r'^#include\s+".*"', "// include stripped", rules, flags=re.MULTILINE)
                tmp.write(rules)
                tmp.write("\n")
        tmp.flush()

        try:
            result = subprocess.run(
                [exe, tmp.name, "-r", str(scan_path)],
                capture_output=True, text=True, timeout=1800,
            )
        except subprocess.TimeoutExpired:
            logger.warning("YARA scan timed out for %s", scan_path.name)
            Path(tmp.name).unlink(missing_ok=True)
            return
        except Exception as exc:
            logger.error("YARA execution failed: %s", exc)
            Path(tmp.name).unlink(missing_ok=True)
            return

        Path(tmp.name).unlink(missing_ok=True)

    if not result.stdout.strip():
        logger.debug("No YARA matches for %s", scan_path.name)
        return

    source_file = str(scan_path)
    match_count = 0
    for doc in parse_yara_output(result.stdout, host_name, source_file, case_id):
        match_count += 1
        yield doc

    logger.info("Found %d YARA matches for %s", match_count, host_name)


def parse_yara_output(
    output: str,
    host_name: str,
    source_file: str,
    case_id: str,
) -> Iterator[dict[str, Any]]:
    """Parse YARA output lines into ECS alert documents.

    YARA output format (per line):
        rule_name target_file
        rule_name [namespace] target_file:matched_offset

    Example:
        CobaltStrike_Beacon_Config  /path/to/file.exe
        SUSP_EXE_PE_Resources  [SUSP] /path/to/malware.exe:12345
    """
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if "warning:" in line.lower():
            continue

        # Parse: RULE_NAME [optional_namespace] FILE_PATH
        parts = line.split()
        if len(parts) < 2:
            continue

        rule_name = parts[0]
        target = parts[-1]

        # Extract namespace if present: rule [NSP] file
        namespace = ""
        if len(parts) >= 3 and parts[1].startswith("[") and parts[1].endswith("]"):
            namespace = parts[1][1:-1]

        # Extract offset if present (file:offset)
        match_offset = ""
        if ":" in target:
            path_part, _, offset_part = target.rpartition(":")
            if offset_part.isdigit():
                target = path_part
                match_offset = offset_part

        doc = build_ecs_doc(
            host_name=host_name,
            event_code="yara_match",
            event_action="malware-scan-hit",
            event_category="malware",
            nighteye_source_file=source_file,
            nighteye_audit_id=f"yara-{case_id}",
            nighteye_parser="yara",
            nighteye_canonical_type="ALERT",
            extra={
                "rule.name": rule_name,
                "rule.namespace": namespace,
                "file.target": target,
                "file.offset": match_offset,
            },
        )
        doc["event"]["kind"] = "alert"
        yield doc
