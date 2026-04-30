"""MemProcFS integration — extracts forensic artifacts from memory dumps.

Detects if MemProcFS is installed, mounts/extracts the memory image
into a temporary directory, and yields the extracted artifacts back
to the NightEye orchestrator for standard ingestion.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterator

__all__ = [
    "is_memprocfs_available",
    "extract_memprocfs",
]

logger = logging.getLogger("nighteye.ingest.memprocfs")


def is_memprocfs_available() -> bool:
    """Check if MemProcFS is available in PATH."""
    return shutil.which("MemProcFS") is not None or shutil.which("MemProcFS.exe") is not None


def extract_memprocfs(
    evidence_path: Path,
) -> Iterator[Path]:
    """Extract forensic artifacts from a memory dump using MemProcFS.

    MemProcFS will extract EVTX, Registry, MFT, etc., from the memory dump.
    This function yields the path to the temporary directory containing
    the extracted files so they can be ingested by standard parsers.

    Args:
        evidence_path: Path to the memory dump.

    Yields:
        Path to the root of the extracted MemProcFS forensic directory.
        (Yields exactly once if successful).
    """
    exe = shutil.which("MemProcFS") or shutil.which("MemProcFS.exe")
    if not exe:
        logger.warning("MemProcFS not found in PATH. Skipping bulk memory extraction.")
        return

    # Use a persistent temp directory for extraction so files aren't
    # deleted before the orchestrator can ingest them. The caller must
    # handle cleanup if desired, or we just rely on OS temp cleanup.
    out_dir = Path(tempfile.mkdtemp(prefix="nighteye_memprocfs_"))

    # Command: MemProcFS -device <file> -forensic 1 -extract <dir> -license
    # -forensic 1: Enables deep forensic parsing
    # -license: Accepts the license to enable built-in YARA scanning
    cmd = [
        exe,
        "-device", str(evidence_path),
        "-forensic", "1",
        "-extract", str(out_dir),
        "-license",
    ]

    logger.info("Extracting artifacts from memory dump %s via MemProcFS...", evidence_path.name)
    logger.debug("Command: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600,  # Extraction can be slow
        )
        if result.returncode != 0:
            logger.error("MemProcFS extraction failed: %s", result.stderr[:500])
            # Don't return yet, sometimes MemProcFS exits non-zero but still extracts data
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.error("MemProcFS execution failed: %s", exc)
        shutil.rmtree(out_dir, ignore_errors=True)
        return

    # Check if anything was actually extracted
    if not any(out_dir.iterdir()):
        logger.warning("MemProcFS extracted no files for %s.", evidence_path.name)
        shutil.rmtree(out_dir, ignore_errors=True)
        return

    logger.info("MemProcFS extraction complete. Artifacts saved to %s", out_dir)
    
    # Yield the extracted directory
    yield out_dir
