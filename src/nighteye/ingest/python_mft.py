"""MFT parser via sleuthkit ``fls`` — fallback when MFTECmd is unavailable.

Runs ``fls -m / -r -l -p <mft_path>`` to get bodyfile output and
converts each entry to an ECS document.

Bodyfile format: ``MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime``
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("nighteye.ingest.python_mft")


def parse_mft(
    path: Path,
    *,
    host_name: str = "",
    source_file: str = "",
    audit_id: str = "",
) -> Iterator[dict[str, Any]]:
    """Yield ECS documents from an MFT file via sleuthkit ``fls``.

    If sleuthkit ``fls`` is not available on PATH, logs a warning and
    yields nothing.

    Args:
        path: Path to the $MFT file.
        host_name: Host name for the host.name ECS field.
        source_file: Source file path for provenance.
        audit_id: Audit trail ID.

    Yields:
        ECS document dicts, one per file entry.
    """
    if not _fls_available():
        logger.warning(
            "sleuthkit 'fls' not found on PATH; cannot parse MFT: %s",
            path.name,
        )
        return

    from nighteye.ingest.ecs import build_ecs_doc

    try:
        result = subprocess.run(
            ["fls", "-m", "/", "-r", "-l", "-p", str(path)],
            capture_output=True,
            text=True,
            timeout=600,
        )
    except FileNotFoundError:
        logger.warning("fls not found; skipping MFT %s", path.name)
        return
    except subprocess.TimeoutExpired:
        logger.error("fls timed out on %s (10 min)", path.name)
        return
    except OSError as exc:
        logger.error("fls failed on %s: %s", path.name, exc)
        return

    if result.returncode != 0:
        stderr = (result.stderr or "")[:500]
        logger.debug("fls returned %d on %s: %s", result.returncode, path.name, stderr)
        if not result.stdout.strip():
            return

    count = 0
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        parsed = _parse_bodyfile_line(line)
        if parsed is None:
            continue

        count += 1
        if count > 2_000_000:
            logger.warning(
                "MFT %s exceeded 2M entries; truncating",
                path.name,
            )
            return

        (name, inode, uid, gid, size, atime, mtime, ctime, crtime, md5_hash) = parsed

        extra: dict[str, Any] = {
            "mft.inode": inode,
            "mft.uid": uid,
            "mft.gid": gid,
            "mft.size": size,
            "mft.atime": _unix_to_iso(atime),
            "mft.mtime": _unix_to_iso(mtime),
            "mft.ctime": _unix_to_iso(ctime),
            "mft.crtime": _unix_to_iso(crtime),
            "mft.md5": md5_hash,
            "mft.source": str(path),
        }

        timestamp = _unix_to_iso(mtime) or _unix_to_iso(crtime) or _unix_to_iso(atime)

        doc = build_ecs_doc(
            timestamp=timestamp,
            host_name=host_name,
            event_action="file-metadata",
            event_category="file",
            file_path=name,
            nighteye_source_file=source_file or str(path),
            nighteye_audit_id=audit_id,
            nighteye_parser="fls-mft",
            nighteye_parser_version="sleuthkit",
            nighteye_canonical_type="MFT_ENTRY",
            extra=extra,
        )
        yield doc

    logger.debug("Parsed %d entries from MFT %s via fls", count, path.name)


# ── helpers ────────────────────────────────────────────────────


def _fls_available() -> bool:
    """Check if sleuthkit's ``fls`` is on PATH."""
    if shutil.which("fls"):
        return True
    extra = ["/usr/local/bin", "/usr/bin", "/opt/sleuthkit/bin"]
    return any((Path(p) / "fls").exists() for p in extra)


def _parse_bodyfile_line(line: str) -> tuple | None:
    """Parse a bodyfile line into its components.

    Bodyfile format (TSK 4.x):
        md5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime

    Returns (name, inode, uid, gid, size, atime, mtime, ctime, crtime, md5)
    or None if the line is malformed.
    """
    parts = line.split("|")
    if len(parts) < 10:
        return None

    try:
        md5_hash = parts[0].strip() or "0"
        name = parts[1]
        inode = parts[2].strip() or "0"
        _ = parts[3]  # mode — unused
        uid = parts[4].strip() or ""
        gid = parts[5].strip() or ""
        size_str = parts[6].strip() or "0"
        atime_str = parts[7].strip() or "0"
        mtime_str = parts[8].strip() or "0"
        ctime_str = parts[9].strip() or "0"
        crtime_str = parts[10].strip() if len(parts) > 10 else "0"

        size = int(size_str) if size_str.lstrip("-").isdigit() else 0
        atime = int(atime_str) if atime_str.lstrip("-").isdigit() else 0
        mtime = int(mtime_str) if mtime_str.lstrip("-").isdigit() else 0
        ctime = int(ctime_str) if ctime_str.lstrip("-").isdigit() else 0
        crtime = int(crtime_str) if crtime_str.lstrip("-").isdigit() else 0
    except (ValueError, IndexError):
        return None

    return (name, inode, uid, gid, size, atime, mtime, ctime, crtime, md5_hash)


def _unix_to_iso(ts: int) -> str | None:
    """Convert a Unix timestamp (seconds) to ISO 8601 UTC string."""
    if ts <= 0:
        return None
    try:
        dt = datetime.fromtimestamp(ts, tz=datetime.UTC)
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
    except (ValueError, OSError):
        return None
