"""Windows Prefetch (.pf) parser — libscca-backed with pure-Python fallback.

Win8.1+ prefetch files are MAM-compressed (Xpress Huffman); the pure-Python
parser only handles legacy uncompressed SCCA. libscca (pyscca, installed via
the libscca-python3 apt package) decompresses MAM natively and exposes a
clean object model. We try pyscca first and fall back to the binary parser
for headers it cannot read.
"""

from __future__ import annotations

import logging
import struct
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    import pyscca  # type: ignore[import-not-found]
    _HAVE_PYSCCA = True
except ImportError:
    _HAVE_PYSCCA = False

logger = logging.getLogger("nighteye.ingest.python_prefetch")


def parse_prefetch(
    path: Path,
    *,
    host_name: str = "",
    source_file: str = "",
    audit_id: str = "",
) -> Iterator[dict[str, Any]]:
    """Yield ECS documents from a Windows Prefetch (.pf) file.

    Yields one document per loaded module per run time found. If no
    modules are present, yields one document per last-run timestamp.

    Args:
        path: Path to the .pf file.
        host_name: Host name for the host.name ECS field.
        source_file: Source file path for provenance.
        audit_id: Audit trail ID.

    Yields:
        ECS document dicts.
    """
    if _HAVE_PYSCCA:
        try:
            yield from _parse_with_pyscca(
                path, host_name=host_name,
                source_file=source_file, audit_id=audit_id,
            )
            return
        except Exception as exc:
            logger.debug("pyscca failed on %s, falling back: %s", path.name, exc)

    yield from _parse_binary(
        path, host_name=host_name,
        source_file=source_file, audit_id=audit_id,
    )


def _parse_with_pyscca(
    path: Path,
    *,
    host_name: str,
    source_file: str,
    audit_id: str,
) -> Iterator[dict[str, Any]]:
    """Parse using libscca (handles MAM-compressed Win8.1+ prefetch)."""
    from nighteye.ingest.ecs import build_ecs_doc

    pf = pyscca.open(str(path))
    try:
        executable = pf.get_executable_filename() or ""
        if not executable:
            return

        version = pf.get_format_version()
        run_count = pf.get_run_count() or 0
        pf_hash = pf.get_prefetch_hash() or 0

        modules: list[str] = []
        for i in range(pf.get_number_of_filenames()):
            try:
                fname = pf.get_filename(i)
                if fname:
                    modules.append(fname)
            except Exception:
                continue

        last_runs: list[tuple[str | None, int]] = []
        for i in range(8):
            try:
                dt = pf.get_last_run_time(i)
                if dt is None:
                    continue
                ts = dt.isoformat().replace("+00:00", "Z")
                last_runs.append((ts, 0))
            except (OSError, ValueError):
                continue

        if not last_runs and run_count:
            last_runs = [(None, 0)]

        for i, (ts_iso, _) in enumerate(last_runs):
            if modules:
                for module_name in modules:
                    yield build_ecs_doc(
                        timestamp=ts_iso,
                        host_name=host_name,
                        event_action="process-execution-evidence",
                        event_category="process",
                        process_name=executable,
                        nighteye_source_file=source_file or str(path),
                        nighteye_audit_id=audit_id,
                        nighteye_parser="pyscca",
                        nighteye_canonical_type="PREFETCH",
                        extra={
                            "prefetch.executable": executable,
                            "prefetch.run_count": run_count,
                            "prefetch.run_index": i,
                            "prefetch.last_run": ts_iso,
                            "prefetch.loaded_module": module_name,
                            "prefetch.hash": pf_hash,
                            "prefetch.version": version,
                            "prefetch.file": str(path),
                        },
                    )
            else:
                yield build_ecs_doc(
                    timestamp=ts_iso,
                    host_name=host_name,
                    event_action="process-execution-evidence",
                    event_category="process",
                    process_name=executable,
                    nighteye_source_file=source_file or str(path),
                    nighteye_audit_id=audit_id,
                    nighteye_parser="pyscca",
                    nighteye_canonical_type="PREFETCH",
                    extra={
                        "prefetch.executable": executable,
                        "prefetch.run_count": run_count,
                        "prefetch.run_index": i,
                        "prefetch.last_run": ts_iso,
                        "prefetch.hash": pf_hash,
                        "prefetch.version": version,
                        "prefetch.file": str(path),
                    },
                )
    finally:
        pf.close()


def _parse_binary(
    path: Path,
    *,
    host_name: str,
    source_file: str,
    audit_id: str,
) -> Iterator[dict[str, Any]]:
    """Pure-Python fallback for legacy uncompressed SCCA prefetch."""
    from nighteye.ingest.ecs import build_ecs_doc

    try:
        data = path.read_bytes()
    except (OSError, PermissionError) as exc:
        logger.debug("Cannot read %s: %s", path.name, exc)
        return

    if len(data) < 0x84:
        logger.debug("%s: file too small (%d bytes)", path.name, len(data))
        return

    sig = data[0:4]
    if not _is_valid_signature(sig):
        logger.debug("%s: not a prefetch file (sig=%r)", path.name, sig)
        return

    try:
        version = struct.unpack_from("<I", data, 4)[0]
    except struct.error:
        logger.debug("%s: cannot read version", path.name)
        return

    executable = _extract_executable_name(data)
    if not executable:
        logger.debug("%s: no executable name found", path.name)
        return

    pf_hash = _read_uint32(data, 0x4C)
    run_count = _extract_run_count(data, version)
    modules = _extract_modules(data)
    last_runs = _extract_last_run_times(data, version)

    if not last_runs and run_count:
        last_runs = [(None, None)]

    for i, (ts_iso, _ts_ft) in enumerate(last_runs):
        if modules:
            for module_name in modules:
                doc = build_ecs_doc(
                    timestamp=ts_iso,
                    host_name=host_name,
                    event_action="process-execution-evidence",
                    event_category="process",
                    process_name=executable,
                    nighteye_source_file=source_file or str(path),
                    nighteye_audit_id=audit_id,
                    nighteye_parser="python_prefetch",
                    nighteye_canonical_type="PREFETCH",
                    extra={
                        "prefetch.executable": executable,
                        "prefetch.run_count": run_count,
                        "prefetch.run_index": i,
                        "prefetch.last_run": ts_iso,
                        "prefetch.loaded_module": module_name,
                        "prefetch.hash": pf_hash,
                        "prefetch.version": version,
                        "prefetch.file": str(path),
                    },
                )
                yield doc
        else:
            doc = build_ecs_doc(
                timestamp=ts_iso,
                host_name=host_name,
                event_action="process-execution-evidence",
                event_category="process",
                process_name=executable,
                nighteye_source_file=source_file or str(path),
                nighteye_audit_id=audit_id,
                nighteye_parser="python_prefetch",
                nighteye_canonical_type="PREFETCH",
                extra={
                    "prefetch.executable": executable,
                    "prefetch.run_count": run_count,
                    "prefetch.run_index": i,
                    "prefetch.last_run": ts_iso,
                    "prefetch.hash": pf_hash,
                    "prefetch.version": version,
                    "prefetch.file": str(path),
                },
            )
            yield doc


# ── binary helpers ─────────────────────────────────────────────


def _is_valid_signature(sig: bytes) -> bool:
    """Check if the 4-byte signature matches SCCA (XP) or MAM (Win8.1+)."""
    return sig == b"SCCA" or sig.startswith(b"MAM")


def _read_uint32(data: bytes, offset: int) -> int:
    """Read a little-endian uint32 at offset, returns 0 on failure."""
    if offset + 4 > len(data):
        return 0
    try:
        return struct.unpack_from("<I", data, offset)[0]
    except struct.error:
        return 0


def _read_filetime(data: bytes, offset: int) -> int:
    """Read a Windows FILETIME (uint64) at offset, returns 0 on failure."""
    if offset + 8 > len(data):
        return 0
    try:
        return struct.unpack_from("<Q", data, offset)[0]
    except struct.error:
        return 0


def _filetime_to_datetime(ft: int) -> datetime | None:
    """Convert Windows FILETIME (100ns since 1601-01-01) to UTC datetime.

    FILETIME epoch is 1601-01-01T00:00:00Z.
    Unix epoch offset = 11644473600 seconds = 116444736000000000 * 100ns intervals.
    """
    if ft <= 0:
        return None
    # FILETIME is number of 100-nanosecond intervals since 1601-01-01
    # The number of 100ns intervals from 1601-01-01 to 1970-01-01
    _EPOCH_OFFSET = 116444736000000000
    if ft <= _EPOCH_OFFSET:
        return None
    try:
        unix_us = (ft - _EPOCH_OFFSET) // 10
        return datetime.fromtimestamp(unix_us / 1_000_000, tz=datetime.UTC)
    except (ValueError, OSError):
        return None


def _extract_executable_name(data: bytes) -> str:
    """Extract the null-terminated UTF-16LE executable name at offset 0x10."""
    try:
        raw = data[0x10:0x10 + 60]
        null_idx = raw.find(b"\x00\x00")
        if null_idx != -1:
            raw = raw[:null_idx]
        name = raw.decode("utf-16-le", errors="replace").strip()
        return name
    except UnicodeDecodeError:
        return ""


def _extract_run_count(data: bytes, version: int) -> int:
    """Extract run count from known offsets based on format version."""
    candidates = [0x64]
    if version == 17:
        candidates = [0x64]
    elif version == 23:
        candidates = [0x78, 0x64]
    elif version in (26, 30):
        candidates = [0x98, 0x78, 0x64, 0xD0]
    else:
        candidates = [0x64, 0x78, 0x98, 0xD0]

    for offset in candidates:
        val = _read_uint32(data, offset)
        if 0 < val < 100_000_000:
            return val
    return 0


def _extract_last_run_times(
    data: bytes, version: int
) -> list[tuple[str | None, int]]:
    """Extract up to 8 last-run FILETIME timestamps.

    Returns list of (ISO_8601_string, raw_filetime) tuples. Empty string
    for ISO if timestamp is invalid.
    """
    results: list[tuple[str | None, int]] = []

    if version <= 17:
        offsets = [0x78]
    else:
        offsets = [0x80 + i * 8 for i in range(8)]

    for off in offsets:
        ft = _read_filetime(data, off)
        if ft <= 0:
            continue
        dt = _filetime_to_datetime(ft)
        ts = dt.isoformat().replace("+00:00", "Z") if dt else None
        if ts:
            results.append((ts, ft))

    # fallback: try alternate offset set for newer versions
    if not results and version > 17:
        for off in [0x98 + i * 8 for i in range(8)]:
            ft = _read_filetime(data, off)
            if ft <= 0:
                continue
            dt = _filetime_to_datetime(ft)
            ts = dt.isoformat().replace("+00:00", "Z") if dt else None
            if ts:
                results.append((ts, ft))

    return results


def _extract_modules(data: bytes) -> list[str]:
    """Extract loaded module filenames from Section D.

    Section D offset is at 0x6C, entry count at 0x70. Each entry is a
    null-terminated UTF-16LE string.
    """
    section_d_offset = _read_uint32(data, 0x6C)
    section_d_count = _read_uint32(data, 0x70)

    if section_d_offset <= 0 or section_d_count <= 0:
        return []
    if section_d_offset + 2 > len(data):
        return []

    modules: list[str] = []
    pos = section_d_offset
    max_entries = min(section_d_count, 10000)

    try:
        for _ in range(max_entries):
            if pos + 2 > len(data):
                break
            end = pos
            while end + 2 <= len(data):
                if data[end:end + 2] == b"\x00\x00":
                    break
                end += 2
            if end > pos:
                raw_chunk = data[pos:end]
                mod = raw_chunk.decode("utf-16-le", errors="replace").strip()
                if mod:
                    modules.append(mod)
            pos = end + 2
    except Exception:
        pass

    return modules
