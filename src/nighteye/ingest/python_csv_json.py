"""Generic CSV / JSON / JSONL / bodyfile timeline parser.

Accepts timeline output from tools like plaso, log2timeline, Volatility
timeliner, Redline, or any CSV/JSONL export and yields ECS documents
with the parsed data in the ``extra`` field.

Supports streaming for large files.
"""

from __future__ import annotations

import csv
import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

logger = logging.getLogger("nighteye.ingest.python_csv_json")


def parse_csv_json(
    path: Path,
    *,
    host_name: str = "",
    source_file: str = "",
    audit_id: str = "",
) -> Iterator[dict[str, Any]]:
    """Yield ECS documents from a CSV, JSON, JSONL, or bodyfile.

    Auto-detects format by extension:
        - ``.csv``  → CSV with DictReader
        - ``.json`` → JSON array or object
        - ``.jsonl`` → one JSON record per line
        - ``.txt`` / ``.body`` → pipe-delimited bodyfile format

    Each row/record is placed in the ECS ``extra`` field. Timestamps
    are extracted from common field names when possible.

    Args:
        path: Path to the timeline file.
        host_name: Host name for the host.name ECS field.
        source_file: Source file path for provenance.
        audit_id: Audit trail ID.

    Yields:
        ECS document dicts.
    """
    ext = path.suffix.lower()

    try:
        if ext in (".jsonl",):
            yield from _parse_jsonl(path, host_name, source_file, audit_id)
        elif ext in (".json",):
            yield from _parse_json(path, host_name, source_file, audit_id)
        elif ext in (".csv",):
            yield from _parse_csv(path, host_name, source_file, audit_id)
        elif ext in (".txt", ".body", ""):
            yield from _parse_bodyfile(path, host_name, source_file, audit_id)
        else:
            logger.debug("Unknown timeline extension %s for %s; skipping", ext, path.name)
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", path.name, exc)


# ── JSONL ──────────────────────────────────────────────────────


def _parse_jsonl(
    path: Path,
    host_name: str,
    source_file: str,
    audit_id: str,
) -> Iterator[dict[str, Any]]:
    """Stream JSONL (one JSON object per line)."""

    count = 0
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    logger.debug("Skipping malformed JSONL line in %s", path.name)
                    continue

                if not isinstance(record, dict):
                    continue

                count += 1
                if count > 5_000_000:
                    logger.warning("JSONL %s exceeded 5M records; truncating", path.name)
                    return

                doc = _record_to_doc(record, host_name, source_file, audit_id)
                yield doc

    except (OSError, PermissionError) as exc:
        logger.warning("Cannot read %s: %s", path.name, exc)

    logger.debug("Parsed %d JSONL records from %s", count, path.name)


# ── JSON ───────────────────────────────────────────────────────


def _parse_json(
    path: Path,
    host_name: str,
    source_file: str,
    audit_id: str,
) -> Iterator[dict[str, Any]]:
    """Parse a JSON file (single object or array)."""

    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError) as exc:
        logger.warning("Cannot read %s: %s", path.name, exc)
        return

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.debug("Invalid JSON in %s: %s", path.name, exc)
        return

    count = 0

    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            count += 1
            if count > 5_000_000:
                logger.warning("JSON %s exceeded 5M records; truncating", path.name)
                return
            doc = _record_to_doc(item, host_name, source_file, audit_id)
            yield doc

    elif isinstance(data, dict):
        doc = _record_to_doc(data, host_name, source_file, audit_id)
        yield doc
        count = 1

    logger.debug("Parsed %d JSON records from %s", count, path.name)


# ── CSV ────────────────────────────────────────────────────────


def _parse_csv(
    path: Path,
    host_name: str,
    source_file: str,
    audit_id: str,
) -> Iterator[dict[str, Any]]:
    """Stream CSV rows via csv.DictReader."""

    count = 0
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            try:
                sample = fh.read(4096)
                fh.seek(0)
            except Exception:
                sample = ""

            try:
                dialect = csv.Sniffer().sniff(sample[:4096])
            except csv.Error:
                dialect = csv.excel

            reader = csv.DictReader(fh, dialect=dialect)
            if reader.fieldnames is None:
                logger.debug("CSV %s has no header row", path.name)
                return

            for row in reader:
                count += 1
                if count > 5_000_000:
                    logger.warning("CSV %s exceeded 5M rows; truncating", path.name)
                    return
                doc = _record_to_doc(row, host_name, source_file, audit_id)
                yield doc

    except (OSError, PermissionError) as exc:
        logger.warning("Cannot read %s: %s", path.name, exc)

    logger.debug("Parsed %d CSV rows from %s", count, path.name)


# ── Bodyfile ───────────────────────────────────────────────────


def _parse_bodyfile(
    path: Path,
    host_name: str,
    source_file: str,
    audit_id: str,
) -> Iterator[dict[str, Any]]:
    """Parse a bodyfile (pipe-delimited timeline)."""
    from nighteye.ingest.ecs import build_ecs_doc

    _BODYFILE_HEADERS = [
        "md5", "name", "inode", "mode", "uid", "gid",
        "size", "atime", "mtime", "ctime", "crtime",
    ]

    count = 0
    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.DictReader(
                fh,
                fieldnames=_BODYFILE_HEADERS,
                delimiter="|",
                restkey="extra_fields",
            )
            for row in reader:
                count += 1
                if count > 5_000_000:
                    logger.warning("Bodyfile %s exceeded 5M rows; truncating", path.name)
                    return

                name = row.get("name", "")
                ts = _extract_bodyfile_timestamp(row)

                extra: dict[str, Any] = {
                    "bodyfile.md5": row.get("md5", ""),
                    "bodyfile.name": name,
                    "bodyfile.inode": row.get("inode", ""),
                    "bodyfile.mode": row.get("mode", ""),
                    "bodyfile.uid": row.get("uid", ""),
                    "bodyfile.gid": row.get("gid", ""),
                    "bodyfile.size": row.get("size", ""),
                    "bodyfile.atime": row.get("atime", ""),
                    "bodyfile.mtime": row.get("mtime", ""),
                    "bodyfile.ctime": row.get("ctime", ""),
                    "bodyfile.crtime": row.get("crtime", ""),
                }

                doc = build_ecs_doc(
                    timestamp=ts,
                    host_name=host_name,
                    event_action="timeline-entry",
                    event_category="file",
                    file_path=name,
                    nighteye_source_file=source_file or str(path),
                    nighteye_audit_id=audit_id,
                    nighteye_parser="python_bodyfile",
                    nighteye_canonical_type="BODYFILE_ENTRY",
                    extra=extra,
                )
                yield doc

    except (OSError, PermissionError) as exc:
        logger.warning("Cannot read %s: %s", path.name, exc)
        return

    # If bodyfile parsing produced nothing, fall back to CSV
    if count == 0:
        logger.debug("Bodyfile parse yielded 0 rows; trying CSV for %s", path.name)
        yield from _parse_csv(path, host_name, source_file, audit_id)
    else:
        logger.debug("Parsed %d bodyfile rows from %s", count, path.name)


def _extract_bodyfile_timestamp(row: dict[str, str]) -> str | None:
    """Try to extract an ISO timestamp from bodyfile unixtime fields."""
    for field in ("mtime", "crtime", "atime", "ctime"):
        val = row.get(field, "")
        if val and val.lstrip("-").isdigit():
            try:
                ts = int(val)
                if ts > 0:
                    from datetime import datetime
                    dt = datetime.fromtimestamp(ts, tz=datetime.UTC)
                    return dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
            except (ValueError, OSError):
                pass
    return None


# ── shared ─────────────────────────────────────────────────────


# Common timestamp field names to extract from records
_TIMESTAMP_KEYS = (
    "@timestamp", "timestamp", "time", "date", "datetime",
    "created", "creation_time", "created_at",
    "modified", "mtime", "modified_at",
    "accessed", "atime", "accessed_at",
    "last_run", "lastrun", "last_seen",
    "event_time", "eventtime", "log_time",
    "crtime", "ctime", "birth",
)


def _record_to_doc(
    record: dict[str, Any],
    host_name: str,
    source_file: str,
    audit_id: str,
) -> dict[str, Any]:
    """Convert a generic dict record into an ECS document.

    Attempts to extract a timestamp from common field names.
    """
    from nighteye.ingest.ecs import build_ecs_doc

    ts = _extract_timestamp(record)
    name = record.get("name", "") or record.get("filename", "") or record.get("file", "") or ""
    proc = record.get("process_name", "") or record.get("exe", "") or record.get("executable", "") or ""

    extra = {"raw." + str(k): v for k, v in record.items() if v is not None}

    return build_ecs_doc(
        timestamp=ts,
        host_name=host_name,
        event_action="timeline-entry",
        event_category="iam" if proc else "file",
        process_name=proc,
        file_path=name,
        nighteye_source_file=source_file,
        nighteye_audit_id=audit_id,
        nighteye_parser="python_csv_json",
        nighteye_canonical_type="TIMELINE_ENTRY",
        extra=extra,
    )


def _extract_timestamp(record: dict[str, Any]) -> str | None:
    """Extract the best available timestamp from a record dict."""
    from datetime import datetime

    for key in _TIMESTAMP_KEYS:
        val = record.get(key)
        if val is None:
            continue
        if isinstance(val, (int, float)):
            if val <= 0:
                continue
            try:
                # Detect precision by magnitude
                #  seconds: ~1.7e9    ms: ~1.7e12   us: ~1.7e15   100ns: ~1.7e17
                if val > 1e16:
                    val = val / 10_000_000
                elif val > 1e14:
                    val = val / 1_000_000
                elif val > 1e11:
                    val = val / 1_000
                dt = datetime.fromtimestamp(val, tz=datetime.UTC)
                return dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
            except (ValueError, OSError):
                continue
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None
