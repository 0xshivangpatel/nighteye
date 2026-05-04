"""Redline .mans (SQLite) ingest module.

Parses Mandiant Redline analysis files which are SQLite databases
containing memory-resident artifacts: processes, API hooks, services,
registry keys, event logs, timeline items, MRI hits, and IOC alerts.

These artifacts complement Plaso timeline CSVs by providing the
*runtime* view of the system at acquisition time.

References:
    - docs/ARCHITECTURE.md § 5 (Layer 1: Wide Evidence Ingestion)
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from nighteye.ingest.ecs import build_ecs_doc, compute_doc_id, make_index_name
from nighteye.ingest.opensearch_client import NightEyeOSClient

__all__ = ["ingest_redline_mans", "stream_redline_mans"]

logger = logging.getLogger("nighteye.ingest.redline_mans")


# ------------------------------------------------------------------
# Schema helpers
# ------------------------------------------------------------------

def _ts(value: str | None) -> str:
    """Normalise a Redline timestamp to ISO-8601 UTC."""
    if not value:
        return datetime.now(timezone.utc).isoformat()
    value = value.strip()
    for fmt in ("%Y-%m-%d %H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            dt = datetime.strptime(value, fmt)
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return datetime.now(timezone.utc).isoformat()


def _row_to_dict(cursor, row) -> dict[str, Any]:
    """Convert a sqlite3 row to a dict keyed by column names."""
    return {desc[0]: row[idx] for idx, desc in enumerate(cursor.description)}


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    cur = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    )
    return cur.fetchone() is not None


# ------------------------------------------------------------------
# Table parsers -> ECS generators
# ------------------------------------------------------------------

def _parse_processes(conn: sqlite3.Connection, host: str) -> Iterator[dict[str, Any]]:
    """Yield ECS docs for each process in the Redline DB."""
    if not _table_exists(conn, "Processes"):
        return
    cur = conn.execute(
        "SELECT PID, ParentPID, Username, Path, ProcessName, Arguments, StartTime, Hidden, SID FROM Processes"
    )
    for row in cur:
        r = _row_to_dict(cur, row)
        proc_name = r.get("ProcessName") or ""
        proc_path = r.get("Path") or ""  # working directory

        # Arguments is the full command line including executable.
        # Extract the real executable path from it.
        args = (r.get("Arguments") or "").strip()
        if args and not proc_name:
            proc_name = args.split("\\")[-1].split(" ")[0].strip('"')

        # Try to extract executable from Arguments
        executable = ""
        cmdline = args
        if args:
            import shlex
            try:
                tokens = shlex.split(args)
                if tokens:
                    executable = tokens[0]
            except Exception:
                # Fallback: first space-delimited token, strip quotes
                executable = args.split(" ", 1)[0].strip('"\'')

        # If no Arguments, use Path as executable
        if not executable and proc_path:
            executable = proc_path + "\\" + proc_name if proc_name else proc_path

        yield build_ecs_doc(
            timestamp=_ts(r.get("StartTime")),
            host_name=host,
            event_action="process-started",
            event_category=["process"],
            process_pid=r.get("PID"),
            process_parent_pid=r.get("ParentPID"),
            process_name=proc_name,
            process_executable=executable,
            process_command_line=cmdline if cmdline else executable,
            user_name=r.get("Username") or "",
            user_id=r.get("SID") or "",
            extra={
                "redline": {"hidden": r.get("Hidden") or "False", "working_dir": proc_path},
            },
        )


def _parse_hooks(conn: sqlite3.Connection, host: str) -> Iterator[dict[str, Any]]:
    """Yield ECS docs for API hooks (process injection indicators)."""
    if not _table_exists(conn, "Hooks"):
        return
    cur = conn.execute(
        "SELECT HookDescription, HookedFunction, HookedModule, HookingModule, HookingAddress FROM Hooks"
    )
    for row in cur:
        r = _row_to_dict(cur, row)
        yield build_ecs_doc(
            timestamp=datetime.now(timezone.utc).isoformat(),
            host_name=host,
            event_action="api-hook-detected",
            event_category=["intrusion_detection"],
            extra={
                "redline": {
                    "hook_description": r.get("HookDescription"),
                    "hooked_function": r.get("HookedFunction"),
                    "hooked_module": r.get("HookedModule"),
                    "hooking_module": r.get("HookingModule"),
                    "hooking_address": r.get("HookingAddress"),
                },
                "alert": {"name": "API Hook Detected", "category": "defense_evasion"},
            },
        )


def _parse_services(conn: sqlite3.Connection, host: str) -> Iterator[dict[str, Any]]:
    """Yield ECS docs for Windows services."""
    if not _table_exists(conn, "Services"):
        return
    cur = conn.execute(
        "SELECT Name, DescriptiveName, Path, ServiceType, Mode, ServiceStatus, ServiceDLL, FromPersistence FROM Services"
    )
    for row in cur:
        r = _row_to_dict(cur, row)
        yield build_ecs_doc(
            timestamp=datetime.now(timezone.utc).isoformat(),
            host_name=host,
            event_action="service-installed",
            event_category=["configuration"],
            extra={
                "service": {
                    "name": r.get("Name"),
                    "display_name": r.get("DescriptiveName"),
                    "path": r.get("Path"),
                    "type": r.get("ServiceType"),
                    "start_type": r.get("Mode"),
                    "state": r.get("ServiceStatus"),
                    "dll": r.get("ServiceDLL"),
                    "from_persistence": r.get("FromPersistence"),
                },
            },
        )


def _parse_registry(conn: sqlite3.Connection, host: str) -> Iterator[dict[str, Any]]:
    """Yield ECS docs for registry keys."""
    if not _table_exists(conn, "RegistryKeys"):
        return
    cur = conn.execute(
        "SELECT Hive, KeyPath, TextValue, RegistryType, Modified, FromPersistence FROM RegistryKeys LIMIT 5000"
    )
    for row in cur:
        r = _row_to_dict(cur, row)
        yield build_ecs_doc(
            timestamp=_ts(r.get("Modified")),
            host_name=host,
            event_action="registry-modified",
            event_category=["configuration", "registry"],
            extra={
                "registry": {
                    "hive": r.get("Hive"),
                    "key": r.get("KeyPath"),
                    "value": r.get("TextValue"),
                    "type": r.get("RegistryType"),
                    "from_persistence": r.get("FromPersistence"),
                },
            },
        )


def _parse_mri_hits(conn: sqlite3.Connection, host: str) -> Iterator[dict[str, Any]]:
    """Yield ECS docs for Malware Risk Index (MRI) hits."""
    if not _table_exists(conn, "MRIHits"):
        return
    # MRIHits has ProcessID referencing Processes(ID)
    cur = conn.execute(
        """SELECT m.RuleID, m.HitType, m.ScoreModifier, m.HitDescription,
                  p.ProcessName, p.Path
           FROM MRIHits m
           LEFT JOIN Processes p ON m.ProcessID = p.ID"""
    )
    for row in cur:
        r = _row_to_dict(cur, row)
        yield build_ecs_doc(
            timestamp=datetime.now(timezone.utc).isoformat(),
            host_name=host,
            event_action="malware-risk-index-hit",
            event_category=["malware"],
            process_name=r.get("ProcessName") or "",
            process_executable=r.get("Path") or "",
            extra={
                "alert": {
                    "name": r.get("RuleID") or "MRI Hit",
                    "category": "malware",
                    "description": r.get("HitDescription"),
                },
                "redline": {
                    "mri_hit_type": r.get("HitType"),
                    "mri_score_modifier": r.get("ScoreModifier"),
                },
            },
        )


def _parse_ioc_alerts(conn: sqlite3.Connection, host: str) -> Iterator[dict[str, Any]]:
    """Yield ECS docs for IOC (Indicator of Compromise) alerts."""
    if not _table_exists(conn, "IOCAlerts"):
        return
    cur = conn.execute(
        "SELECT AlertEventType, IndicatorId, MatchTimestamp FROM IOCAlerts"
    )
    for row in cur:
        r = _row_to_dict(cur, row)
        yield build_ecs_doc(
            timestamp=_ts(r.get("MatchTimestamp")),
            host_name=host,
            event_action="ioc-match",
            event_category=["intrusion_detection"],
            extra={
                "alert": {
                    "name": r.get("AlertEventType") or "IOC Alert",
                    "category": "ioc",
                },
                "threat": {"indicator_id": r.get("IndicatorId")},
            },
        )


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def stream_redline_mans(
    mans_path: Path,
    host: str,
) -> Iterator[dict[str, Any]]:
    """Yield ECS documents from a Redline .mans SQLite file.

    This is a generator so the caller (executor) can bulk-index.
    """
    if not mans_path.exists():
        logger.warning("Redline .mans not found: %s", mans_path)
        return

    try:
        conn = sqlite3.connect(str(mans_path))
    except sqlite3.Error as exc:
        logger.error("Failed to open %s: %s", mans_path, exc)
        return

    parsers = [
        ("processes", _parse_processes),
        ("hooks", _parse_hooks),
        ("services", _parse_services),
        ("registry", _parse_registry),
        ("mri_hits", _parse_mri_hits),
        ("ioc_alerts", _parse_ioc_alerts),
    ]

    for label, parser_fn in parsers:
        try:
            count = 0
            for doc in parser_fn(conn, host):
                yield doc
                count += 1
            if count:
                logger.info("  %s: %d docs", label, count)
        except Exception as exc:
            logger.error("  %s parse failed: %s", label, exc)

    conn.close()


def ingest_redline_mans(
    mans_path: Path,
    host: str,
    case_id: str,
    client: NightEyeOSClient,
) -> dict[str, int]:
    """Ingest a single Redline .mans SQLite file directly via OpenSearch client.

    Returns stats dict with counts per artifact type.
    """
    stats = {"documents_indexed": 0, "errors": 0}
    index_name = make_index_name(case_id, f"redline-{host}")
    logger.info("Ingesting Redline .mans for %s into %s", host, index_name)

    try:
        for doc in stream_redline_mans(mans_path, host):
            doc_id = compute_doc_id(doc)
            client.index_document(index_name, doc_id, doc)
            stats["documents_indexed"] += 1
    except Exception as exc:
        logger.error("Redline ingest failed: %s", exc)
        stats["errors"] += 1

    logger.info("Redline ingest complete for %s: %d docs", host, stats["documents_indexed"])
    return stats
