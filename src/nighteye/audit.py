"""Audit log helpers.

Every MCP tool invocation must call `record_audit` to write a row into
the `audit` table. The audit_id format is:

    {prefix}-{examiner}-{YYYYMMDD}-{NNN}

Sequence number resumes per (prefix, examiner, date). Resumption survives
process restarts because we query the existing rows.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any

_AUDIT_ID_RE = re.compile(r"^[a-z][a-z0-9-]*-[a-z0-9][a-z0-9-]*-\d{8}-\d{3,}$")


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def utc_now_yyyymmdd() -> str:
    """Return current UTC date in YYYYMMDD format."""
    return datetime.now(timezone.utc).strftime("%Y%m%d")


def is_valid_audit_id(audit_id: str) -> bool:
    """Validate an audit_id against the canonical format."""
    return bool(_AUDIT_ID_RE.match(audit_id))


def next_audit_id(
    conn: sqlite3.Connection,
    examiner: str,
    *,
    prefix: str = "nighteye",
    date: str | None = None,
) -> str:
    """Generate the next audit_id for (prefix, examiner, date).

    Resumes the sequence by querying the max existing row.
    """
    date = date or utc_now_yyyymmdd()
    pattern = f"{prefix}-{examiner}-{date}-%"
    cur = conn.execute(
        "SELECT audit_id FROM audit WHERE audit_id LIKE ? ORDER BY audit_id DESC LIMIT 1",
        (pattern,),
    )
    row = cur.fetchone()
    next_seq = 1
    if row:
        try:
            existing_seq = int(row[0].rsplit("-", 1)[-1])
            next_seq = existing_seq + 1
        except (ValueError, IndexError):
            next_seq = 1
    return f"{prefix}-{examiner}-{date}-{next_seq:03d}"


def record_audit(
    conn: sqlite3.Connection,
    *,
    case_id: str,
    tool_group: str,
    tool_name: str,
    parameters: dict[str, Any],
    result_summary: dict[str, Any],
    duration_ms: int,
    examiner: str,
    queries_run: list[dict[str, Any]] | None = None,
    audit_id: str | None = None,
    timestamp: str | None = None,
    prefix: str = "nighteye",
) -> str:
    """Write an audit row, returning the audit_id used.

    Caller is responsible for `conn.commit()` if not running inside a
    transaction context manager.
    """
    if not examiner:
        raise ValueError("audit row requires examiner")
    if not case_id:
        raise ValueError("audit row requires case_id")
    audit_id = audit_id or next_audit_id(conn, examiner, prefix=prefix)
    if not is_valid_audit_id(audit_id):
        raise ValueError(f"Malformed audit_id: {audit_id!r}")
    timestamp = timestamp or utc_now_iso()

    conn.execute(
        """
        INSERT INTO audit (
            audit_id, case_id, tool_group, tool_name,
            parameters, result_summary, duration_ms, queries_run,
            examiner, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            audit_id,
            case_id,
            tool_group,
            tool_name,
            json.dumps(parameters, default=str, sort_keys=True),
            json.dumps(result_summary, default=str, sort_keys=True),
            int(duration_ms),
            json.dumps(queries_run, default=str) if queries_run else None,
            examiner,
            timestamp,
        ),
    )
    return audit_id


def query_audit(
    conn: sqlite3.Connection,
    *,
    case_id: str | None = None,
    tool_name: str | None = None,
    examiner: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Return audit rows matching filters, newest first."""
    sql = ["SELECT * FROM audit WHERE 1=1"]
    params: list[Any] = []
    if case_id:
        sql.append("AND case_id = ?")
        params.append(case_id)
    if tool_name:
        sql.append("AND tool_name = ?")
        params.append(tool_name)
    if examiner:
        sql.append("AND examiner = ?")
        params.append(examiner)
    sql.append("ORDER BY timestamp DESC LIMIT ?")
    params.append(int(limit))

    rows = conn.execute(" ".join(sql), tuple(params)).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        d["parameters"] = json.loads(d["parameters"])
        d["result_summary"] = json.loads(d["result_summary"])
        if d.get("queries_run"):
            d["queries_run"] = json.loads(d["queries_run"])
        out.append(d)
    return out
