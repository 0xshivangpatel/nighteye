"""Investigation Journal — Layer 6 (Persistent Investigation State).

The journal is the externalized memory that lets the agent survive
context-window exhaustion and resume across sessions. Every significant
decision the agent makes is appended here.

Storage: the ``journal`` table in the per-case SQLite Evidence Graph.
See docs/JOURNAL.md for the schema and resume protocol.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nighteye.db import connect, execute_with_retry
from nighteye.models import JournalEntry, JournalEntryType

__all__ = [
    "append_entry",
    "query_entries",
    "build_resume_digest",
    "checkpoint",
    "record_decision",
]

logger = logging.getLogger("nighteye.journal")


# ============================================================
# Helpers
# ============================================================


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_entry_id() -> str:
    return f"jnl-{uuid.uuid4().hex[:12]}"


def _row_to_entry(row: sqlite3.Row) -> JournalEntry:
    details_raw = row["details"]
    details: dict[str, Any] = {}
    if details_raw:
        try:
            details = json.loads(details_raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            details = {}
    ts_raw = row["timestamp"]
    timestamp = datetime.fromisoformat(ts_raw) if isinstance(ts_raw, str) else ts_raw
    return JournalEntry(
        entry_id=row["entry_id"],
        case_id=row["case_id"],
        investigation_id=row["investigation_id"] or "main",
        timestamp=timestamp,
        entry_type=JournalEntryType(row["entry_type"]),
        summary=row["summary"],
        details=details,
        agent_session_id=row["agent_session_id"],
        supersedes=row["supersedes"],
    )


# ============================================================
# Append / query
# ============================================================


def append_entry(
    db_path: str | Path,
    *,
    case_id: str,
    entry_type: JournalEntryType,
    summary: str,
    details: dict[str, Any] | None = None,
    investigation_id: str = "main",
    agent_session_id: str | None = None,
    supersedes: str | None = None,
    timestamp: str | None = None,
) -> JournalEntry:
    """Append a journal entry to the case database.

    Returns the persisted ``JournalEntry``.
    """
    entry_id = _new_entry_id()
    ts = timestamp or _utcnow_iso()

    with connect(db_path) as conn:
        execute_with_retry(
            conn,
            """
            INSERT INTO journal (
                entry_id, case_id, investigation_id, timestamp,
                entry_type, summary, details,
                agent_session_id, supersedes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry_id,
                case_id,
                investigation_id,
                ts,
                entry_type.value,
                summary,
                json.dumps(details) if details else None,
                agent_session_id,
                supersedes,
            ),
        )
        conn.commit()

    return JournalEntry(
        entry_id=entry_id,
        case_id=case_id,
        investigation_id=investigation_id,
        timestamp=datetime.fromisoformat(ts),
        entry_type=entry_type,
        summary=summary,
        details=details or {},
        agent_session_id=agent_session_id,
        supersedes=supersedes,
    )


def query_entries(
    db_path: str | Path,
    *,
    case_id: str,
    since: str | None = None,
    until: str | None = None,
    entry_types: list[JournalEntryType] | None = None,
    limit: int = 100,
    order: str = "DESC",
) -> list[JournalEntry]:
    """Return journal entries for a case, newest-first by default."""
    sql = ["SELECT * FROM journal WHERE case_id = ?"]
    params: list[Any] = [case_id]
    if since:
        sql.append("AND timestamp >= ?")
        params.append(since)
    if until:
        sql.append("AND timestamp <= ?")
        params.append(until)
    if entry_types:
        placeholders = ",".join("?" for _ in entry_types)
        sql.append(f"AND entry_type IN ({placeholders})")
        params.extend(t.value for t in entry_types)
    order_norm = "ASC" if str(order).upper() == "ASC" else "DESC"
    sql.append(f"ORDER BY timestamp {order_norm}")
    sql.append("LIMIT ?")
    params.append(int(limit))

    with connect(db_path, read_only=True) as conn:
        rows = conn.execute(" ".join(sql), tuple(params)).fetchall()
    return [_row_to_entry(r) for r in rows]


# ============================================================
# Resume digest
# ============================================================


def build_resume_digest(
    db_path: str | Path,
    *,
    case_id: str,
    max_recent_entries: int = 10,
) -> dict[str, Any]:
    """Build a compact digest the agent can read at session start.

    Reads from the journal, hypotheses, and evidence_gaps tables.
    """
    with connect(db_path, read_only=True) as conn:
        last_session = conn.execute(
            """
            SELECT entry_id, timestamp, summary, details
            FROM journal
            WHERE case_id = ? AND entry_type IN ('SESSION_END', 'CHECKPOINT_SUMMARY')
            ORDER BY timestamp DESC LIMIT 1
            """,
            (case_id,),
        ).fetchone()

        prior_session_count = conn.execute(
            "SELECT COUNT(*) FROM journal WHERE case_id = ? AND entry_type = 'SESSION_START'",
            (case_id,),
        ).fetchone()[0]

        recent = conn.execute(
            """
            SELECT entry_id, timestamp, entry_type, summary
            FROM journal
            WHERE case_id = ?
            ORDER BY timestamp DESC LIMIT ?
            """,
            (case_id, int(max_recent_entries)),
        ).fetchall()

        h_counts: dict[str, int] = {}
        for status_row in conn.execute(
            """
            SELECT status, COUNT(*) AS n
            FROM hypotheses WHERE case_id = ? GROUP BY status
            """,
            (case_id,),
        ).fetchall():
            h_counts[status_row["status"]] = status_row["n"]

        approved_recent = conn.execute(
            """
            SELECT hypothesis_id, title, confidence_tier, approved_at
            FROM hypotheses
            WHERE case_id = ? AND status = 'APPROVED'
            ORDER BY approved_at DESC LIMIT 5
            """,
            (case_id,),
        ).fetchall()

        gaps = conn.execute(
            """
            SELECT gap_id, question, what_would_resolve
            FROM evidence_gaps
            WHERE case_id = ? AND resolved_at IS NULL
            ORDER BY registered_at DESC LIMIT 10
            """,
            (case_id,),
        ).fetchall()

        clusters_total = conn.execute(
            "SELECT COUNT(*) FROM clusters WHERE case_id = ?", (case_id,)
        ).fetchone()[0]
        clusters_strong = conn.execute(
            "SELECT COUNT(*) FROM clusters WHERE case_id = ? AND strength = 'STRONG'",
            (case_id,),
        ).fetchone()[0]
        clusters_moderate = conn.execute(
            "SELECT COUNT(*) FROM clusters WHERE case_id = ? AND strength = 'MODERATE'",
            (case_id,),
        ).fetchone()[0]

    next_steps: list[str] = []
    last_session_summary = None
    if last_session:
        last_session_summary = {
            "timestamp": last_session["timestamp"],
            "summary": last_session["summary"],
        }
        if last_session["details"]:
            try:
                d = json.loads(last_session["details"])
                if isinstance(d, dict):
                    next_steps = list(d.get("next_steps") or [])
            except (TypeError, ValueError, json.JSONDecodeError):
                pass

    digest = {
        "case_id": case_id,
        "prior_sessions": prior_session_count,
        "last_session_end": last_session_summary,
        "current_state": {
            "hypotheses": {
                "DRAFT": h_counts.get("DRAFT", 0),
                "INSUFFICIENT_EVIDENCE": h_counts.get("INSUFFICIENT_EVIDENCE", 0),
                "APPROVED": h_counts.get("APPROVED", 0),
                "REJECTED": h_counts.get("REJECTED", 0),
                "CONTRADICTED": h_counts.get("CONTRADICTED", 0),
                "DOWNGRADED": h_counts.get("DOWNGRADED", 0),
            },
            "evidence_gaps_open": len(gaps),
            "clusters_total": clusters_total,
            "clusters_strong": clusters_strong,
            "clusters_moderate": clusters_moderate,
        },
        "recent_entries": [
            {
                "entry_id": r["entry_id"],
                "timestamp": r["timestamp"],
                "entry_type": r["entry_type"],
                "summary": r["summary"],
            }
            for r in recent
        ],
        "key_recent_findings": [
            {
                "hypothesis_id": r["hypothesis_id"],
                "title": r["title"],
                "tier": r["confidence_tier"],
                "approved_at": r["approved_at"],
            }
            for r in approved_recent
        ],
        "open_gaps": [
            {
                "gap_id": g["gap_id"],
                "question": g["question"],
                "what_would_resolve": g["what_would_resolve"],
            }
            for g in gaps
        ],
        "next_suggested_actions": next_steps,
    }

    # Record that we read the digest
    append_entry(
        db_path,
        case_id=case_id,
        entry_type=JournalEntryType.RESUME_DIGEST_READ,
        summary=f"Resume digest read ({prior_session_count} prior sessions)",
        details={"recent_count": len(recent), "open_gaps": len(gaps)},
    )

    return digest


# ============================================================
# Convenience wrappers
# ============================================================


def checkpoint(
    db_path: str | Path,
    *,
    case_id: str,
    summary: str,
    next_steps: list[str] | None = None,
    agent_session_id: str | None = None,
) -> JournalEntry:
    """Write a CHECKPOINT_SUMMARY entry."""
    return append_entry(
        db_path,
        case_id=case_id,
        entry_type=JournalEntryType.CHECKPOINT_SUMMARY,
        summary=summary,
        details={"next_steps": next_steps or []},
        agent_session_id=agent_session_id,
    )


def record_decision(
    db_path: str | Path,
    *,
    case_id: str,
    summary: str,
    rationale: str,
    hypotheses_considered: list[str] | None = None,
    agent_session_id: str | None = None,
) -> JournalEntry:
    """Write an INVESTIGATION_DECISION entry capturing reasoning."""
    return append_entry(
        db_path,
        case_id=case_id,
        entry_type=JournalEntryType.INVESTIGATION_DECISION,
        summary=summary,
        details={
            "rationale": rationale,
            "hypotheses_considered": hypotheses_considered or [],
        },
        agent_session_id=agent_session_id,
    )
