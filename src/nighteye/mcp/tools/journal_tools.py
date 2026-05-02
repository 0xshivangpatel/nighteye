"""Journal MCP tools — Layer 6 surfacing.

Wraps :mod:`nighteye.journal` for exposure as MCP tools. The agent uses
these to record decisions, checkpoint state before context exhaustion,
and resume a prior session.
"""

from __future__ import annotations

from typing import Any

from nighteye.case import get_active_case
from nighteye.journal import (
    append_entry,
    build_resume_digest,
    checkpoint as journal_checkpoint_impl,
    query_entries,
    record_decision as journal_record_decision_impl,
)
from nighteye.models import JournalEntryType

__all__ = [
    "journal_checkpoint",
    "journal_record_decision",
    "journal_query",
    "journal_resume",
]


def _resolve_case(case_id: str | None) -> tuple[str, str]:
    """Resolve case_id and graph_db path. Raises if no active case."""
    if case_id:
        from nighteye.case import get_case_dir
        case_dir = get_case_dir(case_id)
        return case_id, str(case_dir / "graph.db")
    info = get_active_case()
    if not info:
        raise RuntimeError(
            "No active case. Initialize one with `nighteye case init` "
            "or pass case_id explicitly."
        )
    return info.case_id, info.graph_db


def journal_checkpoint(
    summary: str,
    next_steps: list[str] | None = None,
    case_id: str | None = None,
    agent_session_id: str | None = None,
) -> dict[str, Any]:
    """Record a CHECKPOINT_SUMMARY entry.

    Use before a session ends or before context approaches exhaustion.
    """
    cid, db = _resolve_case(case_id)
    entry = journal_checkpoint_impl(
        db,
        case_id=cid,
        summary=summary,
        next_steps=next_steps,
        agent_session_id=agent_session_id,
    )
    return {
        "success": True,
        "entry_id": entry.entry_id,
        "case_id": cid,
        "timestamp": entry.timestamp.isoformat(),
    }


def journal_record_decision(
    summary: str,
    rationale: str,
    hypotheses_considered: list[str] | None = None,
    case_id: str | None = None,
    agent_session_id: str | None = None,
) -> dict[str, Any]:
    """Record an INVESTIGATION_DECISION entry capturing reasoning."""
    cid, db = _resolve_case(case_id)
    entry = journal_record_decision_impl(
        db,
        case_id=cid,
        summary=summary,
        rationale=rationale,
        hypotheses_considered=hypotheses_considered,
        agent_session_id=agent_session_id,
    )
    return {
        "success": True,
        "entry_id": entry.entry_id,
        "case_id": cid,
        "timestamp": entry.timestamp.isoformat(),
    }


def journal_query(
    limit: int = 20,
    entry_type: str | None = None,
    case_id: str | None = None,
) -> dict[str, Any]:
    """Return recent journal entries, newest-first."""
    cid, db = _resolve_case(case_id)
    types = None
    if entry_type:
        try:
            types = [JournalEntryType(entry_type)]
        except ValueError:
            return {"success": False, "error": f"Unknown entry_type: {entry_type}"}
    entries = query_entries(
        db, case_id=cid, entry_types=types, limit=int(limit)
    )
    return {
        "success": True,
        "case_id": cid,
        "entries": [
            {
                "entry_id": e.entry_id,
                "timestamp": e.timestamp.isoformat(),
                "entry_type": e.entry_type.value,
                "summary": e.summary,
                "details": e.details,
                "agent_session_id": e.agent_session_id,
            }
            for e in entries
        ],
    }


def journal_resume(case_id: str | None = None) -> dict[str, Any]:
    """Build the session-resume digest the agent reads at session start."""
    cid, db = _resolve_case(case_id)
    digest = build_resume_digest(db, case_id=cid)
    digest["success"] = True
    return digest
