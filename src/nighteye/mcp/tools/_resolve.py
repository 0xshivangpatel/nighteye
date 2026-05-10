"""Shared helpers for MCP tools."""

from __future__ import annotations

from pathlib import Path

from nighteye.case import CaseError, get_active_case, get_case_dir, load_case_meta

__all__ = ["resolve_case_db", "load_case_info"]


def resolve_case_db(
    case_id: str | None,
    db_path: str | None,
) -> tuple[str | None, str | None, str | None]:
    """Resolve (case_id, db_path) from optional inputs.

    Resolution order:
      1. db_path explicit → use it as-is (case_id may still be None)
      2. case_id given → look up via get_case_dir, append graph.db
      3. neither → fall back to active case

    Returns (case_id, db_path, error). On failure, error is non-empty
    and the others are None.
    """
    if db_path:
        return case_id, db_path, None

    if case_id:
        try:
            case_dir = get_case_dir(case_id)
        except CaseError as exc:
            return None, None, f"Cannot resolve case_id {case_id!r}: {exc}"
        return case_id, str(case_dir / "graph.db"), None

    active = get_active_case()
    if not active:
        return None, None, "No active case and no case_id provided"
    return active.id, active.graph_db, None


def load_case_info(case_id: str | None, db_path: str | None) -> dict:
    """Load case metadata from CASE.yaml (no `cases` table exists in graph.db).

    Returns dict with case_id, name, examiner, created_at, status. Empty dict
    on failure.
    """
    if db_path:
        case_dir = Path(db_path).parent
    elif case_id:
        try:
            case_dir = get_case_dir(case_id)
        except CaseError:
            return {}
    else:
        active = get_active_case()
        case_dir = active.case_dir if active else None
        if not case_dir:
            return {}

    try:
        meta = load_case_meta(case_dir)
        return {
            "case_id": meta.get("case_id", case_id or ""),
            "case_name": meta.get("name", ""),
            "name": meta.get("name", ""),
            "examiner": meta.get("examiner", ""),
            "created_at": meta.get("created_at", ""),
            "status": meta.get("status", "unknown"),
            "description": meta.get("description", ""),
        }
    except CaseError:
        return {}
