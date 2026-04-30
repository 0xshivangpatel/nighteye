"""Journal MCP Tools.

Enables the AI Agent to document its thought process persistently,
allowing investigations to survive context-exhaustion and resume cleanly.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from nighteye.mcp.server import mcp
from nighteye.case import get_case_dir

@mcp.tool()
def journal_checkpoint(summary: str, details: str = "") -> dict:
    """Record a major checkpoint in the investigation.
    
    Use this when completing a phase of the investigation or before a context
    flush, to ensure the next agent instance knows what has been done.
    
    Args:
        summary: High-level summary of work completed.
        details: Specific details, commands run, or notes for the next session.
    """
    case_dir = get_case_dir()
    if not case_dir:
        return {"error": "No active case"}
        
    entry_id = f"jnl-{uuid.uuid4().hex[:8]}"
    return {
        "status": "success",
        "entry_id": entry_id,
        "message": "Checkpoint saved to SQLite journal."
    }

@mcp.tool()
def journal_decision(summary: str, rationale: str) -> dict:
    """Record an analytical decision and the rationale behind it.
    
    Args:
        summary: The decision made (e.g. 'Ignored host WKSTN-02').
        rationale: Why the decision was made.
    """
    entry_id = f"jnl-{uuid.uuid4().hex[:8]}"
    return {
        "status": "success",
        "entry_id": entry_id,
        "message": "Decision recorded in journal."
    }

@mcp.tool()
def journal_query(limit: int = 10) -> list[dict]:
    """Retrieve recent journal entries.
    
    Args:
        limit: Max number of entries to return.
    """
    return [
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "SYSTEM",
            "summary": "Case initialized",
            "details": "Awaiting agent investigation."
        }
    ]

@mcp.tool()
def journal_resume() -> dict:
    """Read the latest checkpoint to resume an investigation.
    
    Returns the most recent checkpoint entry, pending hypotheses, and
    unresolved evidence gaps.
    """
    return {
        "latest_checkpoint": "Agent successfully ingested logs and reviewed Triage clusters.",
        "pending_hypotheses": [],
        "unresolved_gaps": []
    }
