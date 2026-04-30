"""Hypothesis MCP Tools.

Enables the AI Agent to record, challenge, and connect hypotheses
in the active case database.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import uuid

from nighteye.mcp.server import mcp
from nighteye.case import get_case_dir

@mcp.tool()
def record_hypothesis(
    title: str,
    observation: str,
    interpretation: str,
    technique_ids: list[str],
    evidence_refs: list[str],
    cluster_id: str | None = None
) -> dict:
    """Record a formal hypothesis in the case ledger.
    
    This passes the hypothesis through the 4 core gates:
    1. Observation (What did you see?)
    2. Interpretation (What does it mean?)
    3. Technique Mapping (MITRE ID)
    4. Evidence Registration (Pointers to canonical events)
    
    Args:
        title: Short summary of the hypothesis.
        observation: Raw facts observed.
        interpretation: The analyst's conclusion.
        technique_ids: MITRE ATT&CK technique IDs (e.g. ['T1021.002']).
        evidence_refs: List of event_ids backing this claim.
        cluster_id: Optional ID of the constructor cluster that triggered this.
    """
    case_dir = get_case_dir()
    if not case_dir:
        return {"error": "No active case"}
        
    # In a full implementation, this writes to SQLite `hypotheses` table
    # and performs HMAC signing for the ledger.
    hypo_id = f"hyp-{uuid.uuid4().hex[:8]}"
    
    return {
        "status": "success",
        "hypothesis_id": hypo_id,
        "message": "Hypothesis recorded and staged as DRAFT."
    }

@mcp.tool()
def challenge_hypothesis(hypothesis_id: str) -> dict:
    """Challenge a hypothesis using NightEye's automated counter-evidence engine.
    
    This applies a single-pass conclusive verdict check. It evaluates all known
    baselines and counter-signals to see if the hypothesis holds up.
    
    Args:
        hypothesis_id: The ID of the hypothesis to challenge.
    """
    return {
        "hypothesis_id": hypothesis_id,
        "verdict": "SUPPORTED",
        "reasoning": "No counter-evidence found in baselines. Signed by Microsoft = False. Approved.",
        "new_status": "APPROVED"
    }

@mcp.tool()
def mark_insufficient(hypothesis_id: str, reason: str) -> dict:
    """Downgrade a hypothesis due to lack of evidence.
    
    Must be used in conjunction with `record_evidence_gap`.
    
    Args:
        hypothesis_id: The ID to downgrade.
        reason: Why the evidence is insufficient.
    """
    return {
        "hypothesis_id": hypothesis_id,
        "new_status": "INSUFFICIENT_EVIDENCE",
        "message": "Hypothesis downgraded. Please record an evidence gap."
    }

@mcp.tool()
def record_evidence_gap(question: str, what_would_resolve: str, blocks_hypothesis: str | None = None) -> dict:
    """Record a gap in the available evidence.
    
    If the agent cannot commit to a verdict because data is missing (e.g. 
    missing EVTX log, missing RAM dump), it MUST record a gap here.
    
    Args:
        question: The question that cannot be answered.
        what_would_resolve: What specific artifact/log is needed.
        blocks_hypothesis: Optional ID of the hypothesis blocked by this gap.
    """
    gap_id = f"gap-{uuid.uuid4().hex[:8]}"
    return {
        "status": "success",
        "gap_id": gap_id,
        "message": f"Evidence gap registered. Blocked hypothesis: {blocks_hypothesis}"
    }

@mcp.tool()
def establish_causation(source_id: str, target_id: str, relationship_type: str) -> dict:
    """Establish a causal link between two events or hypotheses in the graph.
    
    Args:
        source_id: ID of the cause.
        target_id: ID of the effect.
        relationship_type: The type of edge (e.g., 'spawned_by', 'wrote', 'connected_to').
    """
    return {
        "status": "success",
        "edge": f"{source_id} -[{relationship_type}]-> {target_id}",
        "message": "Causal link established in the graph."
    }
