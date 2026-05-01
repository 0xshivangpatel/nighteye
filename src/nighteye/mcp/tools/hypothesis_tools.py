"""MCP Hypothesis Management Tools.

Tools for recording, challenging, and managing investigation hypotheses.
"""

from __future__ import annotations

import logging
from typing import Any

from nighteye.db import connect
from nighteye.models import (
    Hypothesis,
    HypothesisStatus,
    EvidenceRef,
    CausalLink,
    CausalLevel,
    ChallengeVerdict,
)
from nighteye.hypothesis_lifecycle import (
    record_hypothesis as _record_hypothesis,
    challenge_hypothesis as _challenge_hypothesis,
    approve_hypothesis as _approve_hypothesis,
    reject_hypothesis as _reject_hypothesis,
    contradict_hypothesis as _contradict_hypothesis,
    mark_insufficient,
    establish_causation as _establish_causation,
    get_hypothesis as _get_hypothesis,
    list_hypotheses as _list_hypotheses,
)
from nighteye.case import get_active_case

__all__ = [
    "record_hypothesis",
    "challenge_hypothesis",
    "approve_hypothesis",
    "reject_hypothesis",
    "list_hypotheses",
    "get_hypothesis_details",
    "establish_causation",
    "mark_insufficient_evidence",
]

logger = logging.getLogger("nighteye.mcp.tools.hypothesis")

# ============================================================
# Hypothesis Tools
# ============================================================

def record_hypothesis(
    title: str,
    observation: str,
    interpretation: str,
    technique_ids: list[str],
    evidence_refs: list[dict[str, Any]],
    causal_links: list[dict[str, Any]] | None = None,
    suggested_by_cluster: str | None = None,
    examiner: str | None = None,
    case_id: str | None = None,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Record a new investigation hypothesis.

    Args:
        title: Short descriptive title
        observation: What was observed (facts)
        interpretation: What it means (inference)
        technique_ids: MITRE ATT&CK technique IDs
        evidence_refs: List of evidence references with audit_id, description, cluster_id
        causal_links: Optional causal links to other hypotheses
        suggested_by_cluster: Optional cluster ID that suggested this
        examiner: Examiner name (defaults to active case examiner)
        case_id: Case ID (defaults to active case)
        db_path: Path to graph.db

    Returns:
        Hypothesis result with status and confidence
    """
    if not db_path:
        active = get_active_case()
        if active and (not case_id or active.id == case_id):
            case_id = case_id or active.id
            examiner = examiner or active.examiner
            db_path = active.graph_db
        elif case_id:
            from nighteye.case import get_case
            try:
                info = get_case(case_id)
                db_path = info.graph_db
                examiner = examiner or info.examiner
            except:
                pass

    if not db_path:
        return {"success": False, "error": "Database path (db_path) required or active case must be set"}

    if not case_id:
        return {"success": False, "error": "Case ID (case_id) required"}

    if not examiner:
        return {"success": False, "error": "Examiner required"}

    # Convert evidence_refs to EvidenceRef objects
    refs = [
        EvidenceRef(
            audit_id=r.get("audit_id", ""),
            description=r.get("description", ""),
            cluster_id=r.get("cluster_id"),
            canonical_event_ids=r.get("canonical_event_ids", []),
            entity_ids=r.get("entity_ids", []),
        )
        for r in evidence_refs
    ]

    # Convert causal_links to CausalLink objects
    links = []
    if causal_links:
        for c in causal_links:
            try:
                level = CausalLevel(c.get("level", "UNSUPPORTED"))
            except ValueError:
                level = CausalLevel.UNSUPPORTED
            links.append(CausalLink(
                target_hypothesis=c.get("target_hypothesis", ""),
                level=level,
                proof_audit_ids=c.get("proof_audit_ids", []),
                proof_edges=c.get("proof_edges", []),
                notes=c.get("notes", ""),
            ))

    try:
        with connect(db_path) as conn:
            hypothesis = _record_hypothesis(
                db_conn=conn,
                case_id=case_id,
                examiner=examiner,
                title=title,
                observation=observation,
                interpretation=interpretation,
                technique_ids=technique_ids,
                evidence_refs=refs,
                causal_links=links,
                suggested_by_cluster=suggested_by_cluster,
            )

        return {
            "success": True,
            "hypothesis_id": hypothesis.id,
            "status": hypothesis.status.value,
            "confidence_score": hypothesis.confidence.score if hypothesis.confidence else 0,
            "confidence_tier": hypothesis.confidence.tier.value if hypothesis.confidence else "SPECULATIVE",
            "provenance_tier": hypothesis.provenance_tier.value,
            "auto_approved": hypothesis.status == HypothesisStatus.APPROVED,
        }
    except ValueError as exc:
        return {"success": False, "error": str(exc)}
    except Exception as exc:
        logger.exception("Failed to record hypothesis")
        return {"success": False, "error": f"Internal error: {exc}"}


def challenge_hypothesis(
    hypothesis_id: str,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Run adversarial review on a hypothesis.

    Returns:
        Challenge result with verdict and reasoning
    """
    if not db_path:
        active = get_active_case()
        db_path = active.graph_db if active else "graph.db"

    try:
        with connect(db_path) as conn:
            result = _challenge_hypothesis(conn, hypothesis_id)

        return {
            "success": True,
            "hypothesis_id": hypothesis_id,
            "verdict": result["verdict"],
            "reasoning": result["reasoning"],
            "new_status": result["new_status"],
        }
    except ValueError as exc:
        return {"success": False, "error": str(exc)}
    except Exception as exc:
        logger.exception("Failed to challenge hypothesis")
        return {"success": False, "error": f"Internal error: {exc}"}


def approve_hypothesis(
    hypothesis_id: str,
    approved_by: str,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Explicitly approve a hypothesis.

    Returns:
        Approval result
    """
    if not db_path:
        active = get_active_case()
        db_path = active.graph_db if active else "graph.db"

    try:
        with connect(db_path) as conn:
            hypothesis = _approve_hypothesis(conn, hypothesis_id, approved_by)

        return {
            "success": True,
            "hypothesis_id": hypothesis_id,
            "status": hypothesis.status.value,
            "approved_by": approved_by,
            "approved_at": hypothesis.approved_at.isoformat() if hypothesis.approved_at else None,
        }
    except ValueError as exc:
        return {"success": False, "error": str(exc)}
    except Exception as exc:
        logger.exception("Failed to approve hypothesis")
        return {"success": False, "error": f"Internal error: {exc}"}


def reject_hypothesis(
    hypothesis_id: str,
    rejected_by: str,
    reason: str,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Reject a hypothesis.

    Returns:
        Rejection result
    """
    if not db_path:
        active = get_active_case()
        db_path = active.graph_db if active else "graph.db"

    try:
        with connect(db_path) as conn:
            hypothesis = _reject_hypothesis(conn, hypothesis_id, rejected_by, reason)

        return {
            "success": True,
            "hypothesis_id": hypothesis_id,
            "status": hypothesis.status.value,
            "rejected_by": rejected_by,
            "reason": reason,
        }
    except ValueError as exc:
        return {"success": False, "error": str(exc)}
    except Exception as exc:
        logger.exception("Failed to reject hypothesis")
        return {"success": False, "error": f"Internal error: {exc}"}


def list_hypotheses(
    case_id: str | None = None,
    status: str | None = None,
    limit: int = 50,
    db_path: str | None = None,
) -> dict[str, Any]:
    """List hypotheses with optional filtering.

    Returns:
        List of hypotheses
    """
    if not db_path:
        active = get_active_case()
        if active and (not case_id or active.id == case_id):
            case_id = case_id or active.id
            db_path = active.graph_db
        elif case_id:
            from nighteye.case import get_case
            try:
                info = get_case(case_id)
                db_path = info.graph_db
            except:
                pass

    if not db_path:
        db_path = "graph.db"

    try:
        status_enum = None
        if status:
            status_enum = HypothesisStatus(status)

        with connect(db_path, read_only=True) as conn:
            hypotheses = _list_hypotheses(conn, case_id, status_enum, limit)

        return {
            "success": True,
            "total": len(hypotheses),
            "hypotheses": [
                {
                    "id": h.id,
                    "title": h.title,
                    "status": h.status.value,
                    "confidence_score": h.confidence.score if h.confidence else 0,
                    "confidence_tier": h.confidence.tier.value if h.confidence else "SPECULATIVE",
                    "staged_at": h.staged_at.isoformat() if h.staged_at else None,
                    "technique_ids": h.technique_ids,
                }
                for h in hypotheses
            ],
        }
    except Exception as exc:
        logger.exception("Failed to list hypotheses")
        return {"success": False, "error": f"Internal error: {exc}"}


def get_hypothesis_details(
    hypothesis_id: str,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Get full details of a hypothesis.

    Returns:
        Complete hypothesis information
    """
    if not db_path:
        active = get_active_case()
        db_path = active.graph_db if active else "graph.db"

    try:
        with connect(db_path, read_only=True) as conn:
            hypothesis = _get_hypothesis(conn, hypothesis_id)

        if not hypothesis:
            return {"success": False, "error": "Hypothesis not found"}

        return {
            "success": True,
            "hypothesis": {
                "id": hypothesis.id,
                "title": hypothesis.title,
                "observation": hypothesis.observation,
                "interpretation": hypothesis.interpretation,
                "technique_ids": hypothesis.technique_ids,
                "status": hypothesis.status.value,
                "confidence": {
                    "score": hypothesis.confidence.score if hypothesis.confidence else 0,
                    "tier": hypothesis.confidence.tier.value if hypothesis.confidence else "SPECULATIVE",
                    "rationale": hypothesis.confidence.rationale if hypothesis.confidence else "",
                },
                "provenance_tier": hypothesis.provenance_tier.value,
                "evidence_count": len(hypothesis.evidence_refs),
                "causal_links": [
                    {
                        "target": c.target_hypothesis,
                        "level": c.level.value,
                        "notes": c.notes,
                    }
                    for c in hypothesis.causal_links
                ],
                "staged_at": hypothesis.staged_at.isoformat() if hypothesis.staged_at else None,
                "approved_at": hypothesis.approved_at.isoformat() if hypothesis.approved_at else None,
            },
        }
    except Exception as exc:
        logger.exception("Failed to get hypothesis details")
        return {"success": False, "error": f"Internal error: {exc}"}


def establish_causation(
    from_hypothesis_id: str,
    to_hypothesis_id: str,
    level: str,
    proof_audit_ids: list[str],
    proof_edges: list[str] | None = None,
    notes: str = "",
    db_path: str | None = None,
) -> dict[str, Any]:
    """Establish a causal link between two hypotheses.

    Args:
        from_hypothesis_id: Source hypothesis
        to_hypothesis_id: Target hypothesis (effect)
        level: Causal level (CHAIN, WRITE, NET, TIGHT_TIME, CO_OCCUR, TEMPORAL_ONLY, UNSUPPORTED)
        proof_audit_ids: Audit IDs of evidence supporting causation
        proof_edges: Graph edge IDs supporting causation
        notes: Optional notes
        db_path: Path to graph.db

    Returns:
        Causation result
    """
    if not db_path:
        active = get_active_case()
        db_path = active.graph_db if active else "graph.db"

    try:
        causal_level = CausalLevel(level)
    except ValueError:
        return {"success": False, "error": f"Invalid causal level: {level}"}

    try:
        with connect(db_path) as conn:
            link = _establish_causation(
                conn,
                from_hypothesis_id,
                to_hypothesis_id,
                causal_level,
                proof_audit_ids,
                proof_edges or [],
                notes,
            )

        return {
            "success": True,
            "from": from_hypothesis_id,
            "to": to_hypothesis_id,
            "level": link.level.value,
            "proof_count": len(link.proof_audit_ids),
        }
    except Exception as exc:
        logger.exception("Failed to establish causation")
        return {"success": False, "error": f"Internal error: {exc}"}


def mark_insufficient_evidence(
    title: str,
    observation: str,
    interpretation: str,
    technique_ids: list[str],
    evidence_refs: list[dict[str, Any]],
    reason: str,
    what_would_resolve: str = "",
    examiner: str | None = None,
    case_id: str | None = None,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Mark a hypothesis as insufficient evidence.

    Returns:
        Result with gap registration
    """
    if not case_id:
        active = get_active_case()
        if not active:
            return {"success": False, "error": "No active case"}
        case_id = active.id
        examiner = examiner or active.examiner
        db_path = db_path or active.graph_db

    refs = [
        EvidenceRef(
            audit_id=r.get("audit_id", ""),
            description=r.get("description", ""),
            cluster_id=r.get("cluster_id"),
            canonical_event_ids=r.get("canonical_event_ids", []),
            entity_ids=r.get("entity_ids", []),
        )
        for r in evidence_refs
    ]

    try:
        with connect(db_path) as conn:
            hypothesis = mark_insufficient(
                conn,
                case_id,
                examiner,
                title,
                observation,
                interpretation,
                technique_ids,
                refs,
                reason,
                what_would_resolve,
            )

        return {
            "success": True,
            "hypothesis_id": hypothesis.id,
            "status": hypothesis.status.value,
            "reason": reason,
            "what_would_resolve": what_would_resolve,
        }
    except Exception as exc:
        logger.exception("Failed to mark insufficient")
        return {"success": False, "error": f"Internal error: {exc}"}
