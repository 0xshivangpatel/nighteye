"""Hypothesis Lifecycle Management.

Implements the full hypothesis state machine:
  record → challenge → approve/reject/contradict

References:
  - docs/ARCHITECTURE.md § 9 (Layer 5: Recursive AI Investigation)
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from nighteye.models import (
    Hypothesis,
    HypothesisStatus,
    ConfidenceBreakdown,
    ConfidenceTier,
    ProvenanceTier,
    CausalLevel,
    ChallengeVerdict,
    EvidenceRef,
    CausalLink,
)
from nighteye.db import connect, execute_with_retry, transaction
from nighteye.confidence import compute_adaptive_confidence
from nighteye.provenance import derive_provenance

__all__ = [
    "record_hypothesis",
    "challenge_hypothesis",
    "approve_hypothesis",
    "reject_hypothesis",
    "contradict_hypothesis",
    "mark_insufficient",
    "establish_causation",
    "get_hypothesis",
    "list_hypotheses",
]

logger = logging.getLogger("nighteye.hypothesis")

# ============================================================
# Hard Gates
# ============================================================

def _check_provenance_gate(evidence_refs: list[EvidenceRef]) -> tuple[bool, ProvenanceTier]:
    """Gate 1: All evidence must have audit trail."""
    audit_ids = [ref.audit_id for ref in evidence_refs if ref.audit_id]
    tier = derive_provenance(audit_ids)
    if tier == ProvenanceTier.NONE:
        return False, tier
    return True, tier

def _check_confidence_gate(
    confidence: ConfidenceBreakdown
) -> tuple[bool, str]:
    """Gate 2: Confidence must be above floor (31)."""
    if confidence.score < 31:
        return False, (
            f"Confidence {confidence.score} below floor. "
            f"Use mark_insufficient() or gather more evidence. "
            f"Breakdown: {confidence.factor_contributions}"
        )
    return True, ""

def _check_causation_gate(
    interpretation: str,
    causal_links: list[CausalLink],
) -> tuple[bool, str]:
    """Gate 3: Causation claims need proof."""
    causation_words = ["caused", "led to", "resulted in", "triggered", "because", "due to"]
    claims_causation = any(word in interpretation.lower() for word in causation_words)

    if claims_causation:
        has_strong_causal = any(
            link.level in (CausalLevel.CHAIN, CausalLevel.WRITE, CausalLevel.NET)
            for link in causal_links
        )
        if not has_strong_causal:
            return False, (
                "Causation language detected without CHAIN/WRITE/NET causal link. "
                "Call establish_causation() first."
            )
    return True, ""

def _check_anti_forensic_gate(
    evidence_refs: list[EvidenceRef],
    case_id: str,
    db_conn: Any,
    window_min: int = 15,
) -> tuple[bool, int, str]:
    """Gate 4: Anti-forensic proximity check."""
    # Check if any evidence falls within an evidence_disturbance window
    for ref in evidence_refs:
        # Get event timestamp from evidence
        # Simplified: query disturbances that overlap with evidence
        row = db_conn.execute(
            """
            SELECT COUNT(*) FROM evidence_disturbances 
            WHERE case_id = ? 
            AND window_start <= datetime('now') 
            AND window_end >= datetime('now', '-{} minutes')
            """.format(window_min),
            (case_id,),
        ).fetchone()

        if row and row[0] > 0:
            return True, 15, "Anti-forensic activity within 15min of evidence"

    return False, 0, ""

# ============================================================
# Core Operations
# ============================================================

def record_hypothesis(
    db_conn: Any,
    case_id: str,
    examiner: str,
    title: str,
    observation: str,
    interpretation: str,
    technique_ids: list[str],
    evidence_refs: list[EvidenceRef],
    causal_links: list[CausalLink] | None = None,
    suggested_by_cluster: str | None = None,
) -> Hypothesis:
    """Record a new hypothesis with full gate validation.

    Returns:
        Hypothesis object (status depends on gate results)

    Raises:
        ValueError: If gates fail critically
    """
    causal_links = causal_links or []
    now = datetime.now(timezone.utc)

    # Gate 1: Provenance
    provenance_ok, provenance_tier = _check_provenance_gate(evidence_refs)
    if not provenance_ok:
        raise ValueError("No audit trail for evidence - hypothesis rejected")

    # Gate 4: Anti-forensic (do this before confidence for penalty)
    af_nearby, af_penalty, af_reason = _check_anti_forensic_gate(
        evidence_refs, case_id, db_conn
    )

    # Compute confidence
    # Gather evidence domains from refs
    evidence_domains = set()
    for ref in evidence_refs:
        if ref.cluster_id:
            evidence_domains.add("cluster")
        if ref.canonical_event_ids:
            evidence_domains.add("canonical")
        if ref.entity_ids:
            evidence_domains.add("graph")

    # Get cluster strength if suggested by cluster
    cluster_strength = None
    if suggested_by_cluster:
        row = db_conn.execute(
            "SELECT strength FROM clusters WHERE cluster_id = ?",
            (suggested_by_cluster,),
        ).fetchone()
        if row:
            from nighteye.models import ClusterStrength
            cluster_strength = ClusterStrength(row["strength"])

    if cluster_strength is None:
        from nighteye.models import ClusterStrength
        cluster_strength = ClusterStrength.WEAK

    confidence = compute_adaptive_confidence(
        case_id=case_id,
        db_conn=db_conn,
        provenance_tier=provenance_tier,
        causal_links=causal_links,
        cluster_strength=cluster_strength,
        evidence_domains=evidence_domains,
        anti_forensic_nearby=af_nearby,
    )

    # Apply anti-forensic penalty
    if af_nearby:
        confidence.score = max(0, confidence.score - af_penalty)
        confidence.anti_forensic_penalty = af_penalty
        confidence.rationale += f"; {af_reason}"

    # Gate 2: Confidence floor
    confidence_ok, confidence_msg = _check_confidence_gate(confidence)
    if not confidence_ok:
        # Return insufficient evidence hypothesis instead of failing
        return mark_insufficient(
            db_conn, case_id, examiner, title, observation, interpretation,
            technique_ids, evidence_refs, reason=confidence_msg
        )

    # Gate 3: Causation
    causation_ok, causation_msg = _check_causation_gate(interpretation, causal_links)
    if not causation_ok:
        raise ValueError(causation_msg)

    # Build hypothesis
    hypothesis_id = f"H-{examiner}-{now.strftime('%Y%m%d%H%M%S')}"

    # Compute content hash for tamper detection
    content = json.dumps({
        "title": title,
        "observation": observation,
        "interpretation": interpretation,
        "technique_ids": technique_ids,
    }, sort_keys=True)
    content_hash = hashlib.sha256(content.encode()).hexdigest()[:32]

    # Determine initial status
    status = HypothesisStatus.DRAFT
    if (
        confidence.score >= 76
        and provenance_tier == ProvenanceTier.MCP
        and not af_nearby
        and (not _claims_causation(interpretation) or _has_strong_causal(causal_links))
    ):
        status = HypothesisStatus.APPROVED

    hypothesis = Hypothesis(
        id=hypothesis_id,
        case_id=case_id,
        examiner=examiner,
        title=title,
        observation=observation,
        interpretation=interpretation,
        technique_ids=technique_ids,
        status=status,
        staged_at=now,
        modified_at=now,
        evidence_refs=evidence_refs,
        audit_ids=[ref.audit_id for ref in evidence_refs],
        confidence=confidence,
        provenance_tier=provenance_tier,
        causal_links=causal_links,
        suggested_by_cluster=suggested_by_cluster,
        content_hash=content_hash,
    )

    # If approved, sign with HMAC
    if status == HypothesisStatus.APPROVED:
        _sign_hypothesis(db_conn, hypothesis)

    # Persist to database
    _persist_hypothesis(db_conn, hypothesis)

    logger.info(
        "Hypothesis %s recorded: %s (score=%d, tier=%s, status=%s)",
        hypothesis_id, title, confidence.score, confidence.tier.value, status.value
    )

    return hypothesis


def challenge_hypothesis(
    db_conn: Any,
    hypothesis_id: str,
) -> dict[str, Any]:
    """Run adversarial review on a hypothesis.

    Returns:
        Dict with verdict, reasoning, and updated status
    """
    hypothesis = get_hypothesis(db_conn, hypothesis_id)
    if not hypothesis:
        raise ValueError(f"Hypothesis not found: {hypothesis_id}")

    now = datetime.now(timezone.utc)

    # Get pre-computed counter-evidence from cluster
    counter_evidence: list[dict] = []
    contradictions: list[str] = []

    if hypothesis.suggested_by_cluster:
        row = db_conn.execute(
            "SELECT counter_evidence_details, contradicting_clusters FROM clusters WHERE cluster_id = ?",
            (hypothesis.suggested_by_cluster,),
        ).fetchone()
        if row:
            counter_evidence = json.loads(row["counter_evidence_details"] or "[]")
            contradictions = json.loads(row["contradicting_clusters"] or "[]")

    # Anti-forensic proximity check
    af_nearby, _, _ = _check_anti_forensic_gate(
        hypothesis.evidence_refs, hypothesis.case_id, db_conn
    )

    # Causal chain integrity
    causal_ok = (
        not _claims_causation(hypothesis.interpretation)
        or _has_strong_causal(hypothesis.causal_links)
    )

    # Compute verdict
    verdict: ChallengeVerdict
    reasoning: str
    new_status: HypothesisStatus | None = None

    if not causal_ok:
        verdict = ChallengeVerdict.REFUTED
        reasoning = "Causal chain integrity broken"
        new_status = HypothesisStatus.REJECTED

    elif contradictions:
        verdict = ChallengeVerdict.REFUTED
        reasoning = f"Contradicting clusters: {contradictions}"
        new_status = HypothesisStatus.CONTRADICTED

    elif af_nearby and not _has_corroboration_outside_disturbance(hypothesis):
        verdict = ChallengeVerdict.DOWNGRADED
        reasoning = "Anti-forensic proximity invalidates evidence"
        new_status = HypothesisStatus.INSUFFICIENT_EVIDENCE

    else:
        # Weight counter vs support
        counter_weight = sum(c.get("weight", 10) for c in counter_evidence if c.get("applies"))
        support_weight = len(hypothesis.evidence_refs) * 20  # Base weight per ref

        if counter_weight > support_weight * 0.6:
            verdict = ChallengeVerdict.REFUTED
            reasoning = "Counter-evidence outweighs support"
            new_status = HypothesisStatus.REJECTED
        elif counter_weight > 0:
            verdict = ChallengeVerdict.SUPPORTED_WITH_CAVEATS
            reasoning = "Support outweighs but counter-evidence exists"
        else:
            verdict = ChallengeVerdict.SUPPORTED
            reasoning = "No counter-evidence; chain intact"

    # Update hypothesis
    hypothesis.challenged_at = now
    hypothesis.challenge_verdict = verdict
    hypothesis.challenge_reasoning = reasoning

    if new_status:
        hypothesis.status = new_status
        hypothesis.modified_at = now

    _persist_hypothesis(db_conn, hypothesis)

    logger.info(
        "Hypothesis %s challenged: %s (%s)",
        hypothesis_id, verdict.value, reasoning
    )

    return {
        "hypothesis_id": hypothesis_id,
        "verdict": verdict.value,
        "reasoning": reasoning,
        "new_status": new_status.value if new_status else hypothesis.status.value,
    }


def approve_hypothesis(
    db_conn: Any,
    hypothesis_id: str,
    approved_by: str,
) -> Hypothesis:
    """Explicitly approve a hypothesis."""
    hypothesis = get_hypothesis(db_conn, hypothesis_id)
    if not hypothesis:
        raise ValueError(f"Hypothesis not found: {hypothesis_id}")

    if hypothesis.status not in (HypothesisStatus.DRAFT, HypothesisStatus.INSUFFICIENT_EVIDENCE):
        raise ValueError(f"Cannot approve hypothesis in status {hypothesis.status.value}")

    now = datetime.now(timezone.utc)
    hypothesis.status = HypothesisStatus.APPROVED
    hypothesis.approved_at = now
    hypothesis.approved_by = approved_by
    hypothesis.modified_at = now

    # Sign with HMAC
    _sign_hypothesis(db_conn, hypothesis)
    _persist_hypothesis(db_conn, hypothesis)

    logger.info("Hypothesis %s approved by %s", hypothesis_id, approved_by)
    return hypothesis


def reject_hypothesis(
    db_conn: Any,
    hypothesis_id: str,
    rejected_by: str,
    reason: str,
) -> Hypothesis:
    """Reject a hypothesis."""
    hypothesis = get_hypothesis(db_conn, hypothesis_id)
    if not hypothesis:
        raise ValueError(f"Hypothesis not found: {hypothesis_id}")

    now = datetime.now(timezone.utc)
    hypothesis.status = HypothesisStatus.REJECTED
    hypothesis.rejected_at = now
    hypothesis.rejected_by = rejected_by
    hypothesis.rejection_reason = reason
    hypothesis.modified_at = now

    _persist_hypothesis(db_conn, hypothesis)

    logger.info("Hypothesis %s rejected by %s: %s", hypothesis_id, rejected_by, reason)
    return hypothesis


def contradict_hypothesis(
    db_conn: Any,
    hypothesis_id: str,
    contradicting_hypothesis_id: str,
) -> Hypothesis:
    """Mark a hypothesis as contradicted by another."""
    hypothesis = get_hypothesis(db_conn, hypothesis_id)
    if not hypothesis:
        raise ValueError(f"Hypothesis not found: {hypothesis_id}")

    now = datetime.now(timezone.utc)
    hypothesis.status = HypothesisStatus.CONTRADICTED
    hypothesis.contradicted_by = contradicting_hypothesis_id
    hypothesis.modified_at = now

    _persist_hypothesis(db_conn, hypothesis)

    logger.info(
        "Hypothesis %s contradicted by %s",
        hypothesis_id, contradicting_hypothesis_id
    )
    return hypothesis


def mark_insufficient(
    db_conn: Any,
    case_id: str,
    examiner: str,
    title: str,
    observation: str,
    interpretation: str,
    technique_ids: list[str],
    evidence_refs: list[EvidenceRef],
    reason: str,
    what_would_resolve: str = "",
) -> Hypothesis:
    """Mark a hypothesis as insufficient evidence.

    Returns a hypothesis in INSUFFICIENT_EVIDENCE status.
    """
    now = datetime.now(timezone.utc)
    hypothesis_id = f"H-{examiner}-{now.strftime('%Y%m%d%H%M%S')}-ins"

    # Register evidence gap
    gap_id = f"GAP-{hypothesis_id}"
    execute_with_retry(
        db_conn,
        """
        INSERT INTO evidence_gaps (gap_id, case_id, question, what_would_resolve, 
                                    blocks_hypothesis, registered_at, registered_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            gap_id, case_id, reason, what_would_resolve or "Additional evidence needed",
            hypothesis_id, now.isoformat(), examiner,
        ),
    )
    db_conn.commit()

    hypothesis = Hypothesis(
        id=hypothesis_id,
        case_id=case_id,
        examiner=examiner,
        title=title,
        observation=observation,
        interpretation=interpretation,
        technique_ids=technique_ids,
        status=HypothesisStatus.INSUFFICIENT_EVIDENCE,
        staged_at=now,
        modified_at=now,
        evidence_refs=evidence_refs,
        confidence=ConfidenceBreakdown(
            score=0,
            tier=ConfidenceTier.SPECULATIVE,
            rationale=f"Insufficient evidence: {reason}",
        ),
        provenance_tier=ProvenanceTier.NONE,
    )

    _persist_hypothesis(db_conn, hypothesis)

    logger.info("Hypothesis %s marked insufficient: %s", hypothesis_id, reason)
    return hypothesis


def establish_causation(
    db_conn: Any,
    from_hypothesis_id: str,
    to_hypothesis_id: str,
    level: CausalLevel,
    proof_audit_ids: list[str],
    proof_edges: list[str],
    notes: str = "",
) -> CausalLink:
    """Establish a causal link between two hypotheses."""
    link = CausalLink(
        target_hypothesis=to_hypothesis_id,
        level=level,
        proof_audit_ids=proof_audit_ids,
        proof_edges=proof_edges,
        notes=notes,
    )

    # Update from hypothesis with causal link
    hypothesis = get_hypothesis(db_conn, from_hypothesis_id)
    if hypothesis:
        hypothesis.causal_links.append(link)
        hypothesis.modified_at = datetime.now(timezone.utc)
        _persist_hypothesis(db_conn, hypothesis)

    logger.info(
        "Causation established: %s → %s (level=%s)",
        from_hypothesis_id, to_hypothesis_id, level.value
    )
    return link


# ============================================================
# Queries
# ============================================================

def get_hypothesis(db_conn: Any, hypothesis_id: str) -> Hypothesis | None:
    """Load a hypothesis from the database."""
    row = db_conn.execute(
        "SELECT * FROM hypotheses WHERE hypothesis_id = ?",
        (hypothesis_id,),
    ).fetchone()

    if not row:
        return None

    return Hypothesis.from_dict(dict(row))


def list_hypotheses(
    db_conn: Any,
    case_id: str | None = None,
    status: HypothesisStatus | None = None,
    limit: int = 100,
) -> list[Hypothesis]:
    """List hypotheses with optional filtering."""
    sql = "SELECT * FROM hypotheses WHERE 1=1"
    params: list[Any] = []

    if case_id:
        sql += " AND case_id = ?"
        params.append(case_id)
    if status:
        sql += " AND status = ?"
        params.append(status.value)

    sql += " ORDER BY staged_at DESC LIMIT ?"
    params.append(limit)

    rows = db_conn.execute(sql, params).fetchall()
    return [Hypothesis.from_dict(dict(row)) for row in rows]


# ============================================================
# Helpers
# ============================================================

def _claims_causation(interpretation: str) -> bool:
    """Check if interpretation claims causation."""
    causation_words = ["caused", "led to", "resulted in", "triggered", "because", "due to"]
    return any(word in interpretation.lower() for word in causation_words)


def _has_strong_causal(causal_links: list[CausalLink]) -> bool:
    """Check if any causal link is strong enough."""
    return any(
        link.level in (CausalLevel.CHAIN, CausalLevel.WRITE, CausalLevel.NET)
        for link in causal_links
    )


def _has_corroboration_outside_disturbance(hypothesis: Hypothesis) -> bool:
    """Check if hypothesis has corroboration outside disturbance window."""
    # Simplified: check if evidence refs span multiple audit sources
    audit_sources = set()
    for ref in hypothesis.evidence_refs:
        if ref.audit_id:
            # Extract source prefix from audit_id
            prefix = ref.audit_id.split("-")[0] if "-" in ref.audit_id else ref.audit_id
            audit_sources.add(prefix)
    return len(audit_sources) >= 2


def _sign_hypothesis(db_conn: Any, hypothesis: Hypothesis) -> None:
    """Sign an approved hypothesis with HMAC.

    In production, this would use PBKDF2-derived key.
    For now, we compute a content hash.
    """
    if not hypothesis.content_hash:
        content = json.dumps({
            "id": hypothesis.id,
            "title": hypothesis.title,
            "observation": hypothesis.observation,
            "interpretation": hypothesis.interpretation,
            "technique_ids": hypothesis.technique_ids,
        }, sort_keys=True)
        hypothesis.content_hash = hashlib.sha256(content.encode()).hexdigest()[:32]

    # HMAC would be computed here with PBKDF2 key
    # For now, store the content hash as signature placeholder
    hypothesis.hmac_signature = f"hmac-v1-{hypothesis.content_hash}"


def _persist_hypothesis(db_conn: Any, hypothesis: Hypothesis) -> None:
    """Persist hypothesis to SQLite."""
    now = datetime.now(timezone.utc).isoformat()

    execute_with_retry(
        db_conn,
        """
        INSERT INTO hypotheses (
            hypothesis_id, case_id, examiner, title, observation, interpretation,
            technique_ids, status, staged_at, modified_at, approved_at, approved_by,
            rejected_at, rejected_by, rejection_reason, contradicted_by,
            evidence_refs, audit_ids, confidence_score, confidence_tier,
            confidence_breakdown, provenance_tier, causal_links, suggested_by_cluster,
            content_hash, hmac_signature, challenged_at, challenge_verdict, challenge_reasoning
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(hypothesis_id) DO UPDATE SET
            status = excluded.status,
            modified_at = excluded.modified_at,
            approved_at = excluded.approved_at,
            approved_by = excluded.approved_by,
            rejected_at = excluded.rejected_at,
            rejected_by = excluded.rejected_by,
            rejection_reason = excluded.rejection_reason,
            contradicted_by = excluded.contradicted_by,
            evidence_refs = excluded.evidence_refs,
            audit_ids = excluded.audit_ids,
            confidence_score = excluded.confidence_score,
            confidence_tier = excluded.confidence_tier,
            confidence_breakdown = excluded.confidence_breakdown,
            provenance_tier = excluded.provenance_tier,
            causal_links = excluded.causal_links,
            content_hash = excluded.content_hash,
            hmac_signature = excluded.hmac_signature,
            challenged_at = excluded.challenged_at,
            challenge_verdict = excluded.challenge_verdict,
            challenge_reasoning = excluded.challenge_reasoning
        """,
        (
            hypothesis.id,
            hypothesis.case_id,
            hypothesis.examiner,
            hypothesis.title,
            hypothesis.observation,
            hypothesis.interpretation,
            json.dumps(hypothesis.technique_ids),
            hypothesis.status.value,
            hypothesis.staged_at.isoformat() if hypothesis.staged_at else now,
            hypothesis.modified_at.isoformat() if hypothesis.modified_at else now,
            hypothesis.approved_at.isoformat() if hypothesis.approved_at else None,
            hypothesis.approved_by,
            hypothesis.rejected_at.isoformat() if hypothesis.rejected_at else None,
            hypothesis.rejected_by,
            hypothesis.rejection_reason,
            hypothesis.contradicted_by,
            json.dumps([{"audit_id": r.audit_id, "description": r.description, 
                        "cluster_id": r.cluster_id} for r in hypothesis.evidence_refs]),
            json.dumps(hypothesis.audit_ids),
            hypothesis.confidence.score if hypothesis.confidence else 0,
            hypothesis.confidence.tier.value if hypothesis.confidence else ConfidenceTier.SPECULATIVE.value,
            hypothesis.confidence.to_json() if hypothesis.confidence else "{}",
            hypothesis.provenance_tier.value,
            json.dumps([{"target": c.target_hypothesis, "level": c.level.value,
                        "proof": c.proof_audit_ids, "notes": c.notes} for c in hypothesis.causal_links]),
            hypothesis.suggested_by_cluster,
            hypothesis.content_hash,
            hypothesis.hmac_signature,
            hypothesis.challenged_at.isoformat() if hypothesis.challenged_at else None,
            hypothesis.challenge_verdict.value if hypothesis.challenge_verdict else None,
            hypothesis.challenge_reasoning,
        ),
    )
    db_conn.commit()
