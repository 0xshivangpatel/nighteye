"""Tests for NightEye data models (nighteye.models).

Covers JSON round-tripping, enum values, dataclass construction,
and edge cases for all core models.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from nighteye.models import (
    CausalLevel,
    CausalLink,
    ChallengeVerdict,
    ClusterStrength,
    ConfidenceBreakdown,
    ConfidenceTier,
    EvidenceGap,
    EvidenceRef,
    Hypothesis,
    HypothesisStatus,
    JournalEntry,
    JournalEntryType,
    ProvenanceTier,
)


# ============================================================
# Enum completeness
# ============================================================


def test_hypothesis_status_values() -> None:
    expected = {"DRAFT", "INSUFFICIENT_EVIDENCE", "APPROVED",
                "REJECTED", "CONTRADICTED", "DOWNGRADED"}
    actual = {s.value for s in HypothesisStatus}
    assert actual == expected


def test_confidence_tier_values() -> None:
    expected = {"HIGH", "MEDIUM", "LOW", "SPECULATIVE"}
    actual = {t.value for t in ConfidenceTier}
    assert actual == expected


def test_causal_level_values() -> None:
    expected = {"CHAIN", "WRITE", "NET", "TIGHT_TIME",
                "CO_OCCUR", "TEMPORAL_ONLY", "UNSUPPORTED"}
    actual = {c.value for c in CausalLevel}
    assert actual == expected


def test_provenance_tier_values() -> None:
    expected = {"MCP", "HOOK", "SHELL", "NONE"}
    actual = {p.value for p in ProvenanceTier}
    assert actual == expected


def test_challenge_verdict_values() -> None:
    expected = {"SUPPORTED", "SUPPORTED_WITH_CAVEATS", "REFUTED",
                "DOWNGRADED", "INSUFFICIENT"}
    actual = {v.value for v in ChallengeVerdict}
    assert actual == expected


def test_cluster_strength_values() -> None:
    expected = {"STRONG", "MODERATE", "WEAK", "NOISE"}
    actual = {s.value for s in ClusterStrength}
    assert actual == expected


def test_journal_entry_type_values() -> None:
    expected = {
        "SESSION_START", "SESSION_END",
        "CLUSTER_INVESTIGATED", "HYPOTHESIS_RECORDED",
        "HYPOTHESIS_CHALLENGED", "EVIDENCE_GAP_REGISTERED",
        "CAUSATION_ESTABLISHED", "ROOT_CAUSE_ATTEMPTED",
        "INVESTIGATION_DECISION", "CHECKPOINT_SUMMARY",
        "RESUME_DIGEST_READ",
    }
    actual = {t.value for t in JournalEntryType}
    assert actual == expected


# ============================================================
# ConfidenceBreakdown
# ============================================================


def test_confidence_breakdown_round_trip() -> None:
    cb = ConfidenceBreakdown(
        score=82,
        tier=ConfidenceTier.HIGH,
        applicable_factors=["provenance_tier", "causal_lineage"],
        consulted_factors=["provenance_tier"],
        factor_contributions={"provenance_tier": 20},
        anti_forensic_penalty=0,
        cluster_strength_bonus=15,
        rationale="Strong evidence from MCP provenance",
    )
    j = cb.to_json()
    parsed = json.loads(j)
    assert parsed["score"] == 82
    assert parsed["tier"] == "HIGH"

    restored = ConfidenceBreakdown.from_json(j)
    assert restored.score == 82
    assert restored.tier == ConfidenceTier.HIGH
    assert restored.applicable_factors == ["provenance_tier", "causal_lineage"]
    assert restored.consulted_factors == ["provenance_tier"]
    assert restored.factor_contributions == {"provenance_tier": 20}
    assert restored.anti_forensic_penalty == 0
    assert restored.cluster_strength_bonus == 15
    assert restored.rationale == "Strong evidence from MCP provenance"


def test_confidence_breakdown_defaults() -> None:
    cb = ConfidenceBreakdown(score=50, tier=ConfidenceTier.MEDIUM)
    assert cb.applicable_factors == []
    assert cb.anti_forensic_penalty == 0
    assert cb.rationale == ""


# ============================================================
# EvidenceRef
# ============================================================


def test_evidence_ref_round_trip() -> None:
    er = EvidenceRef(
        audit_id="nighteye-alice-20260429-001",
        description="Lateral movement via PsExec",
        cluster_id="cluster-LM-001",
        canonical_event_ids=["evt-001", "evt-002"],
        entity_ids=["ent-001"],
        edge_ids=["edg-001"],
    )
    j = er.to_json()
    restored = EvidenceRef.from_json(j)
    assert restored.audit_id == "nighteye-alice-20260429-001"
    assert restored.cluster_id == "cluster-LM-001"
    assert restored.canonical_event_ids == ["evt-001", "evt-002"]
    assert restored.description == "Lateral movement via PsExec"


def test_evidence_ref_optional_fields() -> None:
    er = EvidenceRef(
        audit_id="test-id",
        description="minimal",
    )
    assert er.cluster_id is None
    assert er.canonical_event_ids == []
    assert er.entity_ids == []


# ============================================================
# CausalLink
# ============================================================


def test_causal_link_round_trip() -> None:
    cl = CausalLink(
        target_hypothesis="H-001",
        level=CausalLevel.CHAIN,
        proof_audit_ids=["a-001"],
        proof_edges=["e-001"],
        notes="Process tree chain observed",
    )
    j = cl.to_json()
    restored = CausalLink.from_json(j)
    assert restored.target_hypothesis == "H-001"
    assert restored.level == CausalLevel.CHAIN
    assert restored.proof_audit_ids == ["a-001"]
    assert restored.notes == "Process tree chain observed"


# ============================================================
# Hypothesis
# ============================================================


def _make_hypothesis(**overrides) -> Hypothesis:
    """Create a minimal Hypothesis for testing."""
    now = datetime.now(timezone.utc)
    defaults = dict(
        id="H-test-001",
        case_id="INC-2026-001",
        examiner="alice",
        title="Test Hypothesis",
        observation="Observed lateral movement",
        interpretation="Attacker pivoted from WKSTN to DC01",
        technique_ids=["T1021.002"],
        status=HypothesisStatus.DRAFT,
        staged_at=now,
        modified_at=now,
        provenance_tier=ProvenanceTier.MCP,
    )
    defaults.update(overrides)
    return Hypothesis(**defaults)


def test_hypothesis_to_dict_and_back() -> None:
    h = _make_hypothesis(
        confidence=ConfidenceBreakdown(
            score=78, tier=ConfidenceTier.HIGH,
            applicable_factors=["provenance_tier"],
            consulted_factors=["provenance_tier"],
            factor_contributions={"provenance_tier": 20},
        ),
        evidence_refs=[
            EvidenceRef(
                audit_id="a-001",
                description="test ref",
                cluster_id="c-001",
            )
        ],
        causal_links=[
            CausalLink(
                target_hypothesis="H-002",
                level=CausalLevel.WRITE,
            )
        ],
    )
    d = h.to_dict()
    assert d["status"] == "DRAFT"
    assert d["provenance_tier"] == "MCP"
    assert d["confidence"]["score"] == 78

    restored = Hypothesis.from_dict(d)
    assert restored.id == "H-test-001"
    assert restored.status == HypothesisStatus.DRAFT
    assert restored.confidence is not None
    assert restored.confidence.score == 78
    assert len(restored.evidence_refs) == 1
    assert len(restored.causal_links) == 1
    assert restored.causal_links[0].level == CausalLevel.WRITE


def test_hypothesis_json_round_trip() -> None:
    h = _make_hypothesis()
    j = h.to_json()
    restored = Hypothesis.from_json(j)
    assert restored.id == h.id
    assert restored.case_id == h.case_id
    assert restored.examiner == h.examiner
    assert restored.status == h.status


def test_hypothesis_optional_fields_default() -> None:
    h = _make_hypothesis()
    assert h.approved_at is None
    assert h.approved_by is None
    assert h.rejected_at is None
    assert h.challenge_verdict is None
    assert h.content_hash is None
    assert h.hmac_signature is None
    assert h.suggested_by_cluster is None


def test_hypothesis_with_challenge_verdict() -> None:
    h = _make_hypothesis(
        challenge_verdict=ChallengeVerdict.SUPPORTED,
        challenge_reasoning="All checks passed",
        challenged_at=datetime.now(timezone.utc),
    )
    d = h.to_dict()
    assert d["challenge_verdict"] == "SUPPORTED"
    assert d["challenge_reasoning"] == "All checks passed"

    restored = Hypothesis.from_dict(d)
    assert restored.challenge_verdict == ChallengeVerdict.SUPPORTED


def test_hypothesis_timestamps_serialize_as_iso() -> None:
    h = _make_hypothesis()
    d = h.to_dict()
    # staged_at and modified_at should be ISO strings
    assert isinstance(d["staged_at"], str)
    assert "T" in d["staged_at"]


# ============================================================
# EvidenceGap
# ============================================================


def test_evidence_gap_round_trip() -> None:
    eg = EvidenceGap(
        id="G-001",
        case_id="INC-001",
        question="Was data exfiltrated?",
        what_would_resolve="Network gateway logs between 14:00-18:00",
        blocks_hypothesis="H-003",
        blocks_report=True,
        registered_at=datetime.now(timezone.utc),
        registered_by="alice",
    )
    j = eg.to_json()
    restored = EvidenceGap.from_json(j)
    assert restored.id == "G-001"
    assert restored.question == "Was data exfiltrated?"
    assert restored.blocks_hypothesis == "H-003"
    assert restored.blocks_report is True
    assert restored.registered_by == "alice"
    assert restored.resolved_at is None
    assert restored.resolution is None


def test_evidence_gap_resolved() -> None:
    now = datetime.now(timezone.utc)
    eg = EvidenceGap(
        id="G-002",
        case_id="INC-001",
        question="What process dropped the binary?",
        what_would_resolve="Process tree from Sysmon",
        resolved_at=now,
        resolution="Found via Sysmon event 1 — PID 4532",
    )
    d = eg.to_dict()
    assert d["resolved_at"] is not None
    assert d["resolution"] == "Found via Sysmon event 1 — PID 4532"


def test_evidence_gap_defaults() -> None:
    eg = EvidenceGap(
        id="G-003",
        case_id="INC-001",
        question="q",
        what_would_resolve="w",
    )
    assert eg.blocks_hypothesis is None
    assert eg.blocks_report is False
    assert eg.registered_by == ""


# ============================================================
# JournalEntry
# ============================================================


def test_journal_entry_round_trip() -> None:
    now = datetime.now(timezone.utc)
    je = JournalEntry(
        entry_id="J-alice-001",
        case_id="INC-001",
        timestamp=now,
        entry_type=JournalEntryType.HYPOTHESIS_RECORDED,
        summary="Recorded H-001 for lateral movement",
        investigation_id="main",
        details={"hypothesis_id": "H-001", "score": 82, "tier": "HIGH"},
        agent_session_id="session-abc",
    )
    j = je.to_json()
    restored = JournalEntry.from_json(j)
    assert restored.entry_id == "J-alice-001"
    assert restored.entry_type == JournalEntryType.HYPOTHESIS_RECORDED
    assert restored.details["hypothesis_id"] == "H-001"
    assert restored.agent_session_id == "session-abc"
    assert restored.supersedes is None


def test_journal_entry_defaults() -> None:
    now = datetime.now(timezone.utc)
    je = JournalEntry(
        entry_id="J-001",
        case_id="INC-001",
        timestamp=now,
        entry_type=JournalEntryType.SESSION_START,
        summary="Session started",
    )
    assert je.investigation_id == "main"
    assert je.details == {}
    assert je.agent_session_id is None
    assert je.supersedes is None


def test_journal_entry_supersedes() -> None:
    now = datetime.now(timezone.utc)
    je = JournalEntry(
        entry_id="J-002",
        case_id="INC-001",
        timestamp=now,
        entry_type=JournalEntryType.CHECKPOINT_SUMMARY,
        summary="Updated checkpoint",
        supersedes="J-001",
    )
    d = je.to_dict()
    assert d["supersedes"] == "J-001"
    restored = JournalEntry.from_dict(d)
    assert restored.supersedes == "J-001"


def test_journal_entry_timestamp_iso_serialization() -> None:
    now = datetime.now(timezone.utc)
    je = JournalEntry(
        entry_id="J-003",
        case_id="INC-001",
        timestamp=now,
        entry_type=JournalEntryType.SESSION_END,
        summary="Done",
    )
    d = je.to_dict()
    assert isinstance(d["timestamp"], str)
    assert "T" in d["timestamp"]


# ============================================================
# Module __all__
# ============================================================


def test_models_all_exports() -> None:
    """Verify __all__ exports all public model names."""
    from nighteye import models
    expected_names = {
        "CausalLevel", "CausalLink", "ChallengeVerdict",
        "ClusterStrength", "ConfidenceBreakdown", "ConfidenceTier",
        "EvidenceGap", "EvidenceRef", "Hypothesis",
        "HypothesisStatus", "JournalEntry", "JournalEntryType",
        "ProvenanceTier",
    }
    assert set(models.__all__) == expected_names
