"""NightEye core dataclasses.

Mirrors the schema in docs/ARCHITECTURE.md sec 6 and the journal schema
in docs/JOURNAL.md. These are the in-memory representations used by
constructors, MCP tools, and the portal.

Every dataclass provides `to_json()` and `from_json()` round-tripping
helpers for storage in SQLite TEXT columns and for OpenSearch indexing.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


# ============================================================
# Enums
# ============================================================


class HypothesisStatus(str, Enum):
    DRAFT = "DRAFT"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    CONTRADICTED = "CONTRADICTED"
    DOWNGRADED = "DOWNGRADED"


class ConfidenceTier(str, Enum):
    HIGH = "HIGH"          # 76-100
    MEDIUM = "MEDIUM"      # 51-75
    LOW = "LOW"            # 31-50
    SPECULATIVE = "SPECULATIVE"  # 0-30; cannot be APPROVED


class CausalLevel(str, Enum):
    CHAIN = "CHAIN"
    WRITE = "WRITE"
    NET = "NET"
    TIGHT_TIME = "TIGHT_TIME"
    CO_OCCUR = "CO_OCCUR"
    TEMPORAL_ONLY = "TEMPORAL_ONLY"
    UNSUPPORTED = "UNSUPPORTED"


class ProvenanceTier(str, Enum):
    MCP = "MCP"
    HOOK = "HOOK"
    SHELL = "SHELL"
    NONE = "NONE"


class ChallengeVerdict(str, Enum):
    SUPPORTED = "SUPPORTED"
    SUPPORTED_WITH_CAVEATS = "SUPPORTED_WITH_CAVEATS"
    REFUTED = "REFUTED"
    DOWNGRADED = "DOWNGRADED"
    INSUFFICIENT = "INSUFFICIENT"


class ClusterStrength(str, Enum):
    STRONG = "STRONG"
    MODERATE = "MODERATE"
    WEAK = "WEAK"
    NOISE = "NOISE"


class JournalEntryType(str, Enum):
    SESSION_START = "SESSION_START"
    SESSION_END = "SESSION_END"
    CLUSTER_INVESTIGATED = "CLUSTER_INVESTIGATED"
    HYPOTHESIS_RECORDED = "HYPOTHESIS_RECORDED"
    HYPOTHESIS_CHALLENGED = "HYPOTHESIS_CHALLENGED"
    EVIDENCE_GAP_REGISTERED = "EVIDENCE_GAP_REGISTERED"
    CAUSATION_ESTABLISHED = "CAUSATION_ESTABLISHED"
    ROOT_CAUSE_ATTEMPTED = "ROOT_CAUSE_ATTEMPTED"
    INVESTIGATION_DECISION = "INVESTIGATION_DECISION"
    CHECKPOINT_SUMMARY = "CHECKPOINT_SUMMARY"
    RESUME_DIGEST_READ = "RESUME_DIGEST_READ"


# ============================================================
# Helpers
# ============================================================


def _json_default(obj: Any) -> Any:
    """JSON encoder for dataclass + datetime + Enum values."""
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _to_json(obj: Any) -> str:
    return json.dumps(obj, default=_json_default, sort_keys=True)


def _parse_dt(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value.replace("Z", "+00:00") if value.endswith("Z") else value)


# ============================================================
# Confidence
# ============================================================


@dataclass
class ConfidenceBreakdown:
    score: int
    tier: ConfidenceTier
    applicable_factors: list[str] = field(default_factory=list)
    consulted_factors: list[str] = field(default_factory=list)
    factor_contributions: dict[str, int] = field(default_factory=dict)
    anti_forensic_penalty: int = 0
    cluster_strength_bonus: int = 0
    rationale: str = ""

    def to_json(self) -> str:
        return _to_json(self)

    @classmethod
    def from_json(cls, raw: str) -> ConfidenceBreakdown:
        d = json.loads(raw)
        return cls(
            score=int(d["score"]),
            tier=ConfidenceTier(d["tier"]),
            applicable_factors=list(d.get("applicable_factors", [])),
            consulted_factors=list(d.get("consulted_factors", [])),
            factor_contributions=dict(d.get("factor_contributions", {})),
            anti_forensic_penalty=int(d.get("anti_forensic_penalty", 0)),
            cluster_strength_bonus=int(d.get("cluster_strength_bonus", 0)),
            rationale=str(d.get("rationale", "")),
        )


# ============================================================
# Evidence
# ============================================================


@dataclass
class EvidenceRef:
    audit_id: str
    description: str
    cluster_id: str | None = None
    canonical_event_ids: list[str] = field(default_factory=list)
    entity_ids: list[str] = field(default_factory=list)
    edge_ids: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        return _to_json(self)

    @classmethod
    def from_json(cls, raw: str) -> EvidenceRef:
        d = json.loads(raw)
        return cls(**d)


@dataclass
class CausalLink:
    target_hypothesis: str
    level: CausalLevel
    proof_audit_ids: list[str] = field(default_factory=list)
    proof_edges: list[str] = field(default_factory=list)
    notes: str = ""

    def to_json(self) -> str:
        return _to_json(self)

    @classmethod
    def from_json(cls, raw: str) -> CausalLink:
        d = json.loads(raw)
        return cls(
            target_hypothesis=d["target_hypothesis"],
            level=CausalLevel(d["level"]),
            proof_audit_ids=list(d.get("proof_audit_ids", [])),
            proof_edges=list(d.get("proof_edges", [])),
            notes=str(d.get("notes", "")),
        )


# ============================================================
# Hypothesis
# ============================================================


@dataclass
class Hypothesis:
    id: str
    case_id: str
    examiner: str
    title: str
    observation: str
    interpretation: str
    technique_ids: list[str]
    status: HypothesisStatus
    staged_at: datetime
    modified_at: datetime
    approved_at: datetime | None = None
    approved_by: str | None = None
    rejected_at: datetime | None = None
    rejected_by: str | None = None
    rejection_reason: str | None = None
    contradicted_by: str | None = None
    evidence_refs: list[EvidenceRef] = field(default_factory=list)
    audit_ids: list[str] = field(default_factory=list)
    confidence: ConfidenceBreakdown | None = None
    provenance_tier: ProvenanceTier = ProvenanceTier.NONE
    causal_links: list[CausalLink] = field(default_factory=list)
    suggested_by_cluster: str | None = None
    content_hash: str | None = None
    hmac_signature: str | None = None
    challenged_at: datetime | None = None
    challenge_verdict: ChallengeVerdict | None = None
    challenge_reasoning: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["provenance_tier"] = self.provenance_tier.value
        if self.confidence:
            d["confidence"] = json.loads(self.confidence.to_json())
        d["evidence_refs"] = [json.loads(e.to_json()) for e in self.evidence_refs]
        d["causal_links"] = [json.loads(c.to_json()) for c in self.causal_links]
        if self.challenge_verdict:
            d["challenge_verdict"] = self.challenge_verdict.value
        for ts_field in ("staged_at", "modified_at", "approved_at",
                         "rejected_at", "challenged_at"):
            v = d.get(ts_field)
            if isinstance(v, datetime):
                d[ts_field] = v.isoformat()
        return d

    def to_json(self) -> str:
        return _to_json(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Hypothesis:
        confidence = None
        if d.get("confidence"):
            conf_data = d["confidence"]
            if isinstance(conf_data, str):
                confidence = ConfidenceBreakdown.from_json(conf_data)
            else:
                confidence = ConfidenceBreakdown.from_json(json.dumps(conf_data))

        raw_refs = d.get("evidence_refs", [])
        if isinstance(raw_refs, str):
            try:
                raw_refs = json.loads(raw_refs)
            except:
                raw_refs = []
        evidence_refs = [
            EvidenceRef.from_json(json.dumps(e)) if not isinstance(e, EvidenceRef) else e 
            for e in raw_refs
        ]

        raw_links = d.get("causal_links", [])
        if isinstance(raw_links, str):
            try:
                raw_links = json.loads(raw_links)
            except:
                raw_links = []
        causal_links = [
            CausalLink.from_json(json.dumps(c)) if not isinstance(c, CausalLink) else c 
            for c in raw_links
        ]
        raw_tech = d.get("technique_ids", [])
        if isinstance(raw_tech, str):
            try:
                raw_tech = json.loads(raw_tech)
            except:
                raw_tech = []
        
        raw_audits = d.get("audit_ids", [])
        if isinstance(raw_audits, str):
            try:
                raw_audits = json.loads(raw_audits)
            except:
                raw_audits = []

        cv = d.get("challenge_verdict")
        return cls(
            id=d.get("hypothesis_id", d.get("id")),
            case_id=d["case_id"],
            examiner=d["examiner"],
            title=d["title"],
            observation=d["observation"],
            interpretation=d["interpretation"],
            technique_ids=list(raw_tech),
            status=HypothesisStatus(d["status"]),
            staged_at=_parse_dt(d["staged_at"]),  # type: ignore[arg-type]
            modified_at=_parse_dt(d["modified_at"]),  # type: ignore[arg-type]
            approved_at=_parse_dt(d.get("approved_at")),
            approved_by=d.get("approved_by"),
            rejected_at=_parse_dt(d.get("rejected_at")),
            rejected_by=d.get("rejected_by"),
            rejection_reason=d.get("rejection_reason"),
            contradicted_by=d.get("contradicted_by"),
            evidence_refs=evidence_refs,
            audit_ids=list(raw_audits),
            confidence=confidence,
            provenance_tier=ProvenanceTier(d.get("provenance_tier", "NONE")),
            causal_links=causal_links,
            suggested_by_cluster=d.get("suggested_by_cluster"),
            content_hash=d.get("content_hash"),
            hmac_signature=d.get("hmac_signature"),
            challenged_at=_parse_dt(d.get("challenged_at")),
            challenge_verdict=ChallengeVerdict(cv) if cv else None,
            challenge_reasoning=d.get("challenge_reasoning"),
        )

    @classmethod
    def from_json(cls, raw: str) -> Hypothesis:
        return cls.from_dict(json.loads(raw))


# ============================================================
# Evidence gap
# ============================================================


@dataclass
class EvidenceGap:
    id: str
    case_id: str
    question: str
    what_would_resolve: str
    blocks_hypothesis: str | None = None
    blocks_report: bool = False
    registered_at: datetime | None = None
    registered_by: str = ""
    resolved_at: datetime | None = None
    resolution: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for ts in ("registered_at", "resolved_at"):
            v = d.get(ts)
            if isinstance(v, datetime):
                d[ts] = v.isoformat()
        return d

    def to_json(self) -> str:
        return _to_json(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> EvidenceGap:
        return cls(
            id=d["id"],
            case_id=d["case_id"],
            question=d["question"],
            what_would_resolve=d["what_would_resolve"],
            blocks_hypothesis=d.get("blocks_hypothesis"),
            blocks_report=bool(d.get("blocks_report", False)),
            registered_at=_parse_dt(d.get("registered_at")),
            registered_by=d.get("registered_by", ""),
            resolved_at=_parse_dt(d.get("resolved_at")),
            resolution=d.get("resolution"),
        )

    @classmethod
    def from_json(cls, raw: str) -> EvidenceGap:
        return cls.from_dict(json.loads(raw))


# ============================================================
# Journal
# ============================================================


@dataclass
class JournalEntry:
    entry_id: str
    case_id: str
    timestamp: datetime
    entry_type: JournalEntryType
    summary: str
    investigation_id: str = "main"
    details: dict[str, Any] = field(default_factory=dict)
    agent_session_id: str | None = None
    supersedes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["entry_type"] = self.entry_type.value
        if isinstance(d.get("timestamp"), datetime):
            d["timestamp"] = d["timestamp"].isoformat()
        return d

    def to_json(self) -> str:
        return _to_json(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> JournalEntry:
        return cls(
            entry_id=d["entry_id"],
            case_id=d["case_id"],
            timestamp=_parse_dt(d["timestamp"]),  # type: ignore[arg-type]
            entry_type=JournalEntryType(d["entry_type"]),
            summary=d["summary"],
            investigation_id=d.get("investigation_id", "main"),
            details=dict(d.get("details") or {}),
            agent_session_id=d.get("agent_session_id"),
            supersedes=d.get("supersedes"),
        )

    @classmethod
    def from_json(cls, raw: str) -> JournalEntry:
        return cls.from_dict(json.loads(raw))


__all__ = [
    "CausalLevel",
    "CausalLink",
    "ChallengeVerdict",
    "ClusterStrength",
    "ConfidenceBreakdown",
    "ConfidenceTier",
    "EvidenceGap",
    "EvidenceRef",
    "Hypothesis",
    "HypothesisStatus",
    "JournalEntry",
    "JournalEntryType",
    "ProvenanceTier",
]
