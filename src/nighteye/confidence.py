"""Adaptive Deterministic Confidence Engine.

Computes confidence scores for hypotheses based on case capabilities,
evidence quality, provenance, and anti-forensic penalties.

The public API is ``compute_adaptive_confidence(profile, factors)``,
which accepts a :class:`CaseProfile` describing the investigation
environment and a :class:`HypothesisFactors` describing the evidence
gathered for one hypothesis.

References:
  - docs/ARCHITECTURE.md § 11 (Layer 7: Validation and Confidence)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from nighteye.models import (
    CausalLevel,
    ClusterStrength,
    ConfidenceBreakdown,
    ConfidenceTier,
    ProvenanceTier,
)

__all__ = [
    "CaseProfile",
    "HypothesisFactors",
    "compute_adaptive_confidence",
    "compute_adaptive_confidence_from_db",
    "ConfidenceEngine",
    "score_to_tier",
    "WEIGHTS",
    "FACTOR_MAX_WEIGHTS",
    "PENALTIES",
    "CAUSAL_WEIGHTS",
    "CLUSTER_WEIGHTS",
    "PROVENANCE_WEIGHTS",
]

logger = logging.getLogger("nighteye.confidence")


# ============================================================
# Weight configuration
# ============================================================

# Factor → maximum weight when fully consulted.
# This is the denominator basis for the consulted/applicable ratio.
WEIGHTS: dict[str, int] = {
    "provenance_tier": 20,
    "causal_lineage": 15,
    "cluster_strength": 15,
    "domain_breadth": 20,
    "cross_host_corroboration": 10,
    "sigma_co_occurrence": 10,
    "threat_intel_match": 5,
    "anti_forensic_clear": 5,
    "memory_corroboration": 5,
    "network_corroboration": 5,
}

# Public alias preferred by external callers and tests.
FACTOR_MAX_WEIGHTS: dict[str, int] = WEIGHTS

PENALTIES: dict[str, int] = {
    "anti_forensic_proximity": -15,
    "contradicting_cluster": -20,
}

# Causal level weights (max contribution to causal_lineage factor).
CAUSAL_WEIGHTS: dict[CausalLevel, int] = {
    CausalLevel.CHAIN: 15,
    CausalLevel.WRITE: 12,
    CausalLevel.NET: 10,
    CausalLevel.TIGHT_TIME: 6,
    CausalLevel.CO_OCCUR: 3,
    CausalLevel.TEMPORAL_ONLY: 1,
    CausalLevel.UNSUPPORTED: 0,
}

# Cluster strength weights (max contribution to cluster_strength factor).
CLUSTER_WEIGHTS: dict[ClusterStrength, int] = {
    ClusterStrength.STRONG: 15,
    ClusterStrength.MODERATE: 10,
    ClusterStrength.WEAK: 4,
    ClusterStrength.NOISE: 0,
}

# Provenance weights (max contribution to provenance_tier factor).
PROVENANCE_WEIGHTS: dict[ProvenanceTier, int] = {
    ProvenanceTier.MCP: 20,
    ProvenanceTier.HOOK: 15,
    ProvenanceTier.SHELL: 8,
    ProvenanceTier.NONE: 0,
}


# ============================================================
# Tier mapping
# ============================================================


def score_to_tier(score: int) -> ConfidenceTier:
    """Map a 0-100 score to its confidence tier.

    Boundaries (per ARCHITECTURE.md § 11):
      - 0-30  → SPECULATIVE (cannot be approved)
      - 31-50 → LOW
      - 51-75 → MEDIUM
      - 76-100→ HIGH
    """
    if score >= 76:
        return ConfidenceTier.HIGH
    if score >= 51:
        return ConfidenceTier.MEDIUM
    if score >= 31:
        return ConfidenceTier.LOW
    return ConfidenceTier.SPECULATIVE


# ============================================================
# Inputs
# ============================================================


@dataclass
class CaseProfile:
    """Profile of case capabilities at ingest completion.

    Determines which confidence factors are *applicable* to hypotheses
    in this case. A single-host investigation cannot be penalized for
    failing to corroborate across hosts.
    """

    host_count: int = 1
    artifact_types_available: set[str] = field(default_factory=set)
    intel_sources_configured: set[str] = field(default_factory=set)
    anti_forensic_observed: bool = False
    memory_available: bool = False
    network_available: bool = False

    # Backward-compat aliases for older callers
    def __post_init__(self) -> None:
        # accept legacy kwarg names if passed via from_kwargs helpers
        pass

    @property
    def artifact_types(self) -> set[str]:
        """Legacy alias for ``artifact_types_available``."""
        return self.artifact_types_available

    @property
    def intel_sources(self) -> set[str]:
        """Legacy alias for ``intel_sources_configured``."""
        return self.intel_sources_configured

    @classmethod
    def from_db(cls, db_conn: Any, case_id: str) -> CaseProfile:
        """Load case profile from the case_capabilities table.

        Returns a default minimal profile if the row is missing.
        """
        try:
            row = db_conn.execute(
                "SELECT * FROM case_capabilities WHERE case_id = ?", (case_id,)
            ).fetchone()
        except Exception:
            return cls()
        if not row:
            return cls()

        import json

        try:
            artifact_types = set(json.loads(row["artifact_types"]))
        except (TypeError, ValueError, json.JSONDecodeError):
            artifact_types = set()

        return cls(
            host_count=int(row["host_count"]),
            artifact_types_available=artifact_types,
            intel_sources_configured=set(),  # would be loaded from config
            anti_forensic_observed=bool(row["anti_forensic_observed"]),
            memory_available=bool(row["has_memory"]),
            network_available=bool(row["has_network"]),
        )


@dataclass
class HypothesisFactors:
    """The per-hypothesis factor inputs.

    All conditional fields default to absent (False/0). Fields that are
    absent will not contribute to the score nor count as consulted.
    """

    provenance_tier: ProvenanceTier
    causal_level: CausalLevel
    cluster_strength: ClusterStrength | None
    domain_count: int
    corroborating_hosts: int = 0
    sigma_critical_co_occurs: bool = False
    threat_intel_match: bool = False
    anti_forensic_clear: bool = False
    memory_corroboration: bool = False
    network_corroboration: bool = False
    anti_forensic_proximity: bool = False
    contradicting_cluster: bool = False


# ============================================================
# Engine
# ============================================================


class ConfidenceEngine:
    """Computes adaptive confidence scores for hypotheses.

    The engine determines applicability from the case profile, computes
    each factor's contribution from the hypothesis factors, and produces
    a deterministic score normalized against the applicable maximum.
    """

    def __init__(self, profile: CaseProfile):
        self.profile = profile

    def compute(self, factors: HypothesisFactors) -> ConfidenceBreakdown:
        """Run the full confidence computation."""

        applicable: dict[str, bool] = {}
        consulted: dict[str, bool] = {}
        contributions: dict[str, int] = {}

        # 1. Provenance tier (always applicable)
        applicable["provenance_tier"] = True
        prov_contrib = PROVENANCE_WEIGHTS.get(factors.provenance_tier, 0)
        if factors.provenance_tier != ProvenanceTier.NONE and prov_contrib > 0:
            consulted["provenance_tier"] = True
            contributions["provenance_tier"] = prov_contrib

        # 2. Causal lineage (always applicable)
        applicable["causal_lineage"] = True
        causal_contrib = CAUSAL_WEIGHTS.get(factors.causal_level, 0)
        if factors.causal_level != CausalLevel.UNSUPPORTED and causal_contrib > 0:
            consulted["causal_lineage"] = True
            contributions["causal_lineage"] = causal_contrib

        # 3. Cluster strength (applicable when a cluster sourced the hypothesis)
        if factors.cluster_strength is not None:
            applicable["cluster_strength"] = True
            cluster_contrib = CLUSTER_WEIGHTS.get(factors.cluster_strength, 0)
            if cluster_contrib > 0:
                consulted["cluster_strength"] = True
                contributions["cluster_strength"] = cluster_contrib

        # 4. Domain breadth (always applicable)
        applicable["domain_breadth"] = True
        if factors.domain_count >= 3:
            db_contrib = 20
        elif factors.domain_count == 2:
            db_contrib = 12
        elif factors.domain_count == 1:
            db_contrib = 5
        else:
            db_contrib = 0
        if db_contrib > 0:
            consulted["domain_breadth"] = True
            contributions["domain_breadth"] = db_contrib

        # 5. Cross-host corroboration (only if multi-host case)
        if self.profile.host_count > 1:
            applicable["cross_host_corroboration"] = True
            ch_contrib = min(factors.corroborating_hosts * 5, 10)
            if ch_contrib > 0:
                consulted["cross_host_corroboration"] = True
                contributions["cross_host_corroboration"] = ch_contrib

        # 6. Sigma co-occurrence (only if Sigma is in the artifact set)
        if "sigma" in self.profile.artifact_types_available:
            applicable["sigma_co_occurrence"] = True
            if factors.sigma_critical_co_occurs:
                consulted["sigma_co_occurrence"] = True
                contributions["sigma_co_occurrence"] = 10

        # 7. Threat intel match (only if intel sources configured)
        if self.profile.intel_sources_configured:
            applicable["threat_intel_match"] = True
            if factors.threat_intel_match:
                consulted["threat_intel_match"] = True
                contributions["threat_intel_match"] = 5

        # 8. Anti-forensic clear (only relevant if AF observed elsewhere)
        if self.profile.anti_forensic_observed:
            applicable["anti_forensic_clear"] = True
            if factors.anti_forensic_clear:
                consulted["anti_forensic_clear"] = True
                contributions["anti_forensic_clear"] = 5

        # 9. Memory corroboration (only if memory ingested)
        if self.profile.memory_available:
            applicable["memory_corroboration"] = True
            if factors.memory_corroboration:
                consulted["memory_corroboration"] = True
                contributions["memory_corroboration"] = 5

        # 10. Network corroboration (only if network artifacts ingested)
        if self.profile.network_available:
            applicable["network_corroboration"] = True
            if factors.network_corroboration:
                consulted["network_corroboration"] = True
                contributions["network_corroboration"] = 5

        # Compute normalized score
        applicable_total = sum(
            FACTOR_MAX_WEIGHTS[f] for f, is_app in applicable.items() if is_app
        )
        consulted_total = sum(contributions.values())

        if applicable_total == 0:
            raw_score = 0.0
        else:
            raw_score = (consulted_total / applicable_total) * 100

        # Apply penalties
        penalties = 0
        penalty_reasons: list[str] = []
        af_penalty = 0
        if factors.anti_forensic_proximity:
            af_penalty = abs(PENALTIES["anti_forensic_proximity"])
            penalties += PENALTIES["anti_forensic_proximity"]
            penalty_reasons.append(
                "Anti-forensic activity within 15 min of evidence"
            )
        if factors.contradicting_cluster:
            penalties += PENALTIES["contradicting_cluster"]
            penalty_reasons.append(
                "Contradicting cluster detected on same host/time"
            )

        score = max(0, min(100, int(round(raw_score + penalties))))
        tier = score_to_tier(score)

        rationale_parts = [
            f"Score {score}/100 (raw {raw_score:.1f} + penalties {penalties})"
        ]
        if penalty_reasons:
            rationale_parts.append("Penalties: " + "; ".join(penalty_reasons))
        if applicable_total:
            rationale_parts.append(
                f"Consulted {consulted_total}/{applicable_total} applicable points"
            )

        return ConfidenceBreakdown(
            score=score,
            tier=tier,
            applicable_factors=[f for f, v in applicable.items() if v],
            consulted_factors=[f for f, v in consulted.items() if v],
            factor_contributions=contributions,
            anti_forensic_penalty=af_penalty,
            cluster_strength_bonus=(
                CLUSTER_WEIGHTS.get(factors.cluster_strength, 0)
                if factors.cluster_strength is not None
                else 0
            ),
            rationale=" | ".join(rationale_parts),
        )


# ============================================================
# Public API
# ============================================================


def compute_adaptive_confidence(
    profile: CaseProfile, factors: HypothesisFactors
) -> ConfidenceBreakdown:
    """Compute adaptive confidence from a case profile and factor set."""
    return ConfidenceEngine(profile).compute(factors)


def compute_adaptive_confidence_from_db(
    case_id: str,
    db_conn: Any,
    *,
    provenance_tier: ProvenanceTier,
    causal_links: list[Any] | None,
    cluster_strength: ClusterStrength | None,
    evidence_domains: set[str] | None = None,
    cross_host_evidence: int = 0,
    sigma_hits: int = 0,
    threat_intel_hits: int = 0,
    memory_corroboration: bool = False,
    network_corroboration: bool = False,
    anti_forensic_clear: bool = False,
    anti_forensic_nearby: bool = False,
    contradicting_cluster: bool = False,
) -> ConfidenceBreakdown:
    """Convenience: build factors from individual values + DB-loaded profile.

    Used by ``hypothesis_lifecycle.record_hypothesis`` and any other
    callers that already have a database connection in hand.
    """
    profile = CaseProfile.from_db(db_conn, case_id)

    best_causal = CausalLevel.UNSUPPORTED
    if causal_links:
        best_causal = max(
            causal_links,
            key=lambda x: CAUSAL_WEIGHTS.get(getattr(x, "level", CausalLevel.UNSUPPORTED), 0),
        ).level

    factors = HypothesisFactors(
        provenance_tier=provenance_tier,
        causal_level=best_causal,
        cluster_strength=cluster_strength,
        domain_count=len(evidence_domains) if evidence_domains else 0,
        corroborating_hosts=cross_host_evidence,
        sigma_critical_co_occurs=sigma_hits > 0,
        threat_intel_match=threat_intel_hits > 0,
        anti_forensic_clear=anti_forensic_clear,
        memory_corroboration=memory_corroboration,
        network_corroboration=network_corroboration,
        anti_forensic_proximity=anti_forensic_nearby,
        contradicting_cluster=contradicting_cluster,
    )
    return compute_adaptive_confidence(profile, factors)
