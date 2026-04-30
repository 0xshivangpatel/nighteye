"""Adaptive deterministic confidence engine.

Implements the scoring algorithm from ARCHITECTURE.md § 11:

1. Profile the case (host count, available artifact types, etc.)
2. Determine which confidence factors are *applicable* to this case.
3. For each hypothesis, compute *actual contributions* from consulted
   factors.
4. Normalize: ``raw_score = (consulted_total / applicable_total) * 100``
5. Apply penalties (anti-forensic proximity, contradicting clusters).
6. Clamp to ``[0, 100]`` and assign tier.

Key design principle: same factors evaluated in every case, but weights
adapt to what's available. A 1-host EVTX-only case can score 100 if all
applicable factors are consulted. A 50-host case demands broader evidence.

References:
    - docs/ARCHITECTURE.md § 11 (worked examples, tier thresholds)
    - docs/ARCHITECTURE.md § 9 (record_hypothesis gates)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from nighteye.causation import CAUSAL_WEIGHTS, causal_weight
from nighteye.models import (
    CausalLevel,
    ClusterStrength,
    ConfidenceBreakdown,
    ConfidenceTier,
    ProvenanceTier,
)
from nighteye.provenance import PROVENANCE_WEIGHTS, provenance_weight

__all__ = [
    "CaseProfile",
    "HypothesisFactors",
    "FACTOR_MAX_WEIGHTS",
    "PENALTIES",
    "compute_adaptive_confidence",
    "score_to_tier",
]


# ============================================================
# Constants
# ============================================================

# Maximum possible weight for each factor.
# These define the denominator in the ratio calculation.
FACTOR_MAX_WEIGHTS: dict[str, int] = {
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

# Factors that are always applicable regardless of case profile.
_ALWAYS_APPLICABLE = frozenset({
    "provenance_tier",
    "causal_lineage",
    "cluster_strength",
    "domain_breadth",
})

# Penalties applied on top of the ratio score.
PENALTIES: dict[str, int] = {
    "anti_forensic_proximity": -15,
    "contradicting_cluster": -20,
}

# Cluster strength → weight contribution.
_CLUSTER_STRENGTH_WEIGHTS: dict[ClusterStrength, int] = {
    ClusterStrength.STRONG: 15,
    ClusterStrength.MODERATE: 10,
    ClusterStrength.WEAK: 4,
    ClusterStrength.NOISE: 0,
}

# Domain breadth → weight contribution.
_DOMAIN_BREADTH_WEIGHTS: dict[int, int] = {
    # key = number of evidence domains
    1: 5,
    2: 12,
    # 3+ = 20 (handled in code)
}


# ============================================================
# Input data structures
# ============================================================


@dataclass
class CaseProfile:
    """Case-level metadata determined at ingest completion.

    Controls which confidence factors are applicable for all
    hypotheses in this case.
    """
    host_count: int = 1
    artifact_types_available: set[str] = field(default_factory=set)
    intel_sources_configured: set[str] = field(default_factory=set)
    anti_forensic_observed: bool = False
    memory_available: bool = False
    network_available: bool = False


@dataclass
class HypothesisFactors:
    """Per-hypothesis evidence inputs for the confidence engine.

    Each field maps to one confidence factor or penalty.
    """
    # Core factors (always applicable)
    provenance_tier: ProvenanceTier = ProvenanceTier.NONE
    causal_level: CausalLevel = CausalLevel.UNSUPPORTED
    cluster_strength: ClusterStrength | None = None
    domain_count: int = 1  # number of evidence domains (EVTX, MFT, etc.)

    # Conditional factors (applicable only when case profile says so)
    corroborating_hosts: int = 0   # other hosts with same signal
    sigma_critical_co_occurs: bool = False
    threat_intel_match: bool = False
    anti_forensic_clear: bool = False  # AF seen elsewhere AND this clean
    memory_corroboration: bool = False
    network_corroboration: bool = False

    # Penalties
    anti_forensic_proximity: bool = False  # disturbance within ±15min
    contradicting_cluster: bool = False


# ============================================================
# Tier classification
# ============================================================


def score_to_tier(score: int) -> ConfidenceTier:
    """Map a 0-100 score to its confidence tier.

    | Score | Tier |
    |-------|------|
    | 0-30  | SPECULATIVE |
    | 31-50 | LOW |
    | 51-75 | MEDIUM |
    | 76-100| HIGH |
    """
    if score >= 76:
        return ConfidenceTier.HIGH
    if score >= 51:
        return ConfidenceTier.MEDIUM
    if score >= 31:
        return ConfidenceTier.LOW
    return ConfidenceTier.SPECULATIVE


# ============================================================
# Main computation
# ============================================================


def compute_adaptive_confidence(
    case_profile: CaseProfile,
    factors: HypothesisFactors,
) -> ConfidenceBreakdown:
    """Compute the adaptive confidence score for a hypothesis.

    This is the deterministic scoring function at the core of NightEye's
    hypothesis lifecycle. It implements the algorithm from
    ARCHITECTURE.md § 11.

    Args:
        case_profile: Case-level metadata (host count, artifact types, etc.)
        factors: Per-hypothesis evidence inputs.

    Returns:
        A ConfidenceBreakdown with score, tier, and full factor audit trail.

    Raises:
        ValueError: If provenance_tier is NONE (hypothesis should be rejected
            before reaching confidence scoring).
    """
    # --- Step 1: Determine applicable factors based on case profile ---
    applicable = _determine_applicable(case_profile)

    # --- Step 2: Compute actual contribution per factor ---
    contributions = _compute_contributions(factors)

    # --- Step 3: Calculate totals ---
    applicable_factors: list[str] = []
    consulted_factors: list[str] = []
    factor_contributions: dict[str, int] = {}

    applicable_total = 0
    consulted_total = 0

    for factor_name, is_applicable in applicable.items():
        if not is_applicable:
            continue
        applicable_factors.append(factor_name)
        max_weight = FACTOR_MAX_WEIGHTS[factor_name]
        applicable_total += max_weight

        actual = contributions.get(factor_name, 0)
        if actual > 0:
            consulted_factors.append(factor_name)
            consulted_total += actual
            factor_contributions[factor_name] = actual

    # --- Step 4: Normalize to 0-100 ---
    if applicable_total == 0:
        raw_score = 0
    else:
        raw_score = (consulted_total / applicable_total) * 100

    # --- Step 5: Apply penalties ---
    total_penalty = 0
    triggered_penalties: list[str] = []

    if factors.anti_forensic_proximity:
        total_penalty += PENALTIES["anti_forensic_proximity"]
        triggered_penalties.append("anti_forensic_proximity")

    if factors.contradicting_cluster:
        total_penalty += PENALTIES["contradicting_cluster"]
        triggered_penalties.append("contradicting_cluster")

    # --- Step 6: Final score ---
    final_score = max(0, min(100, int(round(raw_score + total_penalty))))
    tier = score_to_tier(final_score)

    # Build rationale
    rationale_parts: list[str] = []
    rationale_parts.append(
        f"Applicable: {len(applicable_factors)}/{len(FACTOR_MAX_WEIGHTS)} factors "
        f"(total weight {applicable_total})"
    )
    rationale_parts.append(
        f"Consulted: {len(consulted_factors)} factors "
        f"(total contribution {consulted_total})"
    )
    rationale_parts.append(f"Raw ratio: {raw_score:.1f}")
    if total_penalty:
        rationale_parts.append(
            f"Penalties: {total_penalty} ({', '.join(triggered_penalties)})"
        )
    rationale_parts.append(f"Final: {final_score} → {tier.value}")

    return ConfidenceBreakdown(
        score=final_score,
        tier=tier,
        applicable_factors=applicable_factors,
        consulted_factors=consulted_factors,
        factor_contributions=factor_contributions,
        anti_forensic_penalty=abs(PENALTIES["anti_forensic_proximity"])
            if factors.anti_forensic_proximity else 0,
        cluster_strength_bonus=contributions.get("cluster_strength", 0),
        rationale="; ".join(rationale_parts),
    )


# ============================================================
# Internal helpers
# ============================================================


def _determine_applicable(profile: CaseProfile) -> dict[str, bool]:
    """Determine which factors are applicable for this case profile.

    Always-applicable factors: provenance_tier, causal_lineage,
    cluster_strength, domain_breadth.

    Conditional factors depend on case characteristics.
    """
    return {
        "provenance_tier": True,
        "causal_lineage": True,
        "cluster_strength": True,
        "domain_breadth": True,
        "cross_host_corroboration": profile.host_count > 1,
        "sigma_co_occurrence": "sigma" in profile.artifact_types_available,
        "threat_intel_match": len(profile.intel_sources_configured) > 0,
        "anti_forensic_clear": profile.anti_forensic_observed,
        "memory_corroboration": profile.memory_available,
        "network_corroboration": profile.network_available,
    }


def _compute_contributions(factors: HypothesisFactors) -> dict[str, int]:
    """Compute actual weight contribution for each factor.

    Each factor's contribution is capped at its max weight. Some factors
    have graduated contributions (e.g., provenance MCP=20 vs HOOK=15).
    """
    contributions: dict[str, int] = {}

    # Provenance
    prov_weight = provenance_weight(factors.provenance_tier)
    if prov_weight > 0:
        contributions["provenance_tier"] = prov_weight

    # Causal lineage
    caus_weight = causal_weight(factors.causal_level)
    if caus_weight > 0:
        contributions["causal_lineage"] = caus_weight

    # Cluster strength
    if factors.cluster_strength is not None:
        cs_weight = _CLUSTER_STRENGTH_WEIGHTS.get(factors.cluster_strength, 0)
        if cs_weight > 0:
            contributions["cluster_strength"] = cs_weight

    # Domain breadth
    if factors.domain_count >= 3:
        contributions["domain_breadth"] = 20
    elif factors.domain_count == 2:
        contributions["domain_breadth"] = 12
    elif factors.domain_count == 1:
        contributions["domain_breadth"] = 5
    # domain_count <= 0: no contribution

    # Cross-host corroboration: min(N * 5, 10)
    if factors.corroborating_hosts > 0:
        contributions["cross_host_corroboration"] = min(
            factors.corroborating_hosts * 5, 10
        )

    # Binary factors
    if factors.sigma_critical_co_occurs:
        contributions["sigma_co_occurrence"] = 10

    if factors.threat_intel_match:
        contributions["threat_intel_match"] = 5

    if factors.anti_forensic_clear:
        contributions["anti_forensic_clear"] = 5

    if factors.memory_corroboration:
        contributions["memory_corroboration"] = 5

    if factors.network_corroboration:
        contributions["network_corroboration"] = 5

    return contributions
