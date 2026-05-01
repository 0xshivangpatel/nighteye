"""Adaptive Deterministic Confidence Engine.

Computes confidence scores for hypotheses based on case capabilities,
evidence quality, provenance, and anti-forensic penalties.

References:
  - docs/ARCHITECTURE.md § 11 (Layer 7: Validation and Confidence)
"""

from __future__ import annotations

import logging
from typing import Any

from nighteye.models import (
    ConfidenceBreakdown,
    ConfidenceTier,
    ProvenanceTier,
    CausalLevel,
    ClusterStrength,
)

__all__ = [
    "compute_adaptive_confidence",
    "ConfidenceEngine",
    "WEIGHTS",
    "PENALTIES",
]

logger = logging.getLogger("nighteye.confidence")

# ============================================================
# Weight Configuration
# ============================================================

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

PENALTIES: dict[str, int] = {
    "anti_forensic_proximity": -15,
    "contradicting_cluster": -20,
}

# Causal level weights
CAUSAL_WEIGHTS: dict[CausalLevel, int] = {
    CausalLevel.CHAIN: 15,
    CausalLevel.WRITE: 12,
    CausalLevel.NET: 10,
    CausalLevel.TIGHT_TIME: 6,
    CausalLevel.CO_OCCUR: 3,
    CausalLevel.TEMPORAL_ONLY: 1,
    CausalLevel.UNSUPPORTED: 0,
}

# Cluster strength weights
CLUSTER_WEIGHTS: dict[ClusterStrength, int] = {
    ClusterStrength.STRONG: 15,
    ClusterStrength.MODERATE: 10,
    ClusterStrength.WEAK: 4,
    ClusterStrength.NOISE: 0,
}

# Provenance weights
PROVENANCE_WEIGHTS: dict[ProvenanceTier, int] = {
    ProvenanceTier.MCP: 20,
    ProvenanceTier.HOOK: 15,
    ProvenanceTier.SHELL: 8,
    ProvenanceTier.NONE: 0,
}

# ============================================================
# Case Profiling
# ============================================================

class CaseProfile:
    """Profile of case capabilities at ingest completion."""

    def __init__(
        self,
        host_count: int = 1,
        artifact_types: set[str] | None = None,
        intel_sources: set[str] | None = None,
        anti_forensic_observed: bool = False,
        memory_available: bool = False,
        network_available: bool = False,
    ):
        self.host_count = host_count
        self.artifact_types = artifact_types or set()
        self.intel_sources = intel_sources or set()
        self.anti_forensic_observed = anti_forensic_observed
        self.memory_available = memory_available
        self.network_available = network_available

    @classmethod
    def from_db(cls, db_conn: Any, case_id: str) -> "CaseProfile":
        """Load case profile from database."""
        row = db_conn.execute(
            "SELECT * FROM case_capabilities WHERE case_id = ?", (case_id,)
        ).fetchone()

        if row:
            import json
            return cls(
                host_count=row["host_count"],
                artifact_types=set(json.loads(row["artifact_types"])),
                intel_sources=set(),  # Would load from config
                anti_forensic_observed=bool(row["anti_forensic_observed"]),
                memory_available=bool(row["has_memory"]),
                network_available=bool(row["has_network"]),
            )

        return cls()  # Default minimal profile


# ============================================================
# Confidence Engine
# ============================================================

class ConfidenceEngine:
    """Computes adaptive confidence scores for hypotheses."""

    def __init__(self, case_profile: CaseProfile):
        self.profile = case_profile

    def compute(
        self,
        provenance_tier: ProvenanceTier,
        causal_links: list[Any],
        cluster_strength: ClusterStrength,
        evidence_domains: set[str],
        cross_host_evidence: int,
        sigma_hits: int,
        threat_intel_hits: int,
        memory_corroboration: bool,
        network_corroboration: bool,
        anti_forensic_nearby: bool,
        contradicting_cluster: bool,
    ) -> ConfidenceBreakdown:
        """Compute confidence breakdown."""

        applicable: dict[str, bool] = {}
        consulted: dict[str, bool] = {}
        contributions: dict[str, int] = {}

        # 1. Provenance tier (always applicable)
        applicable["provenance_tier"] = True
        consulted["provenance_tier"] = provenance_tier != ProvenanceTier.NONE
        contributions["provenance_tier"] = PROVENANCE_WEIGHTS.get(provenance_tier, 0)

        # 2. Causal lineage (always applicable if claimed)
        applicable["causal_lineage"] = True
        best_causal = CausalLevel.UNSUPPORTED
        if causal_links:
            best_causal = max(causal_links, key=lambda x: CAUSAL_WEIGHTS.get(x.level, 0)).level
        consulted["causal_lineage"] = best_causal != CausalLevel.UNSUPPORTED
        contributions["causal_lineage"] = CAUSAL_WEIGHTS.get(best_causal, 0)

        # 3. Cluster strength (always applicable)
        applicable["cluster_strength"] = True
        consulted["cluster_strength"] = cluster_strength != ClusterStrength.NOISE
        contributions["cluster_strength"] = CLUSTER_WEIGHTS.get(cluster_strength, 0)

        # 4. Domain breadth (always applicable)
        applicable["domain_breadth"] = True
        domain_count = len(evidence_domains)
        consulted["domain_breadth"] = domain_count > 0
        if domain_count == 1:
            contributions["domain_breadth"] = 5
        elif domain_count == 2:
            contributions["domain_breadth"] = 12
        elif domain_count >= 3:
            contributions["domain_breadth"] = 20
        else:
            contributions["domain_breadth"] = 0

        # 5. Cross-host corroboration (conditional)
        applicable["cross_host_corroboration"] = self.profile.host_count > 1
        consulted["cross_host_corroboration"] = cross_host_evidence > 0
        contributions["cross_host_corroboration"] = min(cross_host_evidence * 5, 10)

        # 6. Sigma co-occurrence (conditional)
        applicable["sigma_co_occurrence"] = "sigma" in self.profile.artifact_types
        consulted["sigma_co_occurrence"] = sigma_hits > 0
        contributions["sigma_co_occurrence"] = 10 if sigma_hits > 0 else 0

        # 7. Threat intel match (conditional)
        applicable["threat_intel_match"] = len(self.profile.intel_sources) > 0
        consulted["threat_intel_match"] = threat_intel_hits > 0
        contributions["threat_intel_match"] = 5 if threat_intel_hits > 0 else 0

        # 8. Anti-forensic clear (conditional)
        applicable["anti_forensic_clear"] = self.profile.anti_forensic_observed
        consulted["anti_forensic_clear"] = not anti_forensic_nearby
        contributions["anti_forensic_clear"] = 5 if not anti_forensic_nearby else 0

        # 9. Memory corroboration (conditional)
        applicable["memory_corroboration"] = self.profile.memory_available
        consulted["memory_corroboration"] = memory_corroboration
        contributions["memory_corroboration"] = 5 if memory_corroboration else 0

        # 10. Network corroboration (conditional)
        applicable["network_corroboration"] = self.profile.network_available
        consulted["network_corroboration"] = network_corroboration
        contributions["network_corroboration"] = 5 if network_corroboration else 0

        # Compute raw score
        applicable_total = sum(
            WEIGHTS[f] for f, is_app in applicable.items() if is_app
        )
        consulted_total = sum(
            contributions[f] for f, is_con in consulted.items() if is_con
        )

        if applicable_total == 0:
            raw_score = 0
        else:
            raw_score = (consulted_total / applicable_total) * 100

        # Apply penalties
        penalties = 0
        penalty_reasons: list[str] = []

        if anti_forensic_nearby:
            penalties += PENALTIES["anti_forensic_proximity"]
            penalty_reasons.append("Anti-forensic activity within 15min of evidence")

        if contradicting_cluster:
            penalties += PENALTIES["contradicting_cluster"]
            penalty_reasons.append("Contradicting cluster detected on same host/time")

        score = max(0, min(100, int(raw_score + penalties)))

        # Determine tier
        if score >= 76:
            tier = ConfidenceTier.HIGH
        elif score >= 51:
            tier = ConfidenceTier.MEDIUM
        elif score >= 31:
            tier = ConfidenceTier.LOW
        else:
            tier = ConfidenceTier.SPECULATIVE

        # Build rationale
        rationale_parts = []
        rationale_parts.append(f"Score {score}/100 (raw {raw_score:.1f} + penalties {penalties})")
        if penalty_reasons:
            rationale_parts.append(f"Penalties: {', '.join(penalty_reasons)}")

        return ConfidenceBreakdown(
            score=score,
            tier=tier,
            applicable_factors=[f for f, v in applicable.items() if v],
            consulted_factors=[f for f, v in consulted.items() if v],
            factor_contributions=contributions,
            anti_forensic_penalty=abs(PENALTIES["anti_forensic_proximity"]) if anti_forensic_nearby else 0,
            cluster_strength_bonus=CLUSTER_WEIGHTS.get(cluster_strength, 0),
            rationale="; ".join(rationale_parts),
        )


# ============================================================
# Convenience Function
# ============================================================

def compute_adaptive_confidence(
    case_id: str,
    db_conn: Any,
    provenance_tier: ProvenanceTier,
    causal_links: list[Any],
    cluster_strength: ClusterStrength,
    evidence_domains: set[str],
    cross_host_evidence: int = 0,
    sigma_hits: int = 0,
    threat_intel_hits: int = 0,
    memory_corroboration: bool = False,
    network_corroboration: bool = False,
    anti_forensic_nearby: bool = False,
    contradicting_cluster: bool = False,
) -> ConfidenceBreakdown:
    """Compute confidence with automatic case profile loading."""
    profile = CaseProfile.from_db(db_conn, case_id)
    engine = ConfidenceEngine(profile)
    return engine.compute(
        provenance_tier=provenance_tier,
        causal_links=causal_links,
        cluster_strength=cluster_strength,
        evidence_domains=evidence_domains,
        cross_host_evidence=cross_host_evidence,
        sigma_hits=sigma_hits,
        threat_intel_hits=threat_intel_hits,
        memory_corroboration=memory_corroboration,
        network_corroboration=network_corroboration,
        anti_forensic_nearby=anti_forensic_nearby,
        contradicting_cluster=contradicting_cluster,
    )
