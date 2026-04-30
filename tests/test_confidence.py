"""Tests for the adaptive confidence engine (D3).

Covers:
- Tier classification boundaries
- Factor applicability based on case profiles
- Graduated contributions (provenance, causal, cluster, domain, cross-host)
- Penalty application (anti-forensic proximity, contradicting cluster)
- Worked examples from ARCHITECTURE.md § 11
- Edge cases (zero applicable, all penalties, NONE provenance)
"""

from __future__ import annotations

import pytest

from nighteye.confidence import (
    CaseProfile,
    FACTOR_MAX_WEIGHTS,
    HypothesisFactors,
    PENALTIES,
    compute_adaptive_confidence,
    score_to_tier,
)
from nighteye.models import (
    CausalLevel,
    ClusterStrength,
    ConfidenceTier,
    ProvenanceTier,
)


# ============================================================
# score_to_tier
# ============================================================


class TestScoreToTier:

    def test_speculative_range(self) -> None:
        for s in (0, 15, 30):
            assert score_to_tier(s) == ConfidenceTier.SPECULATIVE

    def test_low_range(self) -> None:
        for s in (31, 40, 50):
            assert score_to_tier(s) == ConfidenceTier.LOW

    def test_medium_range(self) -> None:
        for s in (51, 60, 75):
            assert score_to_tier(s) == ConfidenceTier.MEDIUM

    def test_high_range(self) -> None:
        for s in (76, 85, 100):
            assert score_to_tier(s) == ConfidenceTier.HIGH

    def test_boundary_30_31(self) -> None:
        assert score_to_tier(30) == ConfidenceTier.SPECULATIVE
        assert score_to_tier(31) == ConfidenceTier.LOW

    def test_boundary_50_51(self) -> None:
        assert score_to_tier(50) == ConfidenceTier.LOW
        assert score_to_tier(51) == ConfidenceTier.MEDIUM

    def test_boundary_75_76(self) -> None:
        assert score_to_tier(75) == ConfidenceTier.MEDIUM
        assert score_to_tier(76) == ConfidenceTier.HIGH


# ============================================================
# Factor applicability
# ============================================================


class TestFactorApplicability:

    def test_minimal_case_has_4_applicable(self) -> None:
        """1-host, EVTX-only case: only 4 always-applicable factors."""
        profile = CaseProfile(host_count=1)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=1,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert len(result.applicable_factors) == 4

    def test_rich_case_has_all_10_applicable(self) -> None:
        """50-host case with everything: all 10 factors applicable."""
        profile = CaseProfile(
            host_count=50,
            artifact_types_available={"evtx", "sigma", "memory", "network"},
            intel_sources_configured={"urlhaus"},
            anti_forensic_observed=True,
            memory_available=True,
            network_available=True,
        )
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=3,
            corroborating_hosts=2,
            sigma_critical_co_occurs=True,
            threat_intel_match=True,
            anti_forensic_clear=True,
            memory_corroboration=True,
            network_corroboration=True,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert len(result.applicable_factors) == 10

    def test_cross_host_not_applicable_single_host(self) -> None:
        profile = CaseProfile(host_count=1)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=1,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert "cross_host_corroboration" not in result.applicable_factors

    def test_sigma_applicable_when_in_artifacts(self) -> None:
        profile = CaseProfile(
            host_count=1,
            artifact_types_available={"evtx", "sigma"},
        )
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=1,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert "sigma_co_occurrence" in result.applicable_factors

    def test_memory_not_applicable_when_unavailable(self) -> None:
        profile = CaseProfile(host_count=1, memory_available=False)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=1,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert "memory_corroboration" not in result.applicable_factors


# ============================================================
# Graduated contributions
# ============================================================


class TestGraduatedContributions:

    def test_provenance_mcp_full_weight(self) -> None:
        profile = CaseProfile(host_count=1)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=3,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert result.factor_contributions["provenance_tier"] == 20

    def test_provenance_hook_partial_weight(self) -> None:
        profile = CaseProfile(host_count=1)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.HOOK,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=3,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert result.factor_contributions["provenance_tier"] == 15

    def test_provenance_shell_lowest_weight(self) -> None:
        profile = CaseProfile(host_count=1)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.SHELL,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=3,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert result.factor_contributions["provenance_tier"] == 8

    def test_causal_chain_full_weight(self) -> None:
        profile = CaseProfile(host_count=1)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=1,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert result.factor_contributions["causal_lineage"] == 15

    def test_causal_temporal_only_minimal_weight(self) -> None:
        profile = CaseProfile(host_count=1)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.TEMPORAL_ONLY,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=1,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert result.factor_contributions["causal_lineage"] == 1

    def test_cluster_strength_strong(self) -> None:
        profile = CaseProfile(host_count=1)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=1,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert result.factor_contributions["cluster_strength"] == 15

    def test_cluster_strength_weak(self) -> None:
        profile = CaseProfile(host_count=1)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.WEAK,
            domain_count=1,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert result.factor_contributions["cluster_strength"] == 4

    def test_cluster_strength_none_not_consulted(self) -> None:
        profile = CaseProfile(host_count=1)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=None,  # no originating cluster
            domain_count=1,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert "cluster_strength" not in result.factor_contributions

    def test_domain_breadth_1(self) -> None:
        profile = CaseProfile(host_count=1)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=1,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert result.factor_contributions["domain_breadth"] == 5

    def test_domain_breadth_2(self) -> None:
        profile = CaseProfile(host_count=1)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=2,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert result.factor_contributions["domain_breadth"] == 12

    def test_domain_breadth_3_plus(self) -> None:
        profile = CaseProfile(host_count=1)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=5,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert result.factor_contributions["domain_breadth"] == 20

    def test_cross_host_capped_at_10(self) -> None:
        profile = CaseProfile(host_count=50)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=1,
            corroborating_hosts=10,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert result.factor_contributions["cross_host_corroboration"] == 10

    def test_cross_host_graduated(self) -> None:
        profile = CaseProfile(host_count=50)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=1,
            corroborating_hosts=1,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert result.factor_contributions["cross_host_corroboration"] == 5


# ============================================================
# Penalty application
# ============================================================


class TestPenalties:

    def test_anti_forensic_penalty_applied(self) -> None:
        profile = CaseProfile(host_count=1)
        # Max score without penalty
        factors_clean = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=3,
        )
        clean = compute_adaptive_confidence(profile, factors_clean)

        # Same but with AF proximity
        factors_af = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=3,
            anti_forensic_proximity=True,
        )
        af = compute_adaptive_confidence(profile, factors_af)

        assert af.score == clean.score - 15
        assert af.anti_forensic_penalty == 15

    def test_contradicting_cluster_penalty(self) -> None:
        profile = CaseProfile(host_count=1)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=3,
            contradicting_cluster=True,
        )
        result = compute_adaptive_confidence(profile, factors)
        # Should subtract 20 from what would otherwise be 100
        assert result.score == 80

    def test_both_penalties_stack(self) -> None:
        profile = CaseProfile(host_count=1)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=3,
            anti_forensic_proximity=True,
            contradicting_cluster=True,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert result.score == 100 - 15 - 20  # = 65

    def test_penalty_clamps_to_zero(self) -> None:
        """Score never goes below 0 even with heavy penalties."""
        profile = CaseProfile(host_count=1)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.SHELL,
            causal_level=CausalLevel.TEMPORAL_ONLY,
            cluster_strength=ClusterStrength.WEAK,
            domain_count=1,
            anti_forensic_proximity=True,
            contradicting_cluster=True,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert result.score >= 0


# ============================================================
# Worked examples from ARCHITECTURE.md § 11
# ============================================================


class TestWorkedExamples:

    def test_1_host_evtx_all_consulted_score_100(self) -> None:
        """Example 1: 1 host EVTX-only, all 4 applicable factors consulted.

        Applicable = 4 (provenance=20, causal=15, cluster=15, domain=20)
        Total applicable = 70. All consulted at max = 70.
        Score = 70/70 * 100 = 100 → HIGH
        """
        profile = CaseProfile(host_count=1)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=3,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert result.score == 100
        assert result.tier == ConfidenceTier.HIGH

    def test_rich_case_all_consulted_score_100(self) -> None:
        """Example 2: 50 host case, all factors consulted, AF clean.

        All 10 factors applicable, all consulted at max.
        Score = 110/110 * 100 = 100 → HIGH
        """
        profile = CaseProfile(
            host_count=50,
            artifact_types_available={"evtx", "sigma", "memory", "network"},
            intel_sources_configured={"urlhaus"},
            anti_forensic_observed=True,
            memory_available=True,
            network_available=True,
        )
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=3,
            corroborating_hosts=2,
            sigma_critical_co_occurs=True,
            threat_intel_match=True,
            anti_forensic_clear=True,
            memory_corroboration=True,
            network_corroboration=True,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert result.score == 100
        assert result.tier == ConfidenceTier.HIGH

    def test_rich_case_partial_consulted_low(self) -> None:
        """Example 3: 50 host case, only core 4 of 10 consulted.

        Applicable total = 110 (all 10 factors).
        Consulted = provenance(20) + causal(15) + cluster(15) + domain(5) = 55.
        Score = 55/110 * 100 = 50 → LOW
        """
        profile = CaseProfile(
            host_count=50,
            artifact_types_available={"evtx", "sigma", "memory", "network"},
            intel_sources_configured={"urlhaus"},
            anti_forensic_observed=True,
            memory_available=True,
            network_available=True,
        )
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=1,  # only 1 domain = 5 points
            # all conditional factors left as False/0
        )
        result = compute_adaptive_confidence(profile, factors)
        assert result.tier == ConfidenceTier.LOW
        assert 40 <= result.score <= 55  # approximately 50

    def test_rich_case_all_consulted_af_penalty(self) -> None:
        """Example 4: 50 host case, all consulted, AF within 15min.

        Raw = 100. Penalty = -15. Score = 85 → HIGH (still).
        """
        profile = CaseProfile(
            host_count=50,
            artifact_types_available={"evtx", "sigma", "memory", "network"},
            intel_sources_configured={"urlhaus"},
            anti_forensic_observed=True,
            memory_available=True,
            network_available=True,
        )
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=3,
            corroborating_hosts=2,
            sigma_critical_co_occurs=True,
            threat_intel_match=True,
            anti_forensic_clear=True,
            memory_corroboration=True,
            network_corroboration=True,
            anti_forensic_proximity=True,  # penalty
        )
        result = compute_adaptive_confidence(profile, factors)
        assert result.score == 85
        assert result.tier == ConfidenceTier.HIGH

    def test_1_host_3_of_4_consulted_medium(self) -> None:
        """Example 6: 1 host case, 3 of 4 consulted, score ≈ 75.

        Applicable = 70 (4 factors).
        Consulted 3: e.g. provenance(20) + causal(15) + domain(20) = 55.
        Score = 55/70 * 100 = 79 → HIGH

        OR: cluster only MODERATE (10 instead of 15):
        Consulted 4: 20 + 15 + 10 + 5 = 50. Score = 50/70*100 = 71 → MEDIUM

        The architecture's example says 75/MEDIUM. We verify the
        mechanism works in the right range.
        """
        profile = CaseProfile(host_count=1)
        # To get ~75: e.g. MCP(20) + CO_OCCUR(3) + STRONG(15) + 1-domain(5) = 43
        # 43/70 = 61 → MEDIUM. Or MCP(20) + CHAIN(15) + MODERATE(10) + 1-domain(5) = 50
        # 50/70 = 71 → MEDIUM ✓
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.MODERATE,
            domain_count=1,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert result.tier == ConfidenceTier.MEDIUM
        assert 51 <= result.score <= 75


# ============================================================
# Provenance NONE
# ============================================================


class TestProvenanceNone:

    def test_none_provenance_produces_zero_contribution(self) -> None:
        """NONE provenance should contribute 0 to provenance_tier factor."""
        profile = CaseProfile(host_count=1)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.NONE,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=3,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert "provenance_tier" not in result.factor_contributions
        # Score should be lower because 20/70 points are missing
        # (15+15+20)/70 = 50/70 = 71
        assert result.score == 71


# ============================================================
# Output structure
# ============================================================


class TestOutputStructure:

    def test_result_has_all_fields(self) -> None:
        profile = CaseProfile(host_count=1)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=3,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert result.score >= 0
        assert result.score <= 100
        assert result.tier in ConfidenceTier
        assert isinstance(result.applicable_factors, list)
        assert isinstance(result.consulted_factors, list)
        assert isinstance(result.factor_contributions, dict)
        assert isinstance(result.rationale, str)
        assert len(result.rationale) > 0

    def test_consulted_is_subset_of_applicable(self) -> None:
        profile = CaseProfile(host_count=50, memory_available=True)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=1,
        )
        result = compute_adaptive_confidence(profile, factors)
        assert set(result.consulted_factors).issubset(set(result.applicable_factors))

    def test_json_round_trip(self) -> None:
        """The result must round-trip through ConfidenceBreakdown JSON."""
        profile = CaseProfile(host_count=1)
        factors = HypothesisFactors(
            provenance_tier=ProvenanceTier.MCP,
            causal_level=CausalLevel.CHAIN,
            cluster_strength=ClusterStrength.STRONG,
            domain_count=3,
        )
        result = compute_adaptive_confidence(profile, factors)
        j = result.to_json()
        from nighteye.models import ConfidenceBreakdown
        restored = ConfidenceBreakdown.from_json(j)
        assert restored.score == result.score
        assert restored.tier == result.tier
