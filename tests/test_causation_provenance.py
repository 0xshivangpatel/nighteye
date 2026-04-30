"""Tests for causation ladder and provenance derivation (D3)."""

from __future__ import annotations

import pytest

from nighteye.causation import (
    CAUSAL_WEIGHTS,
    STRONG_CAUSAL_LEVELS,
    causal_weight,
    claims_causation,
    is_strong_causal,
)
from nighteye.models import CausalLevel
from nighteye.provenance import (
    PROVENANCE_WEIGHTS,
    derive_provenance,
    provenance_weight,
)
from nighteye.models import ProvenanceTier


# ============================================================
# Causation weights
# ============================================================


class TestCausalWeights:

    def test_chain_is_max(self) -> None:
        assert causal_weight(CausalLevel.CHAIN) == 15

    def test_write_weight(self) -> None:
        assert causal_weight(CausalLevel.WRITE) == 12

    def test_net_weight(self) -> None:
        assert causal_weight(CausalLevel.NET) == 10

    def test_tight_time_weight(self) -> None:
        assert causal_weight(CausalLevel.TIGHT_TIME) == 6

    def test_co_occur_weight(self) -> None:
        assert causal_weight(CausalLevel.CO_OCCUR) == 3

    def test_temporal_only_weight(self) -> None:
        assert causal_weight(CausalLevel.TEMPORAL_ONLY) == 1

    def test_unsupported_is_zero(self) -> None:
        assert causal_weight(CausalLevel.UNSUPPORTED) == 0

    def test_all_levels_have_weights(self) -> None:
        for level in CausalLevel:
            assert level in CAUSAL_WEIGHTS


# ============================================================
# Strong causal check
# ============================================================


class TestStrongCausal:

    def test_chain_is_strong(self) -> None:
        assert is_strong_causal(CausalLevel.CHAIN)

    def test_write_is_strong(self) -> None:
        assert is_strong_causal(CausalLevel.WRITE)

    def test_net_is_strong(self) -> None:
        assert is_strong_causal(CausalLevel.NET)

    def test_tight_time_not_strong(self) -> None:
        assert not is_strong_causal(CausalLevel.TIGHT_TIME)

    def test_co_occur_not_strong(self) -> None:
        assert not is_strong_causal(CausalLevel.CO_OCCUR)

    def test_temporal_only_not_strong(self) -> None:
        assert not is_strong_causal(CausalLevel.TEMPORAL_ONLY)

    def test_unsupported_not_strong(self) -> None:
        assert not is_strong_causal(CausalLevel.UNSUPPORTED)

    def test_strong_set_has_3_members(self) -> None:
        assert len(STRONG_CAUSAL_LEVELS) == 3


# ============================================================
# Causation language detection
# ============================================================


class TestClaimsCausation:

    def test_detects_caused(self) -> None:
        assert claims_causation("The malware caused a crash")

    def test_detects_led_to(self) -> None:
        assert claims_causation("This activity led to lateral movement")

    def test_detects_spawned(self) -> None:
        assert claims_causation("services.exe spawned cmd.exe")

    def test_detects_pivoted(self) -> None:
        assert claims_causation("Attacker pivoted to DC01")

    def test_detects_dropped_by(self) -> None:
        assert claims_causation("Binary dropped by initial access vector")

    def test_detects_which_then(self) -> None:
        assert claims_causation("PsExec installed a service, which then executed")

    def test_case_insensitive(self) -> None:
        assert claims_causation("The actor CAUSED damage via encryption")

    def test_no_causation_neutral_text(self) -> None:
        assert not claims_causation(
            "Network logon observed from WKSTN-01 at 14:23 UTC"
        )

    def test_no_causation_correlation_only(self) -> None:
        assert not claims_causation(
            "Service install observed on same host within time window"
        )

    def test_empty_string(self) -> None:
        assert not claims_causation("")


# ============================================================
# Provenance weights
# ============================================================


class TestProvenanceWeights:

    def test_mcp_is_max(self) -> None:
        assert provenance_weight(ProvenanceTier.MCP) == 20

    def test_hook_weight(self) -> None:
        assert provenance_weight(ProvenanceTier.HOOK) == 15

    def test_shell_weight(self) -> None:
        assert provenance_weight(ProvenanceTier.SHELL) == 8

    def test_none_is_zero(self) -> None:
        assert provenance_weight(ProvenanceTier.NONE) == 0

    def test_all_tiers_have_weights(self) -> None:
        for tier in ProvenanceTier:
            assert tier in PROVENANCE_WEIGHTS


# ============================================================
# Provenance derivation
# ============================================================


class TestDeriveProvenance:

    def test_empty_list_is_none(self) -> None:
        assert derive_provenance([]) == ProvenanceTier.NONE

    def test_all_mcp_ids(self) -> None:
        ids = ["nighteye-alice-20260429-001", "nighteye-alice-20260429-002"]
        assert derive_provenance(ids) == ProvenanceTier.MCP

    def test_all_hook_ids(self) -> None:
        ids = ["hook-hayabusa-001", "ingest-evtx-002"]
        assert derive_provenance(ids) == ProvenanceTier.HOOK

    def test_all_shell_ids(self) -> None:
        ids = ["shell-manual-001", "cli-run-002"]
        assert derive_provenance(ids) == ProvenanceTier.SHELL

    def test_mixed_mcp_and_hook_weakens_to_hook(self) -> None:
        ids = ["nighteye-alice-20260429-001", "hook-hayabusa-002"]
        assert derive_provenance(ids) == ProvenanceTier.HOOK

    def test_mixed_mcp_and_shell_weakens_to_shell(self) -> None:
        ids = ["nighteye-alice-20260429-001", "shell-cmd-001"]
        assert derive_provenance(ids) == ProvenanceTier.SHELL

    def test_any_unrecognized_weakens_to_none(self) -> None:
        ids = ["nighteye-alice-20260429-001", "unknown-origin-001"]
        assert derive_provenance(ids) == ProvenanceTier.NONE

    def test_single_mcp_id(self) -> None:
        assert derive_provenance(["nighteye-alice-20260429-001"]) == ProvenanceTier.MCP

    def test_empty_string_id_is_none(self) -> None:
        assert derive_provenance([""]) == ProvenanceTier.NONE

    def test_constructor_prefix_is_hook(self) -> None:
        assert derive_provenance(["constructor-lm-001"]) == ProvenanceTier.HOOK

    def test_manual_prefix_is_shell(self) -> None:
        assert derive_provenance(["manual-vol3-001"]) == ProvenanceTier.SHELL
