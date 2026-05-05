"""Provenance tier derivation.

Every hypothesis must trace its evidence back through audit IDs to tool
invocations. The provenance tier reflects how the evidence was gathered:

- **MCP**: evidence obtained via MCP tool calls (highest trust)
- **HOOK**: evidence from subprocess hooks (e.g. Hayabusa auto-run)
- **SHELL**: evidence from manual shell commands
- **NONE**: no audit trail — hypothesis is rejected at the gate

The confidence engine uses provenance tier as its highest-weighted factor
(20 points max). ProvenanceTier.NONE causes outright rejection before
scoring even begins.

References:
    - docs/ARCHITECTURE.md § 9 (record_hypothesis gate 1)
    - docs/ARCHITECTURE.md § 11 (WEIGHTS: provenance_tier)
"""

from __future__ import annotations

from nighteye.models import ProvenanceTier

__all__ = [
    "PROVENANCE_WEIGHTS",
    "derive_provenance",
    "provenance_weight",
]


# ============================================================
# Weight map — used by confidence engine
# ============================================================

PROVENANCE_WEIGHTS: dict[ProvenanceTier, int] = {
    ProvenanceTier.MCP: 20,
    ProvenanceTier.HOOK: 15,
    ProvenanceTier.SHELL: 8,
    ProvenanceTier.NONE: 0,  # rejected before scoring
}


# ============================================================
# Provenance derivation
# ============================================================

# Prefixes used to classify audit IDs by their origin.
_MCP_PREFIX = "nighteye-"
_HOOK_PREFIXES = ("hook-", "ingest-", "constructor-", "auto-seed-")
_SHELL_PREFIXES = ("shell-", "manual-", "cli-")


def derive_provenance(audit_ids: list[str]) -> ProvenanceTier:
    """Derive the provenance tier from a list of audit trail IDs.

    The tier is determined by the *weakest* link in the chain:
    if all audit IDs are MCP-origin, provenance is MCP. If any
    are HOOK-origin, provenance drops to HOOK. If any are SHELL,
    provenance drops to SHELL. If any are missing or unrecognized,
    provenance is NONE.

    Args:
        audit_ids: List of audit trail identifiers from evidence refs.

    Returns:
        The derived ProvenanceTier (weakest link).
    """
    if not audit_ids:
        return ProvenanceTier.NONE

    tiers: list[ProvenanceTier] = []
    for aid in audit_ids:
        tier = _classify_audit_id(aid)
        tiers.append(tier)

    # Weakest link determines overall provenance
    # Priority order: NONE (worst) > SHELL > HOOK > MCP (best)
    if ProvenanceTier.NONE in tiers:
        return ProvenanceTier.NONE
    if ProvenanceTier.SHELL in tiers:
        return ProvenanceTier.SHELL
    if ProvenanceTier.HOOK in tiers:
        return ProvenanceTier.HOOK
    return ProvenanceTier.MCP


def _classify_audit_id(audit_id: str) -> ProvenanceTier:
    """Classify a single audit ID to its provenance tier.

    The classification is based on naming conventions:
    - "nighteye-{examiner}-{date}-{seq}" → MCP (standard tool calls)
    - "hook-*" / "ingest-*" / "constructor-*" → HOOK (automated pipelines)
    - "shell-*" / "manual-*" / "cli-*" → SHELL (operator commands)
    - Anything else → NONE (unrecognized)

    In practice, most audit IDs will be MCP-format since all agent
    tool calls generate them via ``nighteye.audit.record_audit``.
    """
    if not audit_id:
        return ProvenanceTier.NONE

    if audit_id.startswith(_MCP_PREFIX):
        return ProvenanceTier.MCP

    for prefix in _HOOK_PREFIXES:
        if audit_id.startswith(prefix):
            return ProvenanceTier.HOOK

    for prefix in _SHELL_PREFIXES:
        if audit_id.startswith(prefix):
            return ProvenanceTier.SHELL

    return ProvenanceTier.NONE


# ============================================================
# Weight helper
# ============================================================


def provenance_weight(tier: ProvenanceTier) -> int:
    """Return the confidence weight contribution for a provenance tier.

    MCP=20, HOOK=15, SHELL=8, NONE=0 (rejected before scoring).
    """
    return PROVENANCE_WEIGHTS.get(tier, 0)
