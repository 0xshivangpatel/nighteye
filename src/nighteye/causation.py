"""Causation ladder constants and helpers.

The causation ladder defines six levels of causal evidence, from
strongest (CHAIN — process tree proves execution sequence) to weakest
(TEMPORAL_ONLY — events merely share a time window).

Hypothesis ``record_hypothesis`` enforces: if the interpretation uses
causation language ("caused", "led to", "enabled"), a causal link of
CHAIN, WRITE, or NET must exist. Otherwise the hypothesis is rejected
at the gate.

References:
    - docs/ARCHITECTURE.md § 9 (causal links)
    - docs/CONSTRUCTORS.md § 6 (implementation notes)
"""

from __future__ import annotations

from nighteye.models import CausalLevel

__all__ = [
    "CAUSAL_WEIGHTS",
    "STRONG_CAUSAL_LEVELS",
    "causal_weight",
    "is_strong_causal",
    "claims_causation",
]


# ============================================================
# Weight map — used by confidence engine
# ============================================================

CAUSAL_WEIGHTS: dict[CausalLevel, int] = {
    CausalLevel.CHAIN: 15,
    CausalLevel.WRITE: 12,
    CausalLevel.NET: 10,
    CausalLevel.TIGHT_TIME: 6,
    CausalLevel.CO_OCCUR: 3,
    CausalLevel.TEMPORAL_ONLY: 1,
    CausalLevel.UNSUPPORTED: 0,
}


# ============================================================
# Strong causal levels — required for causation claims
# ============================================================

STRONG_CAUSAL_LEVELS: frozenset[CausalLevel] = frozenset({
    CausalLevel.CHAIN,
    CausalLevel.WRITE,
    CausalLevel.NET,
})


# ============================================================
# Helpers
# ============================================================


def causal_weight(level: CausalLevel) -> int:
    """Return the confidence weight contribution for a causal level."""
    return CAUSAL_WEIGHTS.get(level, 0)


def is_strong_causal(level: CausalLevel) -> bool:
    """True if the causal level is strong enough to support causation claims.

    Only CHAIN, WRITE, and NET are accepted. TIGHT_TIME, CO_OCCUR,
    and TEMPORAL_ONLY are correlational, not causal.
    """
    return level in STRONG_CAUSAL_LEVELS


# ============================================================
# Causation language detection
# ============================================================

# Phrases that imply causation in a hypothesis interpretation.
# These must be matched case-insensitively in the interpretation text.
_CAUSATION_PHRASES: tuple[str, ...] = (
    "caused",
    "led to",
    "enabled",
    "resulted in",
    "triggered",
    "launched",
    "spawned",
    "executed via",
    "dropped by",
    "deployed by",
    "initiated by",
    "established by",
    "pivoted to",
    "moved laterally",
    "exfiltrated via",
    "propagated to",
    "chained to",
    "which then",
)


def claims_causation(interpretation: str) -> bool:
    """Detect whether an interpretation text uses causation language.

    If True, the hypothesis gate requires a strong causal link
    (CHAIN, WRITE, or NET) to be present.

    Args:
        interpretation: The hypothesis interpretation text.

    Returns:
        True if causation language is detected.
    """
    lower = interpretation.lower()
    return any(phrase in lower for phrase in _CAUSATION_PHRASES)
