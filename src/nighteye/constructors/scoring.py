"""Constructor scoring and strength tiering.

Handles the math for combining base triggers, supporting evidence,
and counter-evidence to produce a final confidence score and tier.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["ClusterTier", "calculate_cluster_score", "get_tier"]


class ClusterTier(str, Enum):
    """The visibility tier of a behavioral cluster."""
    STRONG = "STRONG"      # 70-100: High confidence, auto-surfaced
    MODERATE = "MODERATE"  # 40-69: Medium confidence, auto-surfaced
    WEAK = "WEAK"          # 20-39: Low confidence, explicitly requested
    NOISE = "NOISE"        # 0-19: False positive / noise, hidden


def calculate_cluster_score(
    base_score: int,
    supporting_weights: list[int],
    counter_weights: list[int],
) -> int:
    """Calculate the final confidence score for a cluster.

    Score = base + sum(supporting) - sum(counter)
    Bounded between 0 and 100.
    """
    total = base_score + sum(supporting_weights) - sum(counter_weights)
    return max(0, min(100, total))


def get_tier(score: int) -> ClusterTier:
    """Determine the tier based on the score."""
    if score >= 70:
        return ClusterTier.STRONG
    elif score >= 40:
        return ClusterTier.MODERATE
    elif score >= 20:
        return ClusterTier.WEAK
    else:
        return ClusterTier.NOISE
