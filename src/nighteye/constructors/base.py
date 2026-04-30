"""Base Constructor Framework.

Defines the primitives for behavior construction: Triggers, Signals,
Counter-Signals, Clusters, and the Base Constructor.
"""

from __future__ import annotations

import hashlib
import time
from abc import ABC, abstractmethod
from typing import Any, Callable

from nighteye.canonical.types import CanonicalEvent
from nighteye.constructors.scoring import calculate_cluster_score, get_tier, ClusterTier

__all__ = [
    "TriggerRule",
    "SignalRule",
    "CounterSignal",
    "Cluster",
    "Constructor",
]


class TriggerRule:
    """A rule that identifies a primary behavior and instantiates a Cluster."""
    def __init__(self, name: str, base_score: int, filter_fn: Callable[[CanonicalEvent], bool]):
        self.name = name
        self.base_score = base_score
        self.filter_fn = filter_fn

    def evaluate(self, event: CanonicalEvent) -> bool:
        return self.filter_fn(event)


class SignalRule:
    """A supporting rule that adds weight to an existing Cluster."""
    def __init__(self, name: str, weight: int, evaluate_fn: Callable[[Cluster, list[CanonicalEvent]], bool]):
        self.name = name
        self.weight = weight
        self.evaluate_fn = evaluate_fn


class CounterSignal:
    """A counter-evidence rule that subtracts weight and adds context."""
    def __init__(self, name: str, weight_penalty: int, evaluate_fn: Callable[[Cluster, Any], tuple[bool, str]]):
        self.name = name
        self.weight_penalty = weight_penalty
        self.evaluate_fn = evaluate_fn


class Cluster:
    """A behavioral cluster built from multiple canonical events and signals."""
    def __init__(self, constructor_name: str, host_name: str, trigger_event: CanonicalEvent, trigger_name: str, base_score: int):
        self.cluster_id = f"cluster-{hashlib.sha256(f'{constructor_name}-{trigger_event.event_id}'.encode()).hexdigest()[:16]}"
        self.constructor_name = constructor_name
        self.host_name = host_name
        
        self.trigger_name = trigger_name
        self.trigger_event = trigger_event
        
        self.base_score = base_score
        self.events: list[CanonicalEvent] = [trigger_event]
        
        self.supporting_signals: list[str] = []
        self.supporting_weights: list[int] = []
        
        self.counter_details: list[dict[str, Any]] = []
        self.counter_weights: list[int] = []

        self.score = base_score
        self.tier = get_tier(self.score)
        self.summary = ""

    def add_event(self, event: CanonicalEvent) -> None:
        """Add a supporting canonical event to this cluster."""
        if not any(e.event_id == event.event_id for e in self.events):
            self.events.append(event)

    def add_supporting_signal(self, name: str, weight: int) -> None:
        """Add a supporting signal and recalculate score."""
        if name not in self.supporting_signals:
            self.supporting_signals.append(name)
            self.supporting_weights.append(weight)
            self._recalculate()

    def add_counter_signal(self, name: str, penalty: int, applies: bool, evidence: str) -> None:
        """Add counter-evidence details."""
        self.counter_details.append({
            "signal": name,
            "applies": applies,
            "evidence": evidence
        })
        if applies:
            self.counter_weights.append(penalty)
            self._recalculate()

    def _recalculate(self) -> None:
        self.score = calculate_cluster_score(self.base_score, self.supporting_weights, self.counter_weights)
        self.tier = get_tier(self.score)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the cluster for OpenSearch / SQLite."""
        return {
            "cluster_id": self.cluster_id,
            "constructor_name": self.constructor_name,
            "host_name": self.host_name,
            "trigger_name": self.trigger_name,
            "base_score": self.base_score,
            "score": self.score,
            "tier": self.tier.value,
            "summary": self.summary,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "events": [e.to_dict() for e in self.events],
            "supporting_signals": self.supporting_signals,
            "counter_evidence_details": self.counter_details,
        }


class Constructor(ABC):
    """Base class for all NightEye Constructors."""
    name: str = "BaseConstructor"
    mitre_tactic: str = ""
    mitre_techniques: list[str] = []

    def __init__(self, db_client: Any = None):
        self.db = db_client  # Abstract database client for querying context

    @property
    @abstractmethod
    def triggers(self) -> list[TriggerRule]:
        """Return the list of trigger rules."""
        pass

    @property
    @abstractmethod
    def supporting_signals(self) -> list[SignalRule]:
        """Return the list of supporting signal rules."""
        pass

    @property
    @abstractmethod
    def counter_signals(self) -> list[CounterSignal]:
        """Return the list of counter-evidence checks."""
        pass

    def evaluate_event(self, event: CanonicalEvent) -> list[Cluster]:
        """Evaluate a single canonical event against all triggers."""
        clusters = []
        for trigger in self.triggers:
            if trigger.evaluate(event):
                cluster = Cluster(
                    constructor_name=self.name,
                    host_name=event.host_name,
                    trigger_event=event,
                    trigger_name=trigger.name,
                    base_score=trigger.base_score,
                )
                clusters.append(cluster)
        return clusters

    def apply_supporting_signals(self, cluster: Cluster, context_events: list[CanonicalEvent]) -> None:
        """Apply all supporting signals to a cluster based on the time window context."""
        for signal in self.supporting_signals:
            if signal.evaluate_fn(cluster, context_events):
                cluster.add_supporting_signal(signal.name, signal.weight)

    def apply_counter_evidence(self, cluster: Cluster) -> None:
        """Apply pre-computed counter-evidence directly from DB lookups."""
        for counter in self.counter_signals:
            applies, evidence_text = counter.evaluate_fn(cluster, self.db)
            cluster.add_counter_signal(counter.name, counter.weight_penalty, applies, evidence_text)

    def generate_summary(self, cluster: Cluster) -> None:
        """Generate a human-readable summary of the attack chain."""
        cluster.summary = f"{self.name} triggered by {cluster.trigger_name} on {cluster.host_name} (Score: {cluster.score})"
