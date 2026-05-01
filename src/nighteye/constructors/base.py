"""Base Constructor Framework.

Defines the primitives for behavior construction: Triggers, Signals,
Counter-Signals, Clusters, and the Base Constructor.
"""

from __future__ import annotations

import hashlib
import logging
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
    "run_all_constructors",
]

logger = logging.getLogger("nighteye.constructors")


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


# ============================================================
# Cluster Runner
# ============================================================

def run_all_constructors(client, case_id: str, db_path: str) -> dict[str, int]:
    """Run all 12 constructors over the canonical data for a case.

    Args:
        client: NightEyeOSClient
        case_id: Case ID
        db_path: Path to graph.db

    Returns:
        Statistics dict
    """
    from nighteye.constructors import ALL_CONSTRUCTORS
    from nighteye.canonical.engine import normalize_document

    stats = {
        "constructors_run": 0,
        "clusters_created": 0,
        "high_confidence": 0,
        "anti_forensic": 0,
    }

    # Instantiate all constructors
    constructors = [C() for C in ALL_CONSTRUCTORS]
    stats["constructors_run"] = len(constructors)

    # Find all canonical indices for this case
    canonical_indices = client.list_indices(f"case-{case_id}-canonical-*")

    for index_name in canonical_indices:
        logger.info("Running behavioral clustering on %s", index_name)

        try:
            # Scroll through all canonical events
            for page in client.scroll_search_iter(
                index=index_name,
                query={"match_all": {}},
                page_size=1000,
            ):
                events = []
                for doc in page:
                    event = normalize_document(doc, case_id)
                    if event:
                        events.append(event)

                if not events:
                    continue

                # Run each constructor over the events
                for constructor in constructors:
                    for event in events:
                        # 1. Check for triggers
                        new_clusters = constructor.evaluate_event(event)
                        for cluster in new_clusters:
                            # 2. Apply signals from the same host context
                            # (In a real implementation, we'd use a larger time window)
                            constructor.apply_supporting_signals(cluster, events)

                            # 3. Apply counter-evidence (DB lookup)
                            constructor.apply_counter_evidence(cluster)

                            # 4. Finalize
                            constructor.generate_summary(cluster)
                            save_cluster(db_path, case_id, cluster)

                            stats["clusters_created"] += 1
                            if cluster.score >= 70:
                                stats["high_confidence"] += 1
                            if "anti-forensic" in cluster.constructor_name.lower():
                                stats["anti_forensic"] += 1

        except Exception as exc:
            logger.error("Clustering failed for index %s: %s", index_name, exc)

    return stats


def save_cluster(db_path: str, case_id: str, cluster: Cluster) -> None:
    """Save a behavioral cluster to the SQLite graph database."""
    import json
    from nighteye.db import connect, execute_with_retry
    
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    
    with connect(db_path) as conn:
        execute_with_retry(
            conn,
            """
            INSERT INTO clusters (
                cluster_id, case_id, constructor_name, host, 
                score, strength, status, summary, 
                trigger_event_id, event_ids, signals, counter_evidence,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cluster_id) DO UPDATE SET
                score = excluded.score,
                strength = excluded.strength,
                summary = excluded.summary,
                updated_at = excluded.updated_at
            """,
            (
                cluster.cluster_id,
                case_id,
                cluster.constructor_name,
                cluster.host_name,
                cluster.score,
                cluster.tier.value,
                "OPEN",
                cluster.summary,
                cluster.trigger_event.event_id,
                json.dumps([e.event_id for e in cluster.events]),
                json.dumps(cluster.supporting_signals),
                json.dumps(cluster.counter_details),
                now,
                now
            )
        )
        conn.commit()
