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
    """A behavioral cluster aggregating multiple trigger events.

    A cluster represents one (host, time-bucket, constructor) group. It
    records every trigger that fired inside the bucket, accumulates
    supporting signals, and attaches counter-evidence at finalization.
    The cluster_id is keyed on (constructor, host, bucket_start) so that
    re-running the constructor over the same data is idempotent.
    """

    def __init__(
        self,
        constructor_name: str,
        host_name: str,
        trigger_event: CanonicalEvent,
        trigger_name: str,
        base_score: int,
        bucket_key: str | None = None,
        mitre_tactic: str = "",
        technique_ids: list[str] | None = None,
    ):
        bucket_key = bucket_key or trigger_event.event_id
        self.cluster_id = (
            "cluster-"
            + hashlib.sha256(
                f"{constructor_name}|{host_name}|{bucket_key}".encode()
            ).hexdigest()[:16]
        )
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

        # Schema-compat fields: populated by the runner from Constructor.
        self.triggers_fired: list[str] = [trigger_name]
        self.mitre_tactic: str = mitre_tactic
        self.technique_ids: list[str] = list(technique_ids or [])
        self.time_start: str = trigger_event.timestamp
        self.time_end: str = trigger_event.timestamp
        self.bucket_key: str = bucket_key

    def add_trigger(self, trigger_name: str, event: CanonicalEvent, base_score: int) -> None:
        """Record an additional trigger firing within the same cluster bucket.

        Use the higher of (current base_score, new base_score) as the
        cluster's base — strongest trigger wins. The triggers_fired list
        accumulates uniquely so we don't over-count the same trigger.
        """
        self.add_event(event)
        if trigger_name not in self.triggers_fired:
            self.triggers_fired.append(trigger_name)
        if base_score > self.base_score:
            self.base_score = base_score
            self._recalculate()

    def add_event(self, event: CanonicalEvent) -> None:
        """Add a supporting canonical event to this cluster."""
        if not any(e.event_id == event.event_id for e in self.events):
            self.events.append(event)
            # Update temporal bounds
            if event.timestamp and event.timestamp < self.time_start:
                self.time_start = event.timestamp
            if event.timestamp and event.timestamp > self.time_end:
                self.time_end = event.timestamp

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

_ANTI_FORENSIC_CONSTRUCTORS = {
    "LogClearing",
    "Timestomp",
    "ShadowDeletion",
}


def _bucket_key(event: CanonicalEvent, window_seconds: int) -> str:
    """Compute the time-bucket key for grouping events.

    Events that fall within the same `window_seconds` window on the same
    host land in the same bucket and get folded into one cluster per
    constructor.
    """
    ts = event.timestamp or ""
    if not ts or window_seconds <= 0:
        return ts or event.event_id
    try:
        from datetime import datetime, timezone

        # Normalize Z suffix
        norm = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
        dt = datetime.fromisoformat(norm)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        epoch = int(dt.timestamp())
        bucket = epoch - (epoch % window_seconds)
        return f"{bucket}"
    except (ValueError, TypeError):
        return ts


def run_all_constructors(client, case_id: str, db_path: str) -> dict[str, int]:
    """Run all constructors over the canonical data for a case.

    Aggregates events by (constructor, host, time-bucket): all triggers
    firing within the same window on the same host produce ONE cluster
    that records every trigger fired and every member event. This matches
    docs/CONSTRUCTORS.md § 1 (cluster grouping rules).

    Args:
        client: NightEyeOSClient
        case_id: Case ID
        db_path: Path to graph.db

    Returns:
        Statistics dict
    """
    from nighteye.canonical.engine import normalize_document
    from nighteye.constructors import ALL_CONSTRUCTORS

    stats = {
        "constructors_run": 0,
        "clusters_created": 0,
        "high_confidence": 0,
        "anti_forensic": 0,
    }

    constructors = [C(db_client=db_path) for C in ALL_CONSTRUCTORS]
    stats["constructors_run"] = len(constructors)

    # Per-(constructor, host, bucket) cluster accumulator.
    # Key: (constructor.name, host_name, bucket_key) -> Cluster
    cluster_index: dict[tuple[str, str, str], Cluster] = {}
    # Per-host event reservoir for supporting-signal context
    events_by_host: dict[str, list[CanonicalEvent]] = {}

    canonical_indices = client.list_indices(f"case-{case_id}-canonical-*")

    for index_name in canonical_indices:
        logger.info("Running behavioral clustering on %s", index_name)
        try:
            for page in client.scroll_search_iter(
                index=index_name,
                query={"match_all": {}},
                page_size=1000,
            ):
                events: list[CanonicalEvent] = []
                for doc in page:
                    ev = normalize_document(doc, case_id)
                    if ev:
                        events.append(ev)
                if not events:
                    continue

                for ev in events:
                    if ev.host_name:
                        events_by_host.setdefault(ev.host_name, []).append(ev)

                # Score each event against each constructor's triggers.
                for constructor in constructors:
                    window = getattr(constructor, "grouping_window_seconds", 1800)
                    for ev in events:
                        for trigger in constructor.triggers:
                            if not trigger.evaluate(ev):
                                continue
                            host = ev.host_name or "unknown-host"
                            bkey = _bucket_key(ev, window)
                            ck = (constructor.name, host, bkey)
                            cluster = cluster_index.get(ck)
                            if cluster is None:
                                cluster = Cluster(
                                    constructor_name=constructor.name,
                                    host_name=host,
                                    trigger_event=ev,
                                    trigger_name=trigger.name,
                                    base_score=trigger.base_score,
                                    bucket_key=bkey,
                                    mitre_tactic=getattr(constructor, "mitre_tactic", ""),
                                    technique_ids=list(
                                        getattr(constructor, "mitre_techniques", [])
                                    ),
                                )
                                cluster_index[ck] = cluster
                            else:
                                cluster.add_trigger(
                                    trigger.name, ev, trigger.base_score
                                )

        except Exception as exc:
            logger.error("Clustering failed for index %s: %s", index_name, exc)

    # Finalize: apply supporting signals (per-host reservoir) and
    # counter-evidence, generate summary, and persist.
    for (constructor_name, host, _bkey), cluster in cluster_index.items():
        constructor = next(
            (c for c in constructors if c.name == constructor_name),
            None,
        )
        if constructor is None:
            continue
        try:
            host_events = events_by_host.get(host, [])
            constructor.apply_supporting_signals(cluster, host_events)
            constructor.apply_counter_evidence(cluster)
            constructor.generate_summary(cluster)
            save_cluster(db_path, case_id, cluster)
            stats["clusters_created"] += 1
            if cluster.score >= 70:
                stats["high_confidence"] += 1
            if cluster.constructor_name in _ANTI_FORENSIC_CONSTRUCTORS:
                stats["anti_forensic"] += 1
        except Exception as exc:
            logger.error(
                "Cluster finalization failed for %s: %s", cluster.cluster_id, exc
            )

    return stats


def save_cluster(db_path: str, case_id: str, cluster: Cluster) -> None:
    """Save a behavioral cluster to the SQLite database."""
    import json
    from datetime import datetime, timezone
    from nighteye.db import connect, execute_with_retry

    now = datetime.now(timezone.utc).isoformat()
    
    # Determine secondary hosts (all hosts in cluster except primary)
    hosts = {e.host_name for e in cluster.events if e.host_name}
    secondary_hosts = list(hosts - {cluster.host_name})

    # Map strength to allowed values
    strength_map = {
        ClusterTier.STRONG: "STRONG",
        ClusterTier.MODERATE: "MODERATE",
        ClusterTier.WEAK: "WEAK",
        ClusterTier.NOISE: "NOISE"
    }
    strength = strength_map.get(cluster.tier, "MODERATE")

    with connect(db_path) as conn:
        execute_with_retry(
            conn,
            """
            INSERT INTO clusters (
                cluster_id, case_id, cluster_type, strength, score,
                triggers_fired, supporting_signals, counter_signals,
                counter_evidence_details, contradicting_clusters,
                member_canonical_ids, primary_host, primary_user,
                secondary_hosts, time_start, time_end,
                technique_ids, mitre_tactic, summary, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cluster_id) DO UPDATE SET
                score = excluded.score,
                strength = excluded.strength,
                summary = excluded.summary,
                triggers_fired = excluded.triggers_fired,
                supporting_signals = excluded.supporting_signals,
                counter_signals = excluded.counter_signals,
                time_end = excluded.time_end
            """,
            (
                cluster.cluster_id,
                case_id,
                cluster.constructor_name,
                strength,
                cluster.score,
                json.dumps(cluster.triggers_fired),
                json.dumps(cluster.supporting_signals),
                json.dumps([c["signal"] for c in cluster.counter_details if c["applies"]]),
                json.dumps(cluster.counter_details),
                json.dumps([]), # contradicting_clusters
                json.dumps([e.event_id for e in cluster.events]),
                cluster.host_name,
                cluster.trigger_event.user or "unknown",
                json.dumps(secondary_hosts),
                cluster.time_start,
                cluster.time_end,
                json.dumps(cluster.technique_ids),
                cluster.mitre_tactic,
                cluster.summary,
                now
            )
        )
        conn.commit()
