"""Tests for the Constructor framework and Lateral Movement logic (D9)."""

from __future__ import annotations

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import Cluster
from nighteye.constructors.lateral_movement import LateralMovementConstructor
from nighteye.constructors.scoring import ClusterTier, calculate_cluster_score, get_tier


def test_scoring_math() -> None:
    # Base 30, supporting +12 +10 = 52. Tier = MODERATE
    score = calculate_cluster_score(30, [12, 10], [])
    assert score == 52
    assert get_tier(score) == ClusterTier.MODERATE
    
    # Base 30, supporting +12, counter -10 = 32. Tier = WEAK
    score = calculate_cluster_score(30, [12], [10])
    assert score == 32
    assert get_tier(score) == ClusterTier.WEAK
    
    # Bounds checking
    assert calculate_cluster_score(90, [50], []) == 100
    assert calculate_cluster_score(10, [], [30]) == 0


def test_lateral_movement_constructor() -> None:
    constructor = LateralMovementConstructor()
    
    # 1. Test Trigger (Network Logon)
    trigger_event = CanonicalEvent(
        event_id="e1",
        case_id="INC-01",
        host_name="DC01",
        timestamp="2026-04-29T14:24:30Z",
        canonical_type=CanonicalType.AUTHENTICATION,
        source_index="case",
        source_doc_id="doc1",
        remote_ip="10.0.0.5",
        user="stark\\admin",
        raw_data={"winlog": {"event_data": {"LogonType": "3"}}}
    )
    
    clusters = constructor.evaluate_event(trigger_event)
    assert len(clusters) == 1
    cluster = clusters[0]
    
    assert cluster.trigger_name == "network_logon_type3_from_internal"
    assert cluster.base_score == 30
    assert cluster.tier == ClusterTier.WEAK
    
    # 2. Test Supporting Evidence (Admin share write)
    support_event = CanonicalEvent(
        event_id="e2",
        case_id="INC-01",
        host_name="DC01",
        timestamp="2026-04-29T14:24:35Z",
        canonical_type=CanonicalType.FILE_CREATION,
        source_index="case",
        source_doc_id="doc2",
        target_file="\\\\DC01\\C$\\Windows\\temp\\malware.exe"
    )
    
    constructor.apply_supporting_signals(cluster, [support_event])

    assert "tools_dropped_on_target" in cluster.supporting_signals
    assert "target_not_previously_accessed" in cluster.supporting_signals
    assert cluster.score == 54  # 30 + 14 + 10
    assert cluster.tier == ClusterTier.MODERATE
    assert len(cluster.events) == 1  # only trigger event; signals don't add events

    # 3. Test Counter Evidence
    constructor.apply_counter_evidence(cluster)

    assert len(cluster.counter_details) == 4
    assert cluster.counter_details[0]["signal"] == "documented_jump_server"
    assert cluster.counter_details[0]["applies"] is False
    assert cluster.score == 44

    # 4. Summary generation
    constructor.generate_summary(cluster)
    assert "Lateral movement" in cluster.summary
    assert "stark\\admin" in cluster.summary
    assert "10.0.0.5" in cluster.summary
    assert "tools_dropped_on_target" in cluster.summary
