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
        canonical_type=CanonicalType.FILE_MODIFICATION,
        source_index="case",
        source_doc_id="doc2",
        target_file="\\\\DC01\\C$\\Windows\\temp\\malware.exe"
    )
    
    constructor.apply_supporting_signals(cluster, [support_event])
    
    assert "admin_share_write_within_60s" in cluster.supporting_signals
    assert "off_hours_timestamp" not in cluster.supporting_signals # 14:24 is not off hours
    assert cluster.score == 42 # 30 + 12
    assert cluster.tier == ClusterTier.MODERATE
    assert len(cluster.events) == 2
    
    # 3. Test Counter Evidence
    constructor.apply_counter_evidence(cluster)
    
    # By default our stub returns False for both counter signals, meaning they were checked but didn't apply
    assert len(cluster.counter_details) == 2
    assert cluster.counter_details[0]["signal"] == "source_host_baseline_matched_admin_workstation"
    assert cluster.counter_details[0]["applies"] is False
    assert cluster.score == 42 # Score shouldn't change
    
    # 4. Summary generation
    constructor.generate_summary(cluster)
    assert "Lateral movement pattern detected on DC01" in cluster.summary
    assert "stark\\admin" in cluster.summary
    assert "10.0.0.5" in cluster.summary
    assert "admin share write" in cluster.summary
