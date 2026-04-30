"""Tests for Persistence and Defense Evasion constructors (D10)."""

from __future__ import annotations

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.persistence import PersistenceConstructor
from nighteye.constructors.defense_evasion import DefenseEvasionConstructor
from nighteye.constructors.scoring import ClusterTier


def test_persistence_constructor() -> None:
    constructor = PersistenceConstructor()
    
    # Trigger: Startup folder
    event = CanonicalEvent(
        event_id="e1",
        case_id="INC-01",
        host_name="WKSTN-01",
        timestamp="2026-04-29T14:24:30Z",
        canonical_type=CanonicalType.FILE_CREATION,
        source_index="case",
        source_doc_id="doc1",
        target_file="C:\\Users\\stark\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\malware.exe",
        process_path="C:\\Users\\stark\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\malware.exe"
    )
    
    clusters = constructor.evaluate_event(event)
    assert len(clusters) == 1
    cluster = clusters[0]
    
    assert cluster.trigger_name == "startup_folder_item_added"
    assert cluster.base_score == 45
    
    # Evaluate supporting signals
    constructor.apply_supporting_signals(cluster, [event])
    assert "binary_path_unusual" in cluster.supporting_signals # due to AppData in path
    assert "binary_unsigned" in cluster.supporting_signals # due to missing signature in raw_data
    assert cluster.score == 67 # 45 + 10 + 12
    assert cluster.tier == ClusterTier.MODERATE
    
    constructor.generate_summary(cluster)
    assert "Startup folder" in cluster.summary


def test_defense_evasion_constructor() -> None:
    constructor = DefenseEvasionConstructor()
    
    # Trigger: Encoded PowerShell
    event = CanonicalEvent(
        event_id="e2",
        case_id="INC-01",
        host_name="WKSTN-01",
        timestamp="2026-04-29T14:25:30Z",
        canonical_type=CanonicalType.PROCESS_EXECUTION,
        source_index="case",
        source_doc_id="doc2",
        process_name="powershell.exe",
        command_line="powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQAoAFsAQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnACgAIgBIA"
    )
    
    clusters = constructor.evaluate_event(event)
    assert len(clusters) == 1
    cluster = clusters[0]
    
    assert cluster.trigger_name == "obfuscated_powershell"
    assert cluster.base_score == 40
    
    # Support trigger: Anti-forensic window (Defender disabled nearby)
    support_event = CanonicalEvent(
        event_id="e3",
        case_id="INC-01",
        host_name="WKSTN-01",
        timestamp="2026-04-29T14:25:35Z",
        canonical_type=CanonicalType.ALERT,
        source_index="case",
        source_doc_id="doc3",
        alert_name="Windows Defender Protection Disabled"
    )
    
    constructor.apply_supporting_signals(cluster, [event, support_event])
    assert "occurred_during_anti_forensic_window" in cluster.supporting_signals
    assert cluster.score == 50
    
    constructor.generate_summary(cluster)
    assert "Obfuscated/Encoded PowerShell" in cluster.summary
