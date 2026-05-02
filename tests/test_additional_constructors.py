"""Tests for additional constructors (Credential Access, Remote Execution, Exfiltration)."""

from __future__ import annotations

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.credential_access import CredentialAccessConstructor
from nighteye.constructors.remote_execution import RemoteExecutionConstructor
from nighteye.constructors.exfiltration import ExfiltrationConstructor


def test_credential_access_constructor() -> None:
    constructor = CredentialAccessConstructor()
    
    event = CanonicalEvent(
        event_id="e1",
        case_id="INC-01",
        host_name="DC01",
        timestamp="2026-04-29T14:24:30Z",
        canonical_type=CanonicalType.PROCESS_EXECUTION,
        source_index="case",
        source_doc_id="doc1",
        command_line="reg save hklm\\sam C:\\temp\\sam.save",
        target_file="C:\\temp\\sam.save"
    )
    
    clusters = constructor.evaluate_event(event)
    assert len(clusters) == 1
    assert clusters[0].trigger_name == "sam_hive_copy"
    assert clusters[0].base_score == 45


def test_remote_execution_constructor() -> None:
    constructor = RemoteExecutionConstructor()
    
    event = CanonicalEvent(
        event_id="e2",
        case_id="INC-01",
        host_name="WKSTN-01",
        timestamp="2026-04-29T14:24:30Z",
        canonical_type=CanonicalType.PROCESS_EXECUTION,
        source_index="case",
        source_doc_id="doc2",
        process_name="cmd.exe",
        raw_data={"process": {"parent": {"name": "winword.exe"}}}
    )
    
    clusters = constructor.evaluate_event(event)
    assert len(clusters) == 1
    assert clusters[0].trigger_name == "office_spawning_shell"
    assert clusters[0].base_score == 60


def test_exfiltration_constructor() -> None:
    constructor = ExfiltrationConstructor()
    
    event = CanonicalEvent(
        event_id="e3",
        case_id="INC-01",
        host_name="WKSTN-01",
        timestamp="2026-04-29T14:24:30Z",
        canonical_type=CanonicalType.PROCESS_EXECUTION,
        source_index="case",
        source_doc_id="doc3",
        process_name="rclone.exe",
    )
    
    clusters = constructor.evaluate_event(event)
    assert len(clusters) == 1
    assert clusters[0].trigger_name == "cloud_upload_tool"
