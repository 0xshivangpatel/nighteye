"""Tests for the EVTX parser (D5).

Tests the XML-to-ECS mapping logic without needing real EVTX files.
The parse_evtx_xml_event function accepts raw XML strings, so we can
test every mapping path with synthetic events.
"""

from __future__ import annotations

import pytest

from nighteye.ingest.evtx import (
    _event_id_to_action,
    _event_id_to_category,
    parse_evtx_xml_event,
)


# ============================================================
# Synthetic EVTX XML events
# ============================================================

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _make_logon_event(
    event_id: str = "4624",
    timestamp: str = "2026-04-29T14:23:07.412Z",
    computer: str = "DC01.corp.local",
    channel: str = "Security",
    target_user: str = "admin",
    target_domain: str = "CORP",
    target_sid: str = "S-1-5-21-1234-5678-9012-500",
    logon_type: str = "3",
    source_ip: str = "10.0.0.5",
    source_port: str = "49152",
    process_name: str = "C:\\Windows\\System32\\lsass.exe",
) -> str:
    return f"""<Event xmlns="{_NS}">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="{timestamp}"/>
    <Computer>{computer}</Computer>
    <Channel>{channel}</Channel>
    <Execution ProcessID="660" ThreadID="1234"/>
  </System>
  <EventData>
    <Data Name="TargetUserName">{target_user}</Data>
    <Data Name="TargetDomainName">{target_domain}</Data>
    <Data Name="TargetUserSid">{target_sid}</Data>
    <Data Name="LogonType">{logon_type}</Data>
    <Data Name="IpAddress">{source_ip}</Data>
    <Data Name="IpPort">{source_port}</Data>
    <Data Name="ProcessName">{process_name}</Data>
  </EventData>
</Event>"""


def _make_process_event(
    event_id: str = "4688",
    timestamp: str = "2026-04-29T14:25:00.000Z",
    computer: str = "WKSTN-01",
    new_process: str = "C:\\Windows\\System32\\cmd.exe",
    command_line: str = "cmd.exe /c whoami",
    parent_process: str = "C:\\Windows\\explorer.exe",
    subject_user: str = "bob",
    subject_domain: str = "CORP",
) -> str:
    return f"""<Event xmlns="{_NS}">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="{timestamp}"/>
    <Computer>{computer}</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="NewProcessName">{new_process}</Data>
    <Data Name="CommandLine">{command_line}</Data>
    <Data Name="ParentProcessName">{parent_process}</Data>
    <Data Name="SubjectUserName">{subject_user}</Data>
    <Data Name="SubjectDomainName">{subject_domain}</Data>
  </EventData>
</Event>"""


def _make_service_event(
    event_id: str = "7045",
    timestamp: str = "2026-04-29T15:00:00.000Z",
    computer: str = "DC01",
    service_name: str = "PSEXESVC",
) -> str:
    return f"""<Event xmlns="{_NS}">
  <System>
    <Provider Name="Service Control Manager"/>
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="{timestamp}"/>
    <Computer>{computer}</Computer>
    <Channel>System</Channel>
  </System>
  <EventData>
    <Data Name="ServiceName">{service_name}</Data>
    <Data Name="ImagePath">%SystemRoot%\\PSEXESVC.exe</Data>
    <Data Name="ServiceType">user mode service</Data>
    <Data Name="StartType">demand start</Data>
  </EventData>
</Event>"""


# ============================================================
# Tests: XML-to-ECS mapping
# ============================================================


class TestParseEvtxXmlEvent:

    def test_logon_event_basic_fields(self) -> None:
        doc = parse_evtx_xml_event(_make_logon_event())
        assert doc is not None
        assert doc["event"]["code"] == "4624"
        assert doc["host"]["name"] == "DC01.corp.local"
        assert doc["user"]["name"] == "admin"
        assert doc["user"]["domain"] == "CORP"
        assert doc["source"]["ip"] == "10.0.0.5"
        assert doc["source"]["port"] == 49152

    def test_logon_event_timestamp(self) -> None:
        doc = parse_evtx_xml_event(_make_logon_event())
        assert doc is not None
        assert "@timestamp" in doc
        assert "2026-04-29" in doc["@timestamp"]

    def test_logon_event_action_mapped(self) -> None:
        doc = parse_evtx_xml_event(_make_logon_event())
        assert doc is not None
        assert doc["event"]["action"] == "logon-success"

    def test_logon_event_category_mapped(self) -> None:
        doc = parse_evtx_xml_event(_make_logon_event())
        assert doc is not None
        assert "authentication" in doc["event"]["category"]

    def test_logon_failure(self) -> None:
        doc = parse_evtx_xml_event(_make_logon_event(event_id="4625"))
        assert doc is not None
        assert doc["event"]["code"] == "4625"
        assert doc["event"]["action"] == "logon-failure"

    def test_process_creation(self) -> None:
        doc = parse_evtx_xml_event(_make_process_event())
        assert doc is not None
        assert doc["event"]["code"] == "4688"
        assert doc["event"]["action"] == "process-created"
        assert doc["process"]["name"] == "C:\\Windows\\System32\\cmd.exe"
        assert doc["process"]["command_line"] == "cmd.exe /c whoami"

    def test_process_user_fallback_to_subject(self) -> None:
        doc = parse_evtx_xml_event(_make_process_event())
        assert doc is not None
        assert doc["user"]["name"] == "bob"
        assert doc["user"]["domain"] == "CORP"

    def test_service_install(self) -> None:
        doc = parse_evtx_xml_event(_make_service_event())
        assert doc is not None
        assert doc["event"]["code"] == "7045"
        assert doc["event"]["action"] == "service-installed"

    def test_host_override(self) -> None:
        doc = parse_evtx_xml_event(
            _make_logon_event(computer="DC01.corp.local"),
            host_name="MY-DC01",
        )
        assert doc is not None
        assert doc["host"]["name"] == "MY-DC01"

    def test_nighteye_fields(self) -> None:
        doc = parse_evtx_xml_event(
            _make_logon_event(),
            source_file="/evidence/DC01/Security.evtx",
            audit_id="nighteye-alice-20260429-001",
        )
        assert doc is not None
        ne = doc["nighteye"]
        assert ne["parser"] == "evtx-python"
        assert ne["source_file"] == "/evidence/DC01/Security.evtx"
        assert ne["audit_id"] == "nighteye-alice-20260429-001"
        assert ne["canonical_type"] == "WINDOWS_EVENT"

    def test_winlog_event_data_preserved(self) -> None:
        doc = parse_evtx_xml_event(_make_logon_event())
        assert doc is not None
        assert "winlog" in doc
        assert doc["winlog"]["event_data"]["LogonType"] == "3"
        assert doc["winlog"]["event_data"]["TargetUserName"] == "admin"

    def test_dash_ip_excluded(self) -> None:
        """Windows uses '-' for empty IP fields — should be excluded."""
        doc = parse_evtx_xml_event(_make_logon_event(source_ip="-"))
        assert doc is not None
        assert "source" not in doc or "ip" not in doc.get("source", {})

    def test_execution_process_id(self) -> None:
        doc = parse_evtx_xml_event(_make_logon_event())
        assert doc is not None
        assert doc["process"]["pid"] == 660

    def test_winlog_channel_and_provider(self) -> None:
        doc = parse_evtx_xml_event(_make_logon_event())
        assert doc is not None
        assert doc["winlog"]["channel"] == "Security"
        assert "Security-Auditing" in doc["winlog"]["provider_name"]

    def test_invalid_xml_returns_none(self) -> None:
        assert parse_evtx_xml_event("not xml") is None

    def test_empty_xml_returns_none(self) -> None:
        assert parse_evtx_xml_event("") is None

    def test_xml_without_system_returns_none(self) -> None:
        xml = f'<Event xmlns="{_NS}"><EventData/></Event>'
        assert parse_evtx_xml_event(xml) is None


# ============================================================
# Event ID mapping
# ============================================================


class TestEventIdMapping:

    def test_known_actions(self) -> None:
        assert _event_id_to_action("4624") == "logon-success"
        assert _event_id_to_action("4688") == "process-created"
        assert _event_id_to_action("7045") == "service-installed"
        assert _event_id_to_action("4104") == "script-block-logged"
        assert _event_id_to_action("1") == "process-create"

    def test_unknown_action_returns_empty(self) -> None:
        assert _event_id_to_action("99999") == ""

    def test_known_categories(self) -> None:
        assert _event_id_to_category("4624") == "authentication"
        assert _event_id_to_category("4688") == "process"
        assert _event_id_to_category("5156") == "network"
        assert _event_id_to_category("4720") == "iam"

    def test_unknown_category_returns_empty(self) -> None:
        assert _event_id_to_category("99999") == ""
