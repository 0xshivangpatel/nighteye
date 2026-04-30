"""Remote Execution Constructor.

Detects TA0002 (Execution) and TA0008 (Lateral Movement execution) techniques.
Constructs behavioral clusters for suspicious code execution, particularly
involving LOLBins, WMI, or unusual parent-child process relationships.

References:
    - CONSTRUCTORS.md § 5.4
    - MITRE: TA0002, T1059, T1106, T1218
"""

from __future__ import annotations

from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import Cluster, Constructor, CounterSignal, SignalRule, TriggerRule

__all__ = ["RemoteExecutionConstructor"]


def _is_wmi_remote_exec(event: CanonicalEvent) -> bool:
    if event.canonical_type != CanonicalType.PROCESS_EXECUTION:
        return False
    parent = event.raw_data.get("process", {}).get("parent", {}).get("name", "").lower() if event.raw_data else ""
    child = event.process_name.lower()
    return "wmiprvse.exe" in parent and ("cmd.exe" in child or "powershell.exe" in child)


def _is_office_spawning_shell(event: CanonicalEvent) -> bool:
    if event.canonical_type != CanonicalType.PROCESS_EXECUTION:
        return False
    parent = event.raw_data.get("process", {}).get("parent", {}).get("name", "").lower() if event.raw_data else ""
    child = event.process_name.lower()
    office_apps = ["winword.exe", "excel.exe", "powerpnt.exe"]
    return any(app in parent for app in office_apps) and ("cmd.exe" in child or "powershell.exe" in child)


def _is_sigma_execution_match(event: CanonicalEvent) -> bool:
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "execution" in name or "lolbin" in name or "suspicious command" in name


class RemoteExecutionConstructor(Constructor):
    name = "RemoteExecution"
    mitre_tactic = "TA0002"
    mitre_techniques = ["T1059", "T1218", "T1047"]

    @property
    def triggers(self) -> list[TriggerRule]:
        return [
            TriggerRule("wmi_remote_exec", 45, _is_wmi_remote_exec),
            TriggerRule("office_spawning_shell", 60, _is_office_spawning_shell),
            TriggerRule("sigma_execution_match", 40, _is_sigma_execution_match),
        ]

    @property
    def supporting_signals(self) -> list[SignalRule]:
        return []

    @property
    def counter_signals(self) -> list[CounterSignal]:
        return []

    def generate_summary(self, cluster: Cluster) -> None:
        host = cluster.trigger_event.host_name
        cluster.summary = f"Suspicious Execution detected on {host}: {cluster.trigger_name}."
