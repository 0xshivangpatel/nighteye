"""Credential Access Constructor.

Detects TA0006 (Credential Access) techniques.
Constructs behavioral clusters for actions intended to steal credentials,
such as LSASS dumping, Kerberoasting, DCSync, or Registry hive copying.

References:
    - CONSTRUCTORS.md § 5.3
    - MITRE: TA0006, T1003, T1558
"""

from __future__ import annotations

from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import Cluster, Constructor, CounterSignal, SignalRule, TriggerRule

__all__ = ["CredentialAccessConstructor"]


def _is_sigma_credential_access(event: CanonicalEvent) -> bool:
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "credential" in name or "lsass" in name or "dump" in name or "mimikatz" in name


def _is_registry_hive_copy(event: CanonicalEvent) -> bool:
    if event.canonical_type not in (CanonicalType.FILE_CREATION, CanonicalType.PROCESS_EXECUTION):
        return False
        
    cmd = event.command_line.lower()
    path = event.target_file.lower()
    
    # Check for reg save or vssadmin copying SAM/SYSTEM
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        return "reg" in cmd and "save" in cmd and ("hklm\\sam" in cmd or "hklm\\system" in cmd)
        
    # Check for direct file creation of these hives in unusual locations
    if event.canonical_type == CanonicalType.FILE_CREATION:
        return ("sam" in path or "system" in path) and ("\\temp\\" in path or "\\users\\" in path)
        
    return False


def _is_brute_force_spike(event: CanonicalEvent) -> bool:
    # We would theoretically check for a spike here, but since constructors evaluate single events,
    # we rely on Sigma rules or custom aggregate detectors to generate an ALERT for brute force.
    return False


# --- Supporting Signal Evaluators ---

def _eval_dumping_tool_in_process_tree(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    # Stubbed
    return False

def _eval_occurred_after_lateral_movement(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    # Look for LM alerts in context
    for event in context:
        if event.canonical_type == CanonicalType.ALERT and "lateral movement" in event.alert_name.lower():
            return True
    return False

# --- Counter Signal Evaluators ---

def _eval_is_defender(cluster: Cluster, db: Any) -> tuple[bool, str]:
    process = cluster.trigger_event.process_name.lower()
    if process in ("msmpeng.exe", "mssense.exe"):
        return True, "Accessing process is Windows Defender"
    return False, ""


class CredentialAccessConstructor(Constructor):
    name = "CredentialAccess"
    mitre_tactic = "TA0006"
    mitre_techniques = ["T1003", "T1558", "T1110"]

    @property
    def triggers(self) -> list[TriggerRule]:
        return [
            TriggerRule("sigma_credential_access_match", 50, _is_sigma_credential_access),
            TriggerRule("sam_security_hive_copy", 55, _is_registry_hive_copy),
        ]

    @property
    def supporting_signals(self) -> list[SignalRule]:
        return [
            SignalRule("dumping_tool_in_process_tree", 14, _eval_dumping_tool_in_process_tree),
            SignalRule("occurred_after_lateral_movement", 10, _eval_occurred_after_lateral_movement),
        ]

    @property
    def counter_signals(self) -> list[CounterSignal]:
        return [
            CounterSignal("accessing_process_is_defender", 15, _eval_is_defender),
        ]

    def generate_summary(self, cluster: Cluster) -> None:
        host = cluster.trigger_event.host_name
        cluster.summary = f"Credential Access detected on {host}: {cluster.trigger_name}."
