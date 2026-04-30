"""Defense Evasion Constructor.

Detects TA0005 (Defense Evasion) techniques.
Constructs behavioral clusters for actions intended to hide presence
or disable security controls (obfuscation, defender tampering, injection).

References:
    - CONSTRUCTORS.md § 5.5
    - MITRE: TA0005, T1027, T1562
"""

from __future__ import annotations

from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import Cluster, Constructor, CounterSignal, SignalRule, TriggerRule

__all__ = ["DefenseEvasionConstructor"]


def _is_obfuscated_powershell(event: CanonicalEvent) -> bool:
    """Trigger: Process execution matching encoded/obfuscated PowerShell."""
    if event.canonical_type != CanonicalType.PROCESS_EXECUTION:
        return False
    
    cmd = event.command_line.lower()
    return "powershell" in cmd and ("-enc" in cmd or "-encodedcommand" in cmd)


def _is_defender_disabled(event: CanonicalEvent) -> bool:
    """Trigger: Windows Defender disabled or real-time protection turned off."""
    if event.canonical_type == CanonicalType.ALERT:
        if "defender" in event.alert_name.lower() and ("disable" in event.alert_name.lower() or "tamper" in event.alert_name.lower()):
            return True
            
    # Also check if it's a raw Event ID 5001/5007 mapped to execution/alert
    raw = event.raw_data or {}
    event_id = str(raw.get("event", {}).get("code", ""))
    if event_id in ("5001", "5007"):
        return True
        
    return False


def _is_process_injection(event: CanonicalEvent) -> bool:
    """Trigger: Process injection (Sysmon 8/25, Vol3 malfind, or alerts)."""
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        if "injection" in name or "malfind" in name or "hollow" in name:
            return True
            
    # Sysmon CreateRemoteThread
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        # We don't have a specific CREATE_REMOTE_THREAD canonical type yet, 
        # but if we mapped it to PROCESS_EXECUTION with a specific action:
        raw = event.raw_data or {}
        if str(raw.get("event", {}).get("code", "")) == "8":
            return True
            
    return False


def _is_sigma_defense_evasion(event: CanonicalEvent) -> bool:
    """Trigger: Sigma tag attack.defense_evasion."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "evasion" in name or "bypass" in name or "tampering" in name


# --- Supporting Signal Evaluators ---

def _eval_occurred_during_anti_forensic_window(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Checks if this occurred near other anti-forensic acts (e.g. log clearing)."""
    # For now, just look for any other evasion triggers in the context
    for event in context:
        if event.event_id != cluster.trigger_event.event_id:
            if _is_defender_disabled(event) or _is_sigma_defense_evasion(event):
                cluster.add_event(event)
                return True
    return False


# --- Counter Signal Evaluators ---

def _eval_known_admin_script(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if the powershell matches known legitimate admin script patterns."""
    if cluster.trigger_name != "obfuscated_powershell":
        return False, "Not applicable"
        
    # Stubbed lookup
    return False, "Command line does not match known baseline scripts"


def _eval_within_av_update_window(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if Defender event aligns with known patch/update times."""
    if cluster.trigger_name != "defender_disabled":
        return False, "Not applicable"
        
    # Stubbed lookup
    return False, "Not within a documented AV update window"


class DefenseEvasionConstructor(Constructor):
    """Constructor for detecting Defense Evasion."""
    
    name = "DefenseEvasion"
    mitre_tactic = "TA0005"
    mitre_techniques = ["T1027", "T1055", "T1562"]

    @property
    def triggers(self) -> list[TriggerRule]:
        return [
            TriggerRule("obfuscated_powershell", 40, _is_obfuscated_powershell),
            TriggerRule("defender_disabled", 50, _is_defender_disabled),
            TriggerRule("process_injection_indicator", 60, _is_process_injection),
            TriggerRule("sigma_defense_evasion_match", 45, _is_sigma_defense_evasion),
        ]

    @property
    def supporting_signals(self) -> list[SignalRule]:
        return [
            SignalRule("occurred_during_anti_forensic_window", 10, _eval_occurred_during_anti_forensic_window),
        ]

    @property
    def counter_signals(self) -> list[CounterSignal]:
        return [
            CounterSignal("matched_known_admin_powershell", 10, _eval_known_admin_script),
            CounterSignal("within_av_update_window", 10, _eval_within_av_update_window),
        ]

    def generate_summary(self, cluster: Cluster) -> None:
        host = cluster.trigger_event.host_name
        
        parts = [f"Defense Evasion detected on {host}"]
        
        if cluster.trigger_name == "obfuscated_powershell":
            parts.append("Obfuscated/Encoded PowerShell execution")
        elif cluster.trigger_name == "defender_disabled":
            parts.append("Windows Defender protection disabled or tampered")
        elif cluster.trigger_name == "process_injection_indicator":
            parts.append(f"Process injection detected: {cluster.trigger_event.process_name or 'unknown process'}")
        elif cluster.trigger_name == "sigma_defense_evasion_match":
            parts.append(f"Sigma evasion rule matched: {cluster.trigger_event.alert_name}")
            
        cluster.summary = ", ".join(parts) + "."
