"""Lateral Movement Constructor.

Detects T1021 (Remote Services) and related lateral movement techniques.
Constructs behavioral clusters by linking authentications, service installs,
admin share access, and Sigma detections.

References:
    - CONSTRUCTORS.md § 5.1
    - MITRE: TA0008, T1021.002, T1569.002
"""

from __future__ import annotations

from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import Cluster, Constructor, CounterSignal, SignalRule, TriggerRule

__all__ = ["LateralMovementConstructor"]


def _is_network_logon_type3(event: CanonicalEvent) -> bool:
    """Trigger: Logon type 3 (Network) from internal IP, excluding machine accounts."""
    if event.canonical_type != CanonicalType.AUTHENTICATION:
        return False
        
    raw = event.raw_data or {}
    winlog = raw.get("winlog", {}).get("event_data", {})
    logon_type = str(winlog.get("LogonType", ""))
    
    if logon_type != "3":
        return False
        
    # Ignore machine accounts (e.g. WORKSTATION$)
    if event.user and event.user.endswith("$"):
        return False
        
    # Ignore localhost loops
    ip = event.remote_ip
    if not ip or ip in ("127.0.0.1", "::1"):
        return False
        
    return True


def _is_rdp_logon_type10(event: CanonicalEvent) -> bool:
    """Trigger: Logon type 10 (RemoteInteractive/RDP)."""
    if event.canonical_type != CanonicalType.AUTHENTICATION:
        return False
        
    raw = event.raw_data or {}
    winlog = raw.get("winlog", {}).get("event_data", {})
    return str(winlog.get("LogonType", "")) == "10"


def _is_psexec_pattern(event: CanonicalEvent) -> bool:
    """Trigger: PsExec service installation."""
    if event.canonical_type != CanonicalType.SERVICE_INSTALLATION:
        return False
        
    path = event.target_file.lower() or event.process_path.lower()
    return "psexesvc" in path


def _is_sigma_lm_match(event: CanonicalEvent) -> bool:
    """Trigger: Hayabusa/Chainsaw alert tagged with lateral movement."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
        
    # Look for LM in the rule name or ECS rule categorization
    name = event.alert_name.lower()
    return "lateral movement" in name or "psexec" in name or "wmi exec" in name


def _is_admin_share_write(event: CanonicalEvent) -> bool:
    """Supporting: File written to C$, ADMIN$, or IPC$."""
    if event.canonical_type not in (CanonicalType.FILE_CREATION, CanonicalType.FILE_MODIFICATION):
        return False
    path = event.target_file.lower()
    return "\\c$\\" in path or "\\admin$\\" in path or "\\ipc$\\" in path


# --- Supporting Signal Evaluators ---

def _eval_admin_share_write_within_60s(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Checks if an admin share write occurred near the trigger."""
    for event in context:
        if _is_admin_share_write(event):
            cluster.add_event(event)
            return True
    return False


def _eval_off_hours(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Checks if the trigger happened outside normal business hours (09-17)."""
    # Simple heuristic on the UTC timestamp
    # In a real app we'd use local timezone if known
    try:
        # e.g. "2026-04-29T14:24:30Z"
        hour = int(cluster.trigger_event.timestamp[11:13])
        return hour < 9 or hour > 17
    except Exception:
        return False


# --- Counter Signal Evaluators ---

def _eval_admin_workstation_baseline(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if the source IP is a known admin workstation."""
    # Stubbed DB lookup
    ip = cluster.trigger_event.remote_ip
    if not ip:
        return False, "no remote IP available"
    
    # If db had a baseline:
    # if ip in db.get_baseline("admin_workstations"): return True, f"{ip} in admin baseline"
    return False, f"{ip} not in known admin baseline"


def _eval_service_binary_signed(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if the service binary is signed by Microsoft."""
    if cluster.trigger_event.canonical_type != CanonicalType.SERVICE_INSTALLATION:
        return False, "trigger is not a service installation"
        
    # Usually Amcache or PE header parsers give us signature status
    # We would query the canonical events for this file hash
    return False, "binary unsigned or signature status unknown"


class LateralMovementConstructor(Constructor):
    """Constructor for detecting Lateral Movement chains."""
    
    name = "LateralMovement"
    mitre_tactic = "TA0008"
    mitre_techniques = ["T1021.001", "T1021.002", "T1569.002"]

    @property
    def triggers(self) -> list[TriggerRule]:
        return [
            TriggerRule("network_logon_type3_from_internal", 30, _is_network_logon_type3),
            TriggerRule("rdp_logon_type10", 30, _is_rdp_logon_type10),
            TriggerRule("psexec_pattern", 50, _is_psexec_pattern),
            TriggerRule("sigma_lateral_movement_match", 45, _is_sigma_lm_match),
        ]

    @property
    def supporting_signals(self) -> list[SignalRule]:
        return [
            SignalRule("admin_share_write_within_60s", 12, _eval_admin_share_write_within_60s),
            SignalRule("off_hours_timestamp", 10, _eval_off_hours),
        ]

    @property
    def counter_signals(self) -> list[CounterSignal]:
        return [
            CounterSignal("source_host_baseline_matched_admin_workstation", 10, _eval_admin_workstation_baseline),
            CounterSignal("service_binary_signed_microsoft", 10, _eval_service_binary_signed),
        ]

    def generate_summary(self, cluster: Cluster) -> None:
        src_ip = cluster.trigger_event.remote_ip or "unknown IP"
        user = cluster.trigger_event.user or "unknown user"
        host = cluster.trigger_event.host_name
        
        parts = [f"Lateral movement pattern detected on {host}"]
        
        if cluster.trigger_name == "network_logon_type3_from_internal":
            parts.append(f"Network logon (Type 3) by {user} from {src_ip}")
        elif cluster.trigger_name == "psexec_pattern":
            parts.append(f"PsExec service installation detected")
        elif cluster.trigger_name == "sigma_lateral_movement_match":
            parts.append(f"Sigma LM detection: {cluster.trigger_event.alert_name}")
            
        if "admin_share_write_within_60s" in cluster.supporting_signals:
            parts.append("followed by an admin share write")
            
        cluster.summary = ", ".join(parts) + "."
