"""Lateral Movement Constructor.

Detects TA0008 (Lateral Movement) techniques.
Constructs behavioral clusters for RDP, SMB, WMI, PsExec,
PowerShell Remoting, and SSH lateral movement.

References:
  - CONSTRUCTORS.md § 5.1
  - MITRE: TA0008, T1021, T1021.001, T1021.002, T1021.003, T1021.004, T1021.006, T1091, T1210
"""

from __future__ import annotations

from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import Cluster, Constructor, CounterSignal, SignalRule, TriggerRule

__all__ = ["LateralMovementConstructor"]

# ============================================================
# Trigger Evaluators
# ============================================================

def _is_network_logon_type3(event: CanonicalEvent) -> bool:
    """Detect Network Logon (Type 3) from internal IP."""
    if event.canonical_type == CanonicalType.AUTHENTICATION:
        logon_type = event.raw_data.get("winlog", {}).get("event_data", {}).get("LogonType", "")
        if str(logon_type) == "3":
            return True
    return False

def _is_rdp_logon(event: CanonicalEvent) -> bool:
    """Detect RDP logon events."""
    if event.canonical_type == CanonicalType.AUTHENTICATION:
        # Event ID 4624 with LogonType 10 (RemoteInteractive)
        logon_type = event.raw_data.get("winlog", {}).get("event_data", {}).get("LogonType", "")
        return str(logon_type) == "10"
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "rdp" in name and ("logon" in name or "connection" in name)
    return False

def _is_smb_admin_share_write(event: CanonicalEvent) -> bool:
    """Detect write to admin share (C$, ADMIN$)."""
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "admin share" in name or "c$" in name or "admin$" in name
    if event.canonical_type == CanonicalType.FILE_CREATION:
        path = event.target_file.lower()
        return "admin$" in path or "c$" in path or any(share in path for share in ["\\c$", "\\admin$"])
    return False

def _is_wmi_remote(event: CanonicalEvent) -> bool:
    """Detect WMI remote execution."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        return "wmic" in cmd and "/node:" in cmd
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "wmi" in name and "remote" in name
    return False

def _is_psexec_usage(event: CanonicalEvent) -> bool:
    """Detect PsExec or similar remote execution."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        psexec_indicators = ["psexec", "paexec", "csexec", "remcom", "smbexec"]
        return any(ind in cmd for ind in psexec_indicators)
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "psexec" in name or "smbexec" in name
    return False

def _is_powershell_remoting(event: CanonicalEvent) -> bool:
    """Detect PowerShell remoting."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        ps_remote = ["enter-pssession", "invoke-command", "new-pssession", "icm -computername"]
        return any(ind in cmd for ind in ps_remote)
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "powershell remoting" in name or "winrm" in name
    return False

def _is_ssh_lateral(event: CanonicalEvent) -> bool:
    """Detect SSH-based lateral movement."""
    if event.canonical_type == CanonicalType.NETWORK_CONNECTION:
        port = event.remote_port
        return port == 22
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "ssh" in name and ("lateral" in name or "tunnel" in name)
    return False

def _is_pass_the_hash(event: CanonicalEvent) -> bool:
    """Detect Pass-the-Hash or Pass-the-Ticket."""
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "pass the hash" in name or "pass the ticket" in name or "mimikatz" in name
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        return "sekurlsa::pth" in cmd or "sekurlsa::tickets" in cmd
    return False

def _is_new_service_remote(event: CanonicalEvent) -> bool:
    """Detect new service created remotely."""
    if event.canonical_type == CanonicalType.SERVICE_INSTALLATION:
        # Event ID 4697 or 7045 with remote characteristics
        return True
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "service" in name and "remote" in name
    return False

def _is_scheduled_task_remote(event: CanonicalEvent) -> bool:
    """Detect scheduled task created remotely."""
    if event.canonical_type == CanonicalType.SCHEDULED_TASK:
        return True
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "scheduled task" in name and "remote" in name
    return False

# ============================================================
# Supporting Signal Evaluators
# ============================================================

def _eval_new_admin_account(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if new admin account was created."""
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if "new account" in name and "admin" in name:
                return True
    return False

def _eval_tools_dropped_on_target(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if tools were dropped on target host."""
    for evt in context:
        if evt.canonical_type == CanonicalType.FILE_CREATION:
            path = evt.target_file.lower()
            tool_indicators = [".exe", ".dll", ".ps1", ".bat", ".cmd"]
            if any(ind in path for ind in tool_indicators):
                return True
    return False

def _eval_target_not_previously_accessed(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if target host was not previously accessed by same user.

    Heuristic: among the supplied context events for this host, look for
    AUTHENTICATION events by the same user that PREDATE the trigger
    event by more than 24h. If none exist, the target appears 'new' to
    this user and the signal applies. Without a real long-window
    baseline this is necessarily approximate, so we are conservative —
    return False (signal does NOT apply) when in doubt rather than
    biasing every cluster upward.
    """
    user = cluster.trigger_event.user
    host = cluster.trigger_event.host_name
    trigger_ts = cluster.trigger_event.timestamp
    if not user or not host or not trigger_ts:
        return False

    from datetime import datetime, timedelta, timezone

    def _parse(ts: str):
        try:
            norm = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
            dt = datetime.fromisoformat(norm)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError, AttributeError):
            return None

    trig_dt = _parse(trigger_ts)
    if trig_dt is None:
        return False
    threshold = trig_dt - timedelta(hours=24)

    # Look for the same user authenticating to the same host BEFORE the
    # threshold. If found, this is a recurring user and the "not
    # previously accessed" signal does NOT apply.
    for evt in context:
        if evt.canonical_type != CanonicalType.AUTHENTICATION:
            continue
        if evt.host_name != host or evt.user != user:
            continue
        evt_dt = _parse(evt.timestamp)
        if evt_dt is None:
            continue
        if evt_dt < threshold:
            return False
    # No prior authentication found within context — treat as new access.
    return True

def _eval_occurred_after_initial_compromise(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if lateral movement occurred after initial compromise."""
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if "initial access" in name or "compromise" in name or "execution" in name:
                return True
    return False

def _eval_source_host_has_other_attack_signals(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if source host has other attack signals."""
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if any(k in name for k in ["persistence", "credential", "defense evasion"]):
                return True
    return False

# ============================================================
# Counter Signal Evaluators
# ============================================================

def _eval_documented_jump_server(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if source is documented jump server."""
    host = cluster.trigger_event.host_name.lower()
    if any(js in host for js in ["jump", "bastion", "gateway", "rdp-gw"]):
        return True, "Documented jump server"
    return False, ""

def _eval_sccm_puppet_action(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if this matches SCCM/Puppet action."""
    proc = cluster.trigger_event.process_name.lower()
    if proc in ["ccmexec.exe", "puppet.exe", "chef-client.exe"]:
        return True, "Configuration management tool"
    return False, ""

def _eval_help_desk_remote_support(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if this matches help desk remote support."""
    proc = cluster.trigger_event.process_name.lower()
    support_tools = ["teamviewer.exe", "anydesk.exe", "screenconnect.exe", "bomgar.exe"]
    if proc in support_tools:
        return True, "Known remote support tool"
    return False, ""

def _eval_user_documented_it_admin(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if user is documented IT admin."""
    user = cluster.trigger_event.user
    if user:
        user_lower = user.lower()
        if any(admin in user_lower for admin in ["admin", "it-", "helpdesk", "support"]):
            return True, "Documented IT admin user"
    return False, ""

# ============================================================
# Constructor
# ============================================================

class LateralMovementConstructor(Constructor):
    name = "LateralMovement"
    mitre_tactic = "TA0008"
    mitre_techniques = ["T1021", "T1021.001", "T1021.002", "T1021.003", "T1021.004", "T1021.006", "T1091", "T1210"]

    grouping_window_seconds = 1800  # 30 minutes
    group_by = ["source_host", "destination_host"]

    @property
    def triggers(self) -> list[TriggerRule]:
        return [
            TriggerRule("network_logon_type3_from_internal", 30, _is_network_logon_type3),
            TriggerRule("rdp_logon", 45, _is_rdp_logon),
            TriggerRule("smb_admin_share_write", 50, _is_smb_admin_share_write),
            TriggerRule("wmi_remote_execution", 45, _is_wmi_remote),
            TriggerRule("psexec_usage", 50, _is_psexec_usage),
            TriggerRule("powershell_remoting", 45, _is_powershell_remoting),
            TriggerRule("ssh_lateral", 40, _is_ssh_lateral),
            TriggerRule("pass_the_hash_ticket", 55, _is_pass_the_hash),
            TriggerRule("new_service_remote", 40, _is_new_service_remote),
            TriggerRule("scheduled_task_remote", 40, _is_scheduled_task_remote),
        ]

    @property
    def supporting_signals(self) -> list[SignalRule]:
        return [
            SignalRule("new_admin_account", 12, _eval_new_admin_account),
            SignalRule("tools_dropped_on_target", 14, _eval_tools_dropped_on_target),
            SignalRule("target_not_previously_accessed", 10, _eval_target_not_previously_accessed),
            SignalRule("occurred_after_initial_compromise", 12, _eval_occurred_after_initial_compromise),
            SignalRule("source_host_has_other_attack_signals", 12, _eval_source_host_has_other_attack_signals),
        ]

    @property
    def counter_signals(self) -> list[CounterSignal]:
        return [
            CounterSignal("documented_jump_server", 12, _eval_documented_jump_server),
            CounterSignal("sccm_puppet_action", 10, _eval_sccm_puppet_action),
            CounterSignal("help_desk_remote_support", 12, _eval_help_desk_remote_support),
            CounterSignal("user_documented_it_admin", 10, _eval_user_documented_it_admin),
        ]

    def generate_summary(self, cluster: Cluster) -> None:
        host = cluster.trigger_event.host_name
        trigger = cluster.trigger_name
        user = cluster.trigger_event.user or "unknown"
        remote_ip = cluster.trigger_event.remote_ip or "unknown"
        signals = ", ".join(cluster.supporting_signals) if cluster.supporting_signals else "none"
        cluster.summary = (
            f"Lateral movement detected on {host} by {user} "
            f"from {remote_ip}: {trigger}. "
            f"Supporting signals: {signals}. "
            f"Possible host-to-host propagation."
        )
