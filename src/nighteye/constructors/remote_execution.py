"""Remote Execution Constructor.

Detects TA0002 (Execution) techniques via remote mechanisms.
Constructs behavioral clusters for PsExec, WMI, PowerShell Remoting,
Scheduled Tasks, and Service-based remote execution.

References:
  - CONSTRUCTORS.md § 5.4
  - MITRE: TA0002, T1021.002, T1047, T1053, T1059, T1569
"""

from __future__ import annotations

from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import Cluster, Constructor, CounterSignal, SignalRule, TriggerRule

__all__ = ["RemoteExecutionConstructor"]

# ============================================================
# Trigger Evaluators
# ============================================================

def _is_psexec_usage(event: CanonicalEvent) -> bool:
    """Detect PsExec or similar remote execution tools."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        psexec_indicators = ["psexec", "paexec", "csexec", "remcom"]
        return any(ind in cmd for ind in psexec_indicators)
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "psexec" in name or "remote execution" in name
    return False


def _is_office_spawning_shell(event: CanonicalEvent) -> bool:
    """Detect Office app spawning a shell (macro-based execution)."""
    if event.canonical_type != CanonicalType.PROCESS_EXECUTION:
        return False
    parent = event.raw_data.get("process", {}).get("parent", {})
    parent_name = (parent.get("name") or "").lower()
    office_apps = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]
    if parent_name in office_apps:
        shell_procs = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]
        if (event.process_name or "").lower() in shell_procs:
            return True
    return False

def _is_wmi_remote(event: CanonicalEvent) -> bool:
    """Detect WMI remote execution (wmic /node:)."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        return "wmic" in cmd and "/node:" in cmd
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "wmi" in name and "remote" in name
    return False

def _is_powershell_remoting(event: CanonicalEvent) -> bool:
    """Detect PowerShell remoting (Enter-PSSession, Invoke-Command)."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        ps_remote = ["enter-pssession", "invoke-command", "new-pssession", "icm"]
        return any(ind in cmd for ind in ps_remote)
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "powershell remoting" in name or "winrm" in name
    return False

def _is_scheduled_task_remote(event: CanonicalEvent) -> bool:
    """Detect remote scheduled task creation."""
    if event.canonical_type == CanonicalType.SCHEDULED_TASK:
        # Event ID 4698 with remote characteristics
        return True
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "scheduled task" in name and "remote" in name
    return False

def _is_service_remote_install(event: CanonicalEvent) -> bool:
    """Detect remote service installation."""
    if event.canonical_type == CanonicalType.SERVICE_INSTALLATION:
        # Event ID 4697 or 7045 with remote source
        return True
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "service" in name and "remote" in name
    return False

def _is_winrm_activity(event: CanonicalEvent) -> bool:
    """Detect WinRM remote management activity."""
    if event.canonical_type == CanonicalType.NETWORK_CONNECTION:
        port = event.remote_port
        return port in (5985, 5986)  # WinRM HTTP/HTTPS
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "winrm" in name
    return False

# ============================================================
# Supporting Signal Evaluators
# ============================================================

def _eval_occurred_after_lateral_movement(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if remote execution occurred after lateral movement."""
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if "lateral" in name or "smb" in name or "rdp" in name:
                return True
    return False

def _eval_new_admin_share(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if new admin share was created."""
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if "admin$" in name or "c$" in name or "share" in name:
                return True
    return False

def _eval_executed_by_non_admin(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if executed by non-admin user."""
    user = cluster.trigger_event.user
    if user:
        user_lower = user.lower()
        admin_indicators = ["admin", "administrator", "domain admin", "enterprise admin"]
        return not any(ind in user_lower for ind in admin_indicators)
    return False

def _eval_malicious_payload(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if payload matches known malicious patterns."""
    for evt in context:
        if evt.canonical_type == CanonicalType.PROCESS_EXECUTION:
            cmd = evt.command_line.lower()
            malicious = ["-enc", "-encodedcommand", "invoke-expression", "iex", 
                        "downloadstring", "net.webclient", "bitsadmin", "certutil"]
            return any(m in cmd for m in malicious)
    return False

# ============================================================
# Counter Signal Evaluators
# ============================================================

def _eval_documented_sccm(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if this matches documented SCCM activity."""
    proc = cluster.trigger_event.process_name.lower()
    if proc in ["ccmexec.exe", "smsagenthost.exe"]:
        return True, "SCCM agent activity"
    return False, ""

def _eval_documented_puppet_chef(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if this matches documented Puppet/Chef activity."""
    proc = cluster.trigger_event.process_name.lower()
    if proc in ["puppet.exe", "chef-client.exe"]:
        return True, "Configuration management tool"
    return False, ""

def _eval_help_desk_remote_support(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if this matches help desk remote support."""
    proc = cluster.trigger_event.process_name.lower()
    support_tools = ["teamviewer.exe", "anydesk.exe", "screenconnect.exe", "bomgar.exe"]
    if proc in support_tools:
        return True, "Known remote support tool"
    return False, ""

# ============================================================
# Constructor
# ============================================================

class RemoteExecutionConstructor(Constructor):
    name = "RemoteExecution"
    mitre_tactic = "TA0002"
    mitre_techniques = ["T1021.002", "T1047", "T1053", "T1059", "T1569"]

    grouping_window_seconds = 1800  # 30 minutes
    group_by = ["host", "user"]

    @property
    def triggers(self) -> list[TriggerRule]:
        return [
            TriggerRule("office_spawning_shell", 45, _is_office_spawning_shell),
            TriggerRule("psexec_usage", 40, _is_psexec_usage),
            TriggerRule("wmi_remote_execution", 25, _is_wmi_remote),
            TriggerRule("powershell_remoting", 25, _is_powershell_remoting),
            TriggerRule("scheduled_task_remote", 15, _is_scheduled_task_remote),
            TriggerRule("service_remote_install", 15, _is_service_remote_install),
            TriggerRule("winrm_remote_management", 20, _is_winrm_activity),
        ]

    @property
    def supporting_signals(self) -> list[SignalRule]:
        return [
            SignalRule("occurred_after_lateral_movement", 12, _eval_occurred_after_lateral_movement),
            SignalRule("new_admin_share_created", 10, _eval_new_admin_share),
            SignalRule("executed_by_non_admin", 14, _eval_executed_by_non_admin),
            SignalRule("malicious_payload_detected", 14, _eval_malicious_payload),
        ]

    @property
    def counter_signals(self) -> list[CounterSignal]:
        return [
            CounterSignal("documented_sccm_activity", 12, _eval_documented_sccm),
            CounterSignal("documented_puppet_chef", 10, _eval_documented_puppet_chef),
            CounterSignal("help_desk_remote_support", 12, _eval_help_desk_remote_support),
        ]

    def generate_summary(self, cluster: Cluster) -> None:
        host = cluster.trigger_event.host_name
        trigger = cluster.trigger_name
        user = cluster.trigger_event.user or "unknown"
        cluster.summary = f"Remote execution detected on {host} by {user}: {trigger}. Possible lateral movement or remote administration."
