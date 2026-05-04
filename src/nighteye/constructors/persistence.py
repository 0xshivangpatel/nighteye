"""Persistence Constructor.

Detects TA0003 (Persistence) techniques.
Constructs behavioral clusters for registry run keys, scheduled tasks,
WMI event subscriptions, services, and startup folders.

References:
  - CONSTRUCTORS.md § 5.2
  - MITRE: TA0003, T1053, T1058, T1060, T1078, T1098, T1100, T1136, T1543, T1546, T1547
"""

from __future__ import annotations

from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import Cluster, Constructor, CounterSignal, SignalRule, TriggerRule

__all__ = ["PersistenceConstructor"]

# ============================================================
# Trigger Evaluators
# ============================================================

def _is_registry_run_key(event: CanonicalEvent) -> bool:
    """Detect registry run key modification."""
    if event.canonical_type == CanonicalType.REGISTRY_MODIFICATION:
        key = event.registry_key or ""
        run_keys = [
            "\\run\\", "\\runonce\\", "\\runonceex\\",
            "\\startupapproved\\", "\\user shell folders\\",
            "\\load\\", "\\winlogon\\shell",
        ]
        return any(rk in key.lower() for rk in run_keys)
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "run key" in name or "registry run" in name
    return False

def _is_scheduled_task_creation(event: CanonicalEvent) -> bool:
    """Detect scheduled task creation."""
    if event.canonical_type == CanonicalType.SCHEDULED_TASK:
        return True
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "scheduled task" in name and "created" in name
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        return "schtasks" in cmd and "/create" in cmd
    return False

def _is_wmi_event_subscription(event: CanonicalEvent) -> bool:
    """Detect WMI event subscription."""
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "wmi" in name and "subscription" in name
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        return "wmi" in cmd and ("event" in cmd or "subscription" in cmd)
    return False

def _is_service_install(event: CanonicalEvent) -> bool:
    """Detect service installation."""
    if event.canonical_type == CanonicalType.SERVICE_INSTALLATION:
        return True
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "service" in name and "install" in name
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        return "sc create" in cmd or "sc config" in cmd or "new-service" in cmd
    return False

def _is_startup_folder(event: CanonicalEvent) -> bool:
    """Detect startup folder modification."""
    if event.canonical_type == CanonicalType.FILE_CREATION:
        path = event.target_file.lower()
        startup_paths = [
            "\\startup\\", "\\programs\\startup\\",
            "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup",
        ]
        return any(sp in path for sp in startup_paths)
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "startup" in name and "folder" in name
    return False

def _is_bits_job_persistence(event: CanonicalEvent) -> bool:
    """Detect BITS job for persistence."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        return "bitsadmin" in cmd and ("/addfile" in cmd or "/setnotifycmdline" in cmd)
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "bits" in name and "persistence" in name
    return False

def _is_dll_search_order_hijacking(event: CanonicalEvent) -> bool:
    """Detect DLL search order hijacking."""
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "dll hijacking" in name or "search order" in name
    if event.canonical_type == CanonicalType.FILE_CREATION:
        path = event.target_file.lower()
        return path.endswith(".dll") and any(sys in path for sys in ["system32", "syswow64"])
    return False

# ============================================================
# Supporting Signal Evaluators
# ============================================================

def _eval_executable_unsigned(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if persistence executable is unsigned."""
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if "unsigned" in name:
                return True
    return False

def _eval_executable_in_temp(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if persistence executable is in temp directory."""
    for evt in context:
        path = (evt.target_file or "").lower()
        if "\\temp\\" in path or "\\tmp\\" in path:
            return True
    return False

def _eval_hidden_or_system_attribute(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if file has hidden or system attribute."""
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if "hidden" in name or "system attribute" in name:
                return True
    return False

def _eval_no_corresponding_installer(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if no corresponding installer exists."""
    # Would check for msiexec or setup.exe in temporal proximity
    has_installer = False
    for evt in context:
        if evt.canonical_type == CanonicalType.PROCESS_EXECUTION:
            proc = evt.process_name.lower()
            if proc in ["msiexec.exe", "setup.exe", "install.exe"]:
                has_installer = True
                break
    return not has_installer

# ============================================================
# Counter Signal Evaluators
# ============================================================

def _eval_signed_by_known_publisher(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if executable is signed by known publisher."""
    # Would verify signature in production
    return False, ""

def _eval_documented_software_install(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if this matches documented software installation."""
    proc = cluster.trigger_event.process_name.lower()
    if proc in ["msiexec.exe", "setup.exe", "install.exe"]:
        return True, "Software installer activity"
    return False, ""

def _eval_gpo_deployment(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if this matches GPO deployment."""
    # Would check for GPO-related context
    return False, ""

# ============================================================
# Constructor
# ============================================================

class PersistenceConstructor(Constructor):
    name = "Persistence"
    mitre_tactic = "TA0003"
    mitre_techniques = ["T1053", "T1058", "T1060", "T1078", "T1098", "T1100", "T1136", "T1543", "T1546", "T1547"]

    grouping_window_seconds = 1800  # 30 minutes
    group_by = ["host", "user"]

    @property
    def triggers(self) -> list[TriggerRule]:
        return [
            TriggerRule("registry_run_key", 20, _is_registry_run_key),
            TriggerRule("scheduled_task_creation", 15, _is_scheduled_task_creation),
            TriggerRule("wmi_event_subscription", 25, _is_wmi_event_subscription),
            TriggerRule("service_install", 15, _is_service_install),
            TriggerRule("startup_folder", 20, _is_startup_folder),
            TriggerRule("bits_job_persistence", 20, _is_bits_job_persistence),
            TriggerRule("dll_search_order_hijacking", 25, _is_dll_search_order_hijacking),
        ]

    @property
    def supporting_signals(self) -> list[SignalRule]:
        return [
            SignalRule("executable_unsigned", 12, _eval_executable_unsigned),
            SignalRule("executable_in_temp", 10, _eval_executable_in_temp),
            SignalRule("hidden_or_system_attribute", 10, _eval_hidden_or_system_attribute),
            SignalRule("no_corresponding_installer", 10, _eval_no_corresponding_installer),
        ]

    @property
    def counter_signals(self) -> list[CounterSignal]:
        return [
            CounterSignal("signed_by_known_publisher", 12, _eval_signed_by_known_publisher),
            CounterSignal("documented_software_install", 10, _eval_documented_software_install),
            CounterSignal("gpo_deployment", 10, _eval_gpo_deployment),
        ]

    def generate_summary(self, cluster: Cluster) -> None:
        host = cluster.trigger_event.host_name
        trigger = cluster.trigger_name
        user = cluster.trigger_event.user or "unknown"
        cluster.summary = f"Persistence detected on {host} by {user}: {trigger}. Possible foothold establishment."
