"""Defense Evasion Constructor.

Detects TA0005 (Defense Evasion) techniques.
Constructs behavioral clusters for AMSI bypass, ETW tampering,
EDR disablement, and process injection.

References:
  - CONSTRUCTORS.md § 5.5
  - MITRE: TA0005, T1027, T1055, T1070, T1078, T1562, T1562.001, T1562.002, T1562.004, T1564
"""

from __future__ import annotations

from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import Cluster, Constructor, CounterSignal, SignalRule, TriggerRule

__all__ = ["DefenseEvasionConstructor"]

# ============================================================
# Trigger Evaluators
# ============================================================

def _is_amsi_bypass(event: CanonicalEvent) -> bool:
    """Detect AMSI (Anti-Malware Scan Interface) bypass."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        amsi_indicators = [
            "amsi", "antimalware", "scan", "bypass",
            "[ref].assembly.gettype", "system.management.automation.amsiutils",
            "a'ms'i", "a`m`si", "amsiinitfailed"
        ]
        return any(ind in cmd for ind in amsi_indicators)
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "amsi" in name and ("bypass" in name or "tamper" in name)
    return False

def _is_etw_tamper(event: CanonicalEvent) -> bool:
    """Detect ETW (Event Tracing for Windows) tampering."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        etw_indicators = [
            "etw", "eventtracing", "nttraceevent", "e tw",
            "patch etw", "disable etw", "etwbypass"
        ]
        return any(ind in cmd for ind in etw_indicators)
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "etw" in name and ("tamper" in name or "disable" in name)
    return False

def _is_edr_disable(event: CanonicalEvent) -> bool:
    """Detect EDR/AV disablement."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        edr_indicators = [
            "defender", "disable", "exclusion", "mppreference",
            "set-mppreference", "add-mppreference", "tamperprotection",
            "real-time protection", "disableav", "killav"
        ]
        return any(ind in cmd for ind in edr_indicators)
    if event.canonical_type == CanonicalType.REGISTRY_MODIFICATION:
        key = event.registry_key or ""
        return "windows defender" in key.lower() and "disable" in key.lower()
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return any(k in name for k in ["defender", "edr", "av disable", "tamper"])
    return False

def _is_process_injection(event: CanonicalEvent) -> bool:
    """Detect process injection patterns."""
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "process injection" in name or "process hollowing" in name or "apc injection" in name
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        injection_indicators = [
            "virtualallocex", "writeprocessmemory", "createremotethread",
            "ntunmapviewofsection", "setthreadcontext", "resume thread"
        ]
        return any(ind in cmd for ind in injection_indicators)
    return False

def _is_masquerading(event: CanonicalEvent) -> bool:
    """Detect process masquerading."""
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "masquerading" in name or "right-to-left" in name or "spoofed" in name
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        # Check for process name mismatch with image path
        proc_name = event.process_name or ""
        proc_path = event.process_path or ""
        if proc_name and proc_path:
            # e.g., svchost.exe running from non-system32
            if "svchost" in proc_name.lower() and "system32" not in proc_path.lower():
                return True
    return False

def _is_uac_bypass(event: CanonicalEvent) -> bool:
    """Detect UAC bypass techniques."""
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "uac bypass" in name or "elevation" in name
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        uac_indicators = [
            "fodhelper", "computerdefaults", "sdclt", "eventvwr",
            "cleanmgr", "diskcleanup", "slui", "delegateexecute"
        ]
        return any(ind in cmd for ind in uac_indicators)
    return False

def _is_sigma_defense_evasion(event: CanonicalEvent) -> bool:
    """Detect sigma rule match for defense evasion."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "defense evasion" in name or "ta0005" in name

# ============================================================
# Supporting Signal Evaluators
# ============================================================

def _eval_occurred_after_initial_access(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if defense evasion occurred after initial access."""
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if "initial access" in name or "lateral" in name or "execution" in name:
                return True
    return False

def _eval_malicious_tool_present(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if known malicious tool is present."""
    for evt in context:
        if evt.canonical_type == CanonicalType.PROCESS_EXECUTION:
            proc = evt.process_name.lower()
            malicious = ["mimikatz.exe", "cobaltstrike", "metasploit", "powersploit"]
            if proc in malicious:
                return True
    return False

def _eval_persistence_mechanism_present(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if persistence mechanism co-occurs."""
    for evt in context:
        if evt.canonical_type in (CanonicalType.REGISTRY_MODIFICATION, CanonicalType.SERVICE_INSTALLATION, CanonicalType.SCHEDULED_TASK):
            return True
    return False

def _eval_memory_manipulation(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if memory manipulation APIs were used."""
    for evt in context:
        if evt.canonical_type == CanonicalType.PROCESS_EXECUTION:
            cmd = evt.command_line.lower()
            mem_apis = ["virtualalloc", "virtualprotect", "writeprocessmemory", "readprocessmemory"]
            if any(api in cmd for api in mem_apis):
                return True
    return False

# ============================================================
# Counter Signal Evaluators
# ============================================================

def _eval_documented_software_install(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if this matches documented software installation."""
    proc = cluster.trigger_event.process_name.lower()
    if proc in ["msiexec.exe", "setup.exe", "install.exe"]:
        return True, "Software installer activity"
    return False, ""

def _eval_system_update(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if this matches system update."""
    proc = cluster.trigger_event.process_name.lower()
    if proc in ["wuauclt.exe", "usoclient.exe", "trustedinstaller.exe"]:
        return True, "Windows Update component"
    return False, ""

def _eval_legitimate_admin_tool(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if this matches legitimate admin tool."""
    proc = cluster.trigger_event.process_name.lower()
    admin_tools = ["psexec.exe", "pskill.exe", "pslist.exe"]
    if proc in admin_tools:
        return True, "Sysinternals admin tool"
    return False, ""

# ============================================================
# Constructor
# ============================================================

class DefenseEvasionConstructor(Constructor):
    name = "DefenseEvasion"
    mitre_tactic = "TA0005"
    mitre_techniques = ["T1027", "T1055", "T1070", "T1078", "T1562", "T1562.001", "T1562.002", "T1562.004", "T1564"]

    grouping_window_seconds = 1800  # 30 minutes
    group_by = ["host", "user"]

    @property
    def triggers(self) -> list[TriggerRule]:
        return [
            TriggerRule("amsi_bypass", 55, _is_amsi_bypass),
            TriggerRule("etw_tamper", 50, _is_etw_tamper),
            TriggerRule("edr_disable", 50, _is_edr_disable),
            TriggerRule("process_injection", 50, _is_process_injection),
            TriggerRule("process_masquerading", 45, _is_masquerading),
            TriggerRule("uac_bypass", 45, _is_uac_bypass),
            TriggerRule("sigma_defense_evasion", 40, _is_sigma_defense_evasion),
        ]

    @property
    def supporting_signals(self) -> list[SignalRule]:
        return [
            SignalRule("occurred_after_initial_access", 12, _eval_occurred_after_initial_access),
            SignalRule("malicious_tool_present", 14, _eval_malicious_tool_present),
            SignalRule("persistence_mechanism_present", 10, _eval_persistence_mechanism_present),
            SignalRule("memory_manipulation_apis", 12, _eval_memory_manipulation),
        ]

    @property
    def counter_signals(self) -> list[CounterSignal]:
        return [
            CounterSignal("documented_software_install", 10, _eval_documented_software_install),
            CounterSignal("system_update", 12, _eval_system_update),
            CounterSignal("legitimate_admin_tool", 10, _eval_legitimate_admin_tool),
        ]

    def generate_summary(self, cluster: Cluster) -> None:
        host = cluster.trigger_event.host_name
        trigger = cluster.trigger_name
        user = cluster.trigger_event.user or "unknown"
        cluster.summary = f"Defense evasion detected on {host} by {user}: {trigger}. Possible anti-forensic or anti-detection activity."
