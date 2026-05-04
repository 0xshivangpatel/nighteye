"""Defense Evasion Constructor.

Detects TA0005 (Defense Evasion) techniques.
Constructs behavioral clusters for AMSI bypass, ETW tampering,
EDR disablement, and process injection.

References:
  - CONSTRUCTORS.md § 5.5
  - MITRE: TA0005, T1027, T1055, T1070, T1078, T1562, T1562.001, T1562.002, T1562.004, T1564
"""

from __future__ import annotations

import re
from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import Cluster, Constructor, CounterSignal, SignalRule, TriggerRule

__all__ = ["DefenseEvasionConstructor"]

# ============================================================
# Trigger Evaluators
#
# Pattern guidance: substring matchers fired against `command_line`
# routinely false-positive on benign file paths and EVTX descriptions
# that happen to contain short tokens like "etw", "Network", or
# "disable". Every matcher below uses regex word boundaries plus a
# verb/intent context so that "Network and Internet.lnk" does not
# trigger ETW tampering and "DisableNotifications.txt" does not trigger
# EDR disablement.
# ============================================================

# Patterns are pre-compiled for speed since they run over every event.
_AMSI_BYPASS_RE = re.compile(
    r"\b(?:"
    r"amsiinitfailed|amsiutils|amsiscanbuffer|amscontext|"
    r"\[ref\]\.assembly\.gettype|"
    r"system\.management\.automation\.amsiutils|"
    r"amsi\s*(?:bypass|patch|disable|hook)|"
    r"a['`]?m['`]?s['`]?i"
    r")\b",
    re.IGNORECASE,
)
_OBFUSCATED_PS_RE = re.compile(
    r"(?:^|\s)-(?:enc|encodedcommand|e)\b|"
    r"\bfrombase64string\b|"
    r"\binvoke-expression\s+\(.{40,}\)|"
    r"\biex\s*\(\s*\[",
    re.IGNORECASE,
)
_ETW_TAMPER_RE = re.compile(
    r"\b(?:"
    r"etweventwrite|etweventregister|etwregister|etwreplacefunction|"
    r"nttraceevent|etwbypass|etwti|"
    r"(?:patch|disable|hook|bypass|nop|kill)\s+etw|"
    r"etw\s+(?:patch|disable|hook|bypass|tamper)"
    r")\b",
    re.IGNORECASE,
)
_EDR_DISABLE_CMD_RE = re.compile(
    r"\b(?:"
    r"set-mppreference|add-mppreference|"
    r"disable\w*\s+(?:windows\s+)?defender|"
    r"defender\s+(?:disable|stop|exclusion|exclude|tamper)|"
    r"disablerealtimemonitoring|"
    r"tamperprotection\s*(?:0|off|false|disable)|"
    r"real-time\s+protection\s+(?:off|disable)|"
    r"sc\s+(?:stop|delete|config)\s+(?:windefend|sense|wdnissvc|sentinelagent)|"
    r"net\s+stop\s+(?:windefend|sense|wdnissvc|sentinelagent)|"
    r"taskkill[^\n]+(?:msmpeng|sentinelagent|csagent|cyloprotectsvc)|"
    r"killav|disableav"
    r")\b",
    re.IGNORECASE,
)
_EDR_DISABLE_REG_RE = re.compile(
    r"(?:windows\s+defender|microsoft\\windows\s+defender|"
    r"securityhealthservice|sense|windefend)\b.*\b(?:disable|tamperprotection)",
    re.IGNORECASE,
)
_PROCESS_INJECTION_RE = re.compile(
    r"\b(?:"
    r"virtualallocex|writeprocessmemory|createremotethread|"
    r"ntunmapviewofsection|setthreadcontext|queueuserapc|"
    r"ntmapviewofsection|reflectiveloader"
    r")\b",
    re.IGNORECASE,
)
_UAC_BYPASS_RE = re.compile(
    r"\b(?:"
    r"fodhelper(?:\.exe)?|computerdefaults(?:\.exe)?|sdclt(?:\.exe)?|"
    r"eventvwr(?:\.exe)?|cleanmgr(?:\.exe)?|slui(?:\.exe)?|"
    r"delegateexecute|wsreset(?:\.exe)?|cmstp(?:\.exe)?"
    r")\b",
    re.IGNORECASE,
)


def _is_amsi_bypass(event: CanonicalEvent) -> bool:
    """Detect AMSI (Anti-Malware Scan Interface) bypass."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line or ""
        if not cmd:
            return False
        return bool(_AMSI_BYPASS_RE.search(cmd))
    if event.canonical_type == CanonicalType.ALERT:
        name = (event.alert_name or "").lower()
        return "amsi" in name and ("bypass" in name or "tamper" in name)
    return False


def _is_obfuscated_powershell(event: CanonicalEvent) -> bool:
    """Detect obfuscated/encoded PowerShell commands."""
    if event.canonical_type != CanonicalType.PROCESS_EXECUTION:
        return False
    proc = (event.process_name or "").lower()
    cmd = event.command_line or ""
    if "powershell" not in proc and "pwsh" not in proc:
        return False
    if not cmd:
        return False
    return bool(_OBFUSCATED_PS_RE.search(cmd))


def _is_etw_tamper(event: CanonicalEvent) -> bool:
    """Detect ETW (Event Tracing for Windows) tampering."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line or ""
        if not cmd:
            return False
        return bool(_ETW_TAMPER_RE.search(cmd))
    if event.canonical_type == CanonicalType.ALERT:
        name = (event.alert_name or "").lower()
        return "etw" in name and ("tamper" in name or "disable" in name or "patch" in name)
    return False


def _is_edr_disable(event: CanonicalEvent) -> bool:
    """Detect EDR/AV disablement."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line or ""
        if not cmd:
            return False
        return bool(_EDR_DISABLE_CMD_RE.search(cmd))
    if event.canonical_type == CanonicalType.REGISTRY_MODIFICATION:
        key = event.registry_key or ""
        if not key:
            return False
        return bool(_EDR_DISABLE_REG_RE.search(key))
    if event.canonical_type == CanonicalType.ALERT:
        name = (event.alert_name or "").lower()
        return any(k in name for k in ["defender disable", "edr disable", "av disable", "tamper protection"])
    return False


def _is_process_injection(event: CanonicalEvent) -> bool:
    """Detect process injection patterns."""
    if event.canonical_type == CanonicalType.ALERT:
        name = (event.alert_name or "").lower()
        return "process injection" in name or "process hollowing" in name or "apc injection" in name
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line or ""
        if not cmd:
            return False
        return bool(_PROCESS_INJECTION_RE.search(cmd))
    return False


def _is_masquerading(event: CanonicalEvent) -> bool:
    """Detect process masquerading."""
    if event.canonical_type == CanonicalType.ALERT:
        name = (event.alert_name or "").lower()
        return "masquerading" in name or "right-to-left" in name or "spoofed" in name
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        proc_name = (event.process_name or "").lower()
        proc_path = (event.process_path or "").lower()
        if not proc_name or not proc_path:
            return False
        # svchost.exe outside System32 → almost always malicious masquerade.
        if proc_name == "svchost.exe" and "system32" not in proc_path:
            return True
        # lsass.exe outside System32, conhost outside System32, etc.
        if proc_name in {"lsass.exe", "smss.exe", "csrss.exe", "wininit.exe", "services.exe"}:
            if "system32" not in proc_path:
                return True
    return False


def _is_uac_bypass(event: CanonicalEvent) -> bool:
    """Detect UAC bypass techniques.

    Note: matches the *bypass tooling binary names* in the command line.
    Just running cleanmgr.exe is fine; we only fire when one of these
    binaries is named in a command-line context (which usually means an
    autoElevate hijack chain).
    """
    if event.canonical_type == CanonicalType.ALERT:
        name = (event.alert_name or "").lower()
        return "uac bypass" in name or "auto elevation" in name
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line or ""
        if not cmd:
            return False
        # Only fire when the bypass binary is being launched WITH another
        # command (e.g. registry write to DelegateExecute), not when it's
        # the only thing on the line.
        if not _UAC_BYPASS_RE.search(cmd):
            return False
        # Heuristic: real bypass chains usually involve a registry write
        # or cmd.exe spawn alongside the bypass binary.
        return bool(re.search(r"\b(?:reg\s+add|delegateexecute|hkcu|hkey_current_user|cmd\s+/c)\b", cmd, re.IGNORECASE))
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
        # Base scores lowered so a single trigger without supporting context
        # lands in WEAK (20-39) rather than auto-MODERATE.  Supporting signals
        # (+10 to +14 each) push clusters into MODERATE / STRONG.
        return [
            TriggerRule("obfuscated_powershell", 30, _is_obfuscated_powershell),
            TriggerRule("amsi_bypass", 35, _is_amsi_bypass),
            TriggerRule("etw_tamper", 28, _is_etw_tamper),
            TriggerRule("edr_disable", 35, _is_edr_disable),
            TriggerRule("process_injection", 30, _is_process_injection),
            TriggerRule("process_masquerading", 25, _is_masquerading),
            TriggerRule("uac_bypass", 28, _is_uac_bypass),
            TriggerRule("sigma_defense_evasion", 30, _is_sigma_defense_evasion),
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
