"""Credential Access Constructor.

Detects TA0006 (Credential Access) techniques.
Constructs behavioral clusters for LSASS dumping, SAM extraction,
Kerberoasting, and credential harvesting.

References:
  - CONSTRUCTORS.md § 5.3
  - MITRE: TA0006, T1003, T1003.001, T1003.002, T1003.003, T1003.004, T1003.005, T1003.006, T1558, T1558.003
"""

from __future__ import annotations

from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import Cluster, Constructor, CounterSignal, SignalRule, TriggerRule
from nighteye.constructors.counter_evidence import counter_known_good_hash, counter_system_legitimate_path, counter_high_frequency_baseline

__all__ = ["CredentialAccessConstructor"]

# ============================================================
# Trigger Evaluators
# ============================================================

def _is_lsass_access(event: CanonicalEvent) -> bool:
    """Detect LSASS memory access or dump."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        lsass_indicators = [
            "lsass", "procdump", "rundll32", "comsvcs.dll", "minidump",
            "mimikatz", "sekurlsa", "logonpasswords", "dump::", "sekurlsa::logonpasswords"
        ]
        return any(ind in cmd for ind in lsass_indicators)
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "lsass" in name or "credential dump" in name or "mimikatz" in name
    return False

_HIVE_BASENAMES = frozenset({
    "sam", "system", "security", "software",
    "sam.save", "system.save", "security.save", "software.save",
    "sam.hive", "system.hive", "security.hive", "software.hive",
    "sam.bak", "system.bak", "security.bak", "software.bak",
    "sam.old", "system.old", "security.old", "software.old",
})


def _path_basename(path: str) -> str:
    """Return the file basename for either Windows or POSIX paths."""
    if not path:
        return ""
    p = path.lower().replace("\\", "/")
    return p.rsplit("/", 1)[-1]


def _is_sam_hive_copy(event: CanonicalEvent) -> bool:
    """Detect SAM/SYSTEM/SECURITY hive copy.

    Tight matching:
      - FILE_CREATION: basename must be exactly one of the registry hive
        files (with optional .save/.hive/.bak/.old suffix). Substring
        matching on path explodes false positives because "sam" matches
        "samples", "samba", "username", etc., and ``system`` + ``config``
        appear in every path under ``\\Windows\\System32\\``.
      - PROCESS_EXECUTION: command line must invoke ``reg save`` or
        ``ntds.dit`` extraction tooling.
      - ALERT: explicit hive-related alert name.
    """
    if event.canonical_type == CanonicalType.FILE_CREATION:
        basename = _path_basename(event.target_file)
        if basename in _HIVE_BASENAMES:
            return True
        # Allow "ntds.dit" extraction copies as well.
        return basename in ("ntds.dit", "ntds.dit.save", "ntds.dit.bak")
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        # Tight cmdline matching — must look like an actual save/copy.
        if "reg save" in cmd or "reg.exe save" in cmd:
            return True
        if "ntds.dit" in cmd or "ntdsutil" in cmd:
            return True
        if "vssadmin" in cmd and "create" in cmd and "shadow" in cmd:
            return True
        return False
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "sam hive" in name or "registry hive" in name
    return False

def _is_kerberoast(event: CanonicalEvent) -> bool:
    """Detect Kerberoasting activity."""
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "kerberoast" in name or "kerberos" in name and "ticket" in name
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        return "kerberoast" in cmd or "get-userprincipalname" in cmd
    return False

def _is_ntds_dump(event: CanonicalEvent) -> bool:
    """Detect NTDS.dit extraction."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        ntds_indicators = ["ntds.dit", "ntdsutil", "vssadmin", "diskshadow"]
        return any(ind in cmd for ind in ntds_indicators)
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "ntds" in name or "domain dump" in name
    return False

def _is_password_spray(event: CanonicalEvent) -> bool:
    """Detect password spray or brute force."""
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "password spray" in name or "brute force" in name or "failed logon" in name
    return False

def _is_credvault_access(event: CanonicalEvent) -> bool:
    """Detect Windows Credential Manager access."""
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "credential vault" in name or "vault" in name and "credential" in name
    return False

def _is_dpapi_extraction(event: CanonicalEvent) -> bool:
    """Detect DPAPI key extraction."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        return "dpapi" in cmd or "cryptunprotectdata" in cmd
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "dpapi" in name
    return False

# ============================================================
# Supporting Signal Evaluators
# ============================================================

def _eval_occurred_after_initial_access(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if credential access occurred after initial access."""
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if "initial access" in name or "lateral" in name:
                return True
    return False

def _eval_domain_admin_target(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if domain admin accounts were targeted."""
    for evt in context:
        user = evt.user or ""
        if any(admin in user.lower() for admin in ["domain admin", "enterprise admin", "administrator"]):
            return True
    return False

def _eval_lsass_dump_tool_present(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if known LSASS dump tool is present."""
    for evt in context:
        if evt.canonical_type == CanonicalType.PROCESS_EXECUTION:
            proc = evt.process_name.lower()
            if proc in ["procdump.exe", "mimikatz.exe", "rundll32.exe"]:
                return True
    return False

def _eval_occurred_during_lateral_movement(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if credential access co-occurs with lateral movement."""
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if "lateral" in name or "smb" in name or "rdp" in name:
                return True
    return False

# ============================================================
# Counter Signal Evaluators
# ============================================================

def _eval_documented_security_audit(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if this matches documented security audit."""
    user = cluster.trigger_event.user
    if user and "audit" in user.lower():
        return True, "Documented security audit user"
    return False, ""

def _eval_av_memory_scan(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if LSASS access matches AV memory scan."""
    proc = cluster.trigger_event.process_name.lower()
    av_processes = ["msmpeng.exe", "mssense.exe", "ccsvchst.exe", "avastsvc.exe"]
    if proc in av_processes:
        return True, "Antivirus memory scan"
    return False, ""

def _eval_backup_software(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if NTDS access matches backup software."""
    proc = cluster.trigger_event.process_name.lower()
    backup_tools = ["wbadmin.exe", "vssadmin.exe", "ntbackup.exe"]
    if proc in backup_tools:
        return True, "System backup tool"
    return False, ""

# ============================================================
# Constructor
# ============================================================

class CredentialAccessConstructor(Constructor):
    name = "CredentialAccess"
    mitre_tactic = "TA0006"
    mitre_techniques = ["T1003", "T1003.001", "T1003.002", "T1003.003", "T1003.004", "T1003.005", "T1003.006", "T1558", "T1558.003"]

    grouping_window_seconds = 1800  # 30 minutes
    group_by = ["host", "user"]

    @property
    def triggers(self) -> list[TriggerRule]:
        return [
            TriggerRule("lsass_access_or_dump", 45, _is_lsass_access),
            TriggerRule("sam_hive_copy", 35, _is_sam_hive_copy),
            TriggerRule("kerberoast_activity", 35, _is_kerberoast),
            TriggerRule("ntds_dump", 35, _is_ntds_dump),
            TriggerRule("password_spray_brute_force", 25, _is_password_spray),
            TriggerRule("credential_vault_access", 25, _is_credvault_access),
            TriggerRule("dpapi_extraction", 30, _is_dpapi_extraction),
        ]

    @property
    def supporting_signals(self) -> list[SignalRule]:
        return [
            SignalRule("occurred_after_initial_access", 12, _eval_occurred_after_initial_access),
            SignalRule("domain_admin_targeted", 14, _eval_domain_admin_target),
            SignalRule("lsass_dump_tool_present", 12, _eval_lsass_dump_tool_present),
            SignalRule("occurred_during_lateral_movement", 10, _eval_occurred_during_lateral_movement),
        ]

    @property
    def counter_signals(self) -> list[CounterSignal]:
        return [
            CounterSignal("documented_security_audit", 12, _eval_documented_security_audit),
            CounterSignal("av_memory_scan", 12, _eval_av_memory_scan),
            CounterSignal("backup_software", 10, _eval_backup_software),
            CounterSignal("high_frequency_baseline", 25, counter_high_frequency_baseline),
            CounterSignal("known_good_hash", 15, counter_known_good_hash),
            CounterSignal("system_legitimate_path", 20, counter_system_legitimate_path),
        ]

    def generate_summary(self, cluster: Cluster) -> None:
        host = cluster.trigger_event.host_name
        trigger = cluster.trigger_name
        user = cluster.trigger_event.user or "unknown"
        cluster.summary = f"Credential access detected on {host} by {user}: {trigger}. Possible credential theft or privilege escalation."
