"""Impact Constructor.

Detects TA0040 (Impact) techniques.
Constructs behavioral clusters for ransomware, data destruction,
backup deletion, and service disruption.

References:
  - CONSTRUCTORS.md § 5.9
  - MITRE: TA0040, T1485, T1486, T1489, T1490, T1491, T1565
"""

from __future__ import annotations

from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import Cluster, Constructor, CounterSignal, SignalRule, TriggerRule

__all__ = ["ImpactConstructor"]

# ============================================================
# Trigger Evaluators
# ============================================================

def _is_mass_file_modification(event: CanonicalEvent) -> bool:
    """Detect mass file modifications (>100/min would be aggregate)."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "mass file" in name and ("modify" in name or "encrypt" in name or "ransom" in name)

def _is_ransomware_extension(event: CanonicalEvent) -> bool:
    """Detect file writes with known ransomware extensions."""
    if event.canonical_type != CanonicalType.FILE_CREATION:
        return False
    path = event.target_file.lower()
    ransom_exts = [
        ".locked", ".encrypted", ".crypt", ".crypto", ".enc", ". ransom",
        ".locky", ".zepto", ".cerber", ".wannacry", ".wncry", ".wncryt",
        ".gandcrab", ".sodinokibi", ".revil", ".darkside", ".lockbit",
        ".readme", ".how_to_decrypt", ".recover", ".restore"
    ]
    return path.endswith(tuple(ransom_exts))

def _is_shadow_copy_deletion(event: CanonicalEvent) -> bool:
    """Detect shadow copy deletion events."""
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "shadow" in name and ("delete" in name or "delet" in name)
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        return "vssadmin" in cmd and "delete" in cmd and "shadows" in cmd
    return False

def _is_backup_destruction(event: CanonicalEvent) -> bool:
    """Detect backup destruction commands."""
    if event.canonical_type != CanonicalType.PROCESS_EXECUTION:
        return False
    cmd = event.command_line.lower()
    destructive_cmds = [
        "wbadmin delete",
        "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
        "bcdedit /set {default} recoveryenabled no",
        "vssadmin resize shadowstorage",
    ]
    return any(dc in cmd for dc in destructive_cmds)

def _is_ransom_note(event: CanonicalEvent) -> bool:
    """Detect ransom note file creation."""
    if event.canonical_type != CanonicalType.FILE_CREATION:
        return False
    path = event.target_file.lower()
    note_patterns = [
        "readme", "how_to_decrypt", "_readme", "recover", "restore",
        "decrypt", "instructions", "help_decrypt", "about_files"
    ]
    filename = path.split("\\")[-1] if "\\" in path else path.split("/")[-1]
    return any(pat in filename for pat in note_patterns) and filename.endswith(".txt")

def _is_mass_service_stop(event: CanonicalEvent) -> bool:
    """Detect mass service stops."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "service stop" in name or "mass service" in name or "stop services" in name

def _is_mass_account_lockout(event: CanonicalEvent) -> bool:
    """Detect mass account lockouts."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "account lockout" in name or "brute force" in name or "mass lockout" in name

# ============================================================
# Supporting Signal Evaluators
# ============================================================

def _eval_occurred_after_credential_access(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if impact occurred after credential access."""
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if "credential" in name or "lsass" in name or "dump" in name:
                return True
    return False

def _eval_affected_dc_or_fileserver(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if high-value server was affected."""
    host = cluster.trigger_event.host_name.lower()
    high_value = ["dc", "dc01", "dc02", "fileserver", "fs", "nas", "sql", "exchange"]
    return any(hv in host for hv in high_value)

def _eval_persistence_destruction(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if persistence mechanisms were destroyed."""
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if "delete" in name and ("service" in name or "task" in name or "registry" in name):
                return True
    return False

def _eval_anti_forensic_cooccurrence(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if anti-forensic activity co-occurs."""
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if "log cleared" in name or "timestomp" in name or "anti-forensic" in name:
                return True
    return False

# ============================================================
# Counter Signal Evaluators
# ============================================================

def _eval_documented_decommission(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if this matches a documented decommission."""
    return False, ""

def _eval_av_quarantine(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if file modifications match AV quarantine pattern."""
    proc = cluster.trigger_event.process_name.lower()
    av_processes = ["msmpeng.exe", "mssense.exe", "ccsvchst.exe", "avastsvc.exe", "bdagent.exe"]
    if proc in av_processes:
        return True, "Antivirus quarantine activity"
    return False, ""

def _eval_known_software_uninstall(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if this matches known software uninstall."""
    proc = cluster.trigger_event.process_name.lower()
    if proc in ["msiexec.exe", "setup.exe", "uninstall.exe"]:
        return True, "Software installer/uninstaller activity"
    return False, ""

# ============================================================
# Constructor
# ============================================================

class ImpactConstructor(Constructor):
    name = "Impact"
    mitre_tactic = "TA0040"
    mitre_techniques = ["T1485", "T1486", "T1489", "T1490", "T1491", "T1565"]

    grouping_window_seconds = 1800  # 30 minutes
    group_by = ["host"]

    @property
    def triggers(self) -> list[TriggerRule]:
        return [
            TriggerRule("mass_file_modification", 40, _is_mass_file_modification),
            TriggerRule("ransomware_extension_pattern", 55, _is_ransomware_extension),
            TriggerRule("shadow_copy_deletion", 50, _is_shadow_copy_deletion),
            TriggerRule("backup_destruction", 50, _is_backup_destruction),
            TriggerRule("ransom_note_pattern", 45, _is_ransom_note),
            TriggerRule("mass_service_stop", 40, _is_mass_service_stop),
            TriggerRule("mass_account_lockout", 35, _is_mass_account_lockout),
        ]

    @property
    def supporting_signals(self) -> list[SignalRule]:
        return [
            SignalRule("occurred_after_credential_access", 12, _eval_occurred_after_credential_access),
            SignalRule("affected_dc_or_file_server", 14, _eval_affected_dc_or_fileserver),
            SignalRule("persistence_destruction_pattern", 10, _eval_persistence_destruction),
            SignalRule("anti_forensic_co_occurrence", 12, _eval_anti_forensic_cooccurrence),
        ]

    @property
    def counter_signals(self) -> list[CounterSignal]:
        return [
            CounterSignal("matched_documented_decommission", 15, _eval_documented_decommission),
            CounterSignal("within_av_quarantine_pattern", 12, _eval_av_quarantine),
            CounterSignal("matched_known_software_uninstall", 10, _eval_known_software_uninstall),
        ]

    def generate_summary(self, cluster: Cluster) -> None:
        host = cluster.trigger_event.host_name
        trigger = cluster.trigger_name
        cluster.summary = f"Impact/Destruction detected on {host}: {trigger}. Possible ransomware or sabotage activity."
