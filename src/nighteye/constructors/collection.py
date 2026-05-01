"""Collection Constructor.

Detects TA0009 (Collection) techniques.
Constructs behavioral clusters for data staging, mass file enumeration,
archive creation, and credential harvesting.

References:
  - CONSTRUCTORS.md § 5.7
  - MITRE: TA0009, T1005, T1039, T1056, T1074, T1113, T1115, T1119, T1213
"""

from __future__ import annotations

from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import Cluster, Constructor, CounterSignal, SignalRule, TriggerRule

__all__ = ["CollectionConstructor"]

# ============================================================
# Trigger Evaluators
# ============================================================

def _is_mass_file_enumeration(event: CanonicalEvent) -> bool:
    """Detect mass file reads (>100 in 60s would be aggregate; single event check)."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "mass file" in name or "file enumeration" in name or "recursive read" in name

def _is_archive_creation_unusual(event: CanonicalEvent) -> bool:
    """Detect archive creation in non-typical paths."""
    if event.canonical_type != CanonicalType.FILE_CREATION:
        return False
    path = event.target_file.lower()
    archive_exts = (".zip", ".rar", ".7z", ".tar.gz", ".tar")
    if not path.endswith(archive_exts):
        return False
    # Unusual paths: Temp, AppData, non-standard backup locations
    unusual_paths = ["\\temp\\", "\\appdata\\", "\\programdata\\", "\\users\\public\\"]
    return any(p in path for p in unusual_paths)

def _is_password_grep(event: CanonicalEvent) -> bool:
    """Detect credential harvesting via command-line grep/findstr."""
    if event.canonical_type != CanonicalType.PROCESS_EXECUTION:
        return False
    cmd = event.command_line.lower()
    grep_tools = ["findstr", "grep", "select-string", "get-childitem"]
    cred_patterns = ["password", "credential", "passwd", "secret", "apikey", "api_key"]
    has_grep = any(tool in cmd for tool in grep_tools)
    has_cred = any(pat in cmd for pat in cred_patterns)
    return has_grep and has_cred

def _is_document_enumeration(event: CanonicalEvent) -> bool:
    """Detect recursive enumeration of document files."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "document enumeration" in name or "file collection" in name

def _is_screenshot_or_clipboard_yara(event: CanonicalEvent) -> bool:
    """Detect screenshot/clipboard/keylog libraries via YARA."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return any(k in name for k in ["screenshot", "clipboard", "keylog", "capture"])

def _is_outlook_pst_unusual(event: CanonicalEvent) -> bool:
    """Detect PST access by non-Outlook process."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "pst" in name or "outlook" in name

# ============================================================
# Supporting Signal Evaluators
# ============================================================

def _eval_occurred_after_lateral_movement(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if collection occurred after lateral movement."""
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if "lateral movement" in name or "lateral" in name:
                return True
    return False

def _eval_high_value_paths(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if files from high-value paths were accessed."""
    high_value = ["\\finance\\", "\\hr\\", "\\accounting\\", "\\payroll\\", 
                  "\\source\\", "\\repo\\", "\\git\\", "\\dev\\"]
    for evt in context:
        path = (evt.target_file or "").lower()
        if any(hv in path for hv in high_value):
            return True
    return False

def _eval_encrypted_archive(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if encrypted archive was created."""
    for evt in context:
        if evt.canonical_type == CanonicalType.PROCESS_EXECUTION:
            cmd = evt.command_line.lower()
            if any(flag in cmd for flag in ["-p", "-hp", "--password", "-aes"]):
                return True
    return False

def _eval_outside_business_hours(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if activity occurred outside 09:00-17:00."""
    from datetime import datetime
    for evt in context:
        if evt.timestamp:
            try:
                ts = evt.timestamp.replace("Z", "+00:00")
                dt = datetime.fromisoformat(ts)
                if dt.hour < 9 or dt.hour >= 17:
                    return True
            except (ValueError, TypeError):
                continue
    return False

# ============================================================
# Counter Signal Evaluators
# ============================================================

def _eval_backup_software(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if pattern matches backup software."""
    proc = cluster.trigger_event.process_name.lower()
    backup_tools = ["backup.exe", "veeam", "acronis", "backuppc", "restic"]
    if any(b in proc for b in backup_tools):
        return True, f"Process {proc} matches backup software"
    return False, ""

def _eval_indexing_service(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if pattern matches indexing service."""
    proc = cluster.trigger_event.process_name.lower()
    if proc in ["searchindexer.exe", "searchprotocolhost.exe", "msexchange.exe"]:
        return True, "Known indexing service"
    return False, ""

def _eval_documented_data_owner(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if user is documented data owner."""
    user = cluster.trigger_event.user
    # Would query from case config
    return False, ""

# ============================================================
# Constructor
# ============================================================

class CollectionConstructor(Constructor):
    name = "Collection"
    mitre_tactic = "TA0009"
    mitre_techniques = ["T1005", "T1039", "T1056", "T1074", "T1113", "T1115", "T1119", "T1213"]

    grouping_window_seconds = 1800  # 30 minutes
    group_by = ["host", "user"]

    @property
    def triggers(self) -> list[TriggerRule]:
        return [
            TriggerRule("mass_file_enumeration", 40, _is_mass_file_enumeration),
            TriggerRule("archive_creation_unusual_path", 45, _is_archive_creation_unusual),
            TriggerRule("password_grep_pattern", 50, _is_password_grep),
            TriggerRule("document_recursive_enumeration", 40, _is_document_enumeration),
            TriggerRule("screenshot_or_clipboard_yara", 45, _is_screenshot_or_clipboard_yara),
            TriggerRule("outlook_pst_access_unusual", 40, _is_outlook_pst_unusual),
        ]

    @property
    def supporting_signals(self) -> list[SignalRule]:
        return [
            SignalRule("occurred_after_lateral_movement", 12, _eval_occurred_after_lateral_movement),
            SignalRule("files_from_high_value_paths", 10, _eval_high_value_paths),
            SignalRule("encrypted_archive_creation", 12, _eval_encrypted_archive),
            SignalRule("occurred_outside_business_hours", 8, _eval_outside_business_hours),
        ]

    @property
    def counter_signals(self) -> list[CounterSignal]:
        return [
            CounterSignal("matched_backup_software_pattern", 12, _eval_backup_software),
            CounterSignal("within_indexing_service_pattern", 10, _eval_indexing_service),
            CounterSignal("user_documented_data_owner", 8, _eval_documented_data_owner),
        ]

    def generate_summary(self, cluster: Cluster) -> None:
        host = cluster.trigger_event.host_name
        trigger = cluster.trigger_name
        user = cluster.trigger_event.user or "unknown"
        cluster.summary = f"Collection activity detected on {host} by {user}: {trigger}. Possible data staging for exfiltration."
