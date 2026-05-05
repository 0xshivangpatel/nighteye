"""Shadow Deletion Constructor (Anti-Forensic + Impact).

Detects T1490 (Inhibit System Recovery).
Constructs behavioral clusters for Volume Shadow Copy deletion.
Also registers evidence disturbance ±30 minutes around detection.

References:
  - CONSTRUCTORS.md § 5.12
  - MITRE: TA0040 + TA0005, T1490
"""

from __future__ import annotations

from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import Cluster, Constructor, CounterSignal, SignalRule, TriggerRule
from nighteye.constructors.counter_evidence import counter_known_good_hash, counter_system_legitimate_path, counter_high_frequency_baseline

__all__ = ["ShadowDeletionConstructor"]

# ============================================================
# Trigger Evaluators
# ============================================================

def _is_vssadmin_delete(event: CanonicalEvent) -> bool:
    """Detect vssadmin delete shadows command."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        return "vssadmin" in cmd and "delete" in cmd and "shadows" in cmd
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "vssadmin" in name and "delete" in name
    return False

def _is_wmic_shadowcopy_delete(event: CanonicalEvent) -> bool:
    """Detect wmic shadowcopy delete command."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        return "wmic" in cmd and "shadowcopy" in cmd and "delete" in cmd
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "wmic" in name and "shadowcopy" in name and "delete" in name
    return False

def _is_diskshadow_delete(event: CanonicalEvent) -> bool:
    """Detect diskshadow delete command."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        return "diskshadow" in cmd and "delete" in cmd
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "diskshadow" in name and "delete" in name
    return False

def _is_evtx_524(event: CanonicalEvent) -> bool:
    """Detect Event ID 524 (volume shadow copy deleted)."""
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "524" in name and "shadow" in name
    return False

def _is_powershell_remove_shadow(event: CanonicalEvent) -> bool:
    """Detect PowerShell removal of shadow copies."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        return (
            "powershell" in cmd 
            and "get-wmiobject" in cmd 
            and "win32_shadowcopy" in cmd 
            and "delete" in cmd
        )
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "powershell" in name and "shadowcopy" in name and "delete" in name
    return False

# ============================================================
# Supporting Signal Evaluators
# ============================================================

def _eval_executed_by_non_admin(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if shadow deletion was executed by non-admin."""
    user = cluster.trigger_event.user
    if user:
        user_lower = user.lower()
        admin_indicators = ["admin", "administrator", "system", "localsystem", "nt authority"]
        return not any(ind in user_lower for ind in admin_indicators)
    return False

def _eval_followed_by_mass_file_modification(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if followed by mass file modification (ransomware pattern)."""
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if "mass file" in name or "ransom" in name or "encrypt" in name:
                return True
    return False

def _eval_occurred_with_backup_destruction(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if co-occurs with other backup destruction."""
    for evt in context:
        if evt.canonical_type == CanonicalType.PROCESS_EXECUTION:
            cmd = evt.command_line.lower()
            if any(bd in cmd for bd in ["wbadmin delete", "bcdedit", "recoveryenabled"]):
                return True
    return False

# ============================================================
# Counter Signal Evaluators
# ============================================================

def _eval_documented_disk_cleanup(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if this matches documented disk cleanup."""
    proc = cluster.trigger_event.process_name.lower()
    if proc in ["cleanmgr.exe", "diskcleanup.exe"]:
        return True, "System disk cleanup utility"
    return False, ""

def _eval_backup_software_window(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if within backup software maintenance window."""
    from datetime import datetime
    ts = cluster.trigger_event.timestamp
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            # Common backup windows: late night / early morning
            if dt.hour in [0, 1, 2, 3, 4]:
                return True, "Occurred during typical backup maintenance window"
        except (ValueError, TypeError):
            pass
    return False, ""

# ============================================================
# Constructor
# ============================================================

class ShadowDeletionConstructor(Constructor):
    name = "ShadowDeletion"
    mitre_tactic = "TA0040"
    mitre_techniques = ["T1490"]

    grouping_window_seconds = 0  # Instantaneous
    group_by = ["host"]
    is_anti_forensic = True

    @property
    def triggers(self) -> list[TriggerRule]:
        return [
            TriggerRule("vssadmin_delete_shadows", 45, _is_vssadmin_delete),
            TriggerRule("wmic_shadowcopy_delete", 40, _is_wmic_shadowcopy_delete),
            TriggerRule("diskshadow_delete", 40, _is_diskshadow_delete),
            TriggerRule("evtx_524", 25, _is_evtx_524),
            TriggerRule("powershell_remove_wmiobject_shadow", 40, _is_powershell_remove_shadow),
        ]

    @property
    def supporting_signals(self) -> list[SignalRule]:
        return [
            SignalRule("executed_by_non_admin", 14, _eval_executed_by_non_admin),
            SignalRule("followed_by_mass_file_modification", 14, _eval_followed_by_mass_file_modification),
            SignalRule("occurred_with_backup_destruction", 12, _eval_occurred_with_backup_destruction),
        ]

    @property
    def counter_signals(self) -> list[CounterSignal]:
        return [
            CounterSignal("matched_documented_disk_cleanup", 12, _eval_documented_disk_cleanup),
            CounterSignal("within_backup_software_window", 10, _eval_backup_software_window),
            CounterSignal("high_frequency_baseline", 25, counter_high_frequency_baseline),
            CounterSignal("known_good_hash", 15, counter_known_good_hash),
            CounterSignal("system_legitimate_path", 20, counter_system_legitimate_path),
        ]

    def generate_summary(self, cluster: Cluster) -> None:
        host = cluster.trigger_event.host_name
        trigger = cluster.trigger_name
        user = cluster.trigger_event.user or "unknown"
        cluster.summary = f"Shadow copy deletion detected on {host} by {user}: {trigger}. System recovery inhibition / anti-forensic activity."

    def post_process(self, cluster: Cluster, db_conn: Any) -> None:
        """Register evidence disturbance ±30 minutes around detection."""
        from nighteye.db import execute_with_retry
        from datetime import datetime, timedelta, timezone

        host = cluster.trigger_event.host_name
        ts = cluster.trigger_event.timestamp

        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                dt = datetime.now(timezone.utc)
        else:
            dt = datetime.now(timezone.utc)

        # Shadow deletion is preparatory - wider window
        window_start = (dt - timedelta(minutes=30)).isoformat()
        window_end = (dt + timedelta(minutes=30)).isoformat()

        disturbance_id = f"dist-shadow-{cluster.cluster_id}"

        try:
            execute_with_retry(
                db_conn,
                """
                INSERT OR REPLACE INTO evidence_disturbances 
                (disturbance_id, case_id, host, window_start, window_end, disturbance_type, detected_by, source_audit_id, details, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    disturbance_id,
                    cluster.case_id,
                    host,
                    window_start,
                    window_end,
                    "SHADOW_DELETION",
                    "ShadowDeletionConstructor",
                    cluster.trigger_event.event_id if hasattr(cluster.trigger_event, 'event_id') else "unknown",
                    '{"cluster_id": "' + cluster.cluster_id + '", "trigger": "' + cluster.trigger_name + '"}',
                    datetime.now(timezone.utc).isoformat(),
                )
            )
        except Exception as e:
            import logging
            logging.getLogger("nighteye.constructors.shadow_deletion").warning(
                "Failed to register evidence disturbance: %s", e
            )
