"""Log Clearing Constructor (Anti-Forensic).

Detects T1070.001 (Clear Windows Event Logs).
Constructs behavioral clusters for evidence destruction via log clearing.
Also registers evidence_disturbance rows for affected time windows.

References:
  - CONSTRUCTORS.md § 5.10
  - MITRE: TA0005, T1070.001
"""

from __future__ import annotations

from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import Cluster, Constructor, CounterSignal, SignalRule, TriggerRule

__all__ = ["LogClearingConstructor"]

# ============================================================
# Trigger Evaluators
# ============================================================

def _is_evtx_1102_clear(event: CanonicalEvent) -> bool:
    """Detect Event ID 1102 (Security log cleared)."""
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "1102" in name or "log cleared" in name
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        # Weeutil or other log clearing tools
        cmd = event.command_line.lower()
        return "wevtutil" in cmd and "cl" in cmd
    return False

def _is_evtx_104_alt_clear(event: CanonicalEvent) -> bool:
    """Detect alternative log clearing (Event ID 104)."""
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return "104" in name and "log" in name
    return False

def _is_recordid_gap(event: CanonicalEvent) -> bool:
    """Detect EVTX RecordID sequence gaps."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "recordid gap" in name or "event gap" in name or "missing event" in name

def _is_evtx_truncated(event: CanonicalEvent) -> bool:
    """Detect truncated EVTX files."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "truncated" in name and ("evtx" in name or "event log" in name)

# ============================================================
# Supporting Signal Evaluators
# ============================================================

def _eval_cleared_by_non_admin(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if logs were cleared by non-admin user."""
    user = cluster.trigger_event.user
    if user and not _is_admin_user(user):
        return True
    return False

def _eval_during_other_attack_signals(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if clearing occurred during other attack signals."""
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if any(k in name for k in ["lateral", "persistence", "credential", "defense evasion"]):
                return True
    return False

def _eval_multiple_logs_cleared(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if multiple log channels were cleared in same window."""
    cleared_channels = set()
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if "cleared" in name or "1102" in name or "104" in name:
                # Extract channel name heuristically
                for ch in ["security", "system", "application", "powershell", "sysmon"]:
                    if ch in name:
                        cleared_channels.add(ch)
    return len(cleared_channels) >= 2

# ============================================================
# Counter Signal Evaluators
# ============================================================

def _eval_log_rotation_pattern(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if this matches normal log rotation."""
    # Log rotation typically happens at scheduled times
    from datetime import datetime
    ts = cluster.trigger_event.timestamp
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            # Common rotation times: midnight, early morning
            if dt.hour in [0, 1, 2, 3] and dt.minute < 10:
                return True, "Log clearing occurred during typical rotation window"
        except (ValueError, TypeError):
            pass
    return False, ""

def _eval_documented_admin(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if performed by documented admin during maintenance."""
    user = cluster.trigger_event.user
    if user and _is_admin_user(user):
        # Would check maintenance window config
        return False, ""
    return False, ""

def _is_admin_user(user: str) -> bool:
    """Check if user is likely an admin."""
    if not user:
        return False
    user_lower = user.lower()
    admin_indicators = ["admin", "administrator", "domain admin", "enterprise admin"]
    return any(ind in user_lower for ind in admin_indicators)

# ============================================================
# Constructor
# ============================================================

class LogClearingConstructor(Constructor):
    name = "LogClearing"
    mitre_tactic = "TA0005"
    mitre_techniques = ["T1070.001"]

    grouping_window_seconds = 0  # Instantaneous
    group_by = ["host"]
    is_anti_forensic = True

    @property
    def triggers(self) -> list[TriggerRule]:
        return [
            TriggerRule("evtx_1102_clear", 45, _is_evtx_1102_clear),
            TriggerRule("evtx_104_alt_clear", 35, _is_evtx_104_alt_clear),
            TriggerRule("recordid_gap", 25, _is_recordid_gap),
            TriggerRule("evtx_truncated", 20, _is_evtx_truncated),
        ]

    @property
    def supporting_signals(self) -> list[SignalRule]:
        return [
            SignalRule("cleared_by_non_admin", 14, _eval_cleared_by_non_admin),
            SignalRule("occurred_during_other_attack_signals", 12, _eval_during_other_attack_signals),
            SignalRule("multiple_logs_cleared_same_window", 14, _eval_multiple_logs_cleared),
        ]

    @property
    def counter_signals(self) -> list[CounterSignal]:
        return [
            CounterSignal("within_log_rotation_pattern", 15, _eval_log_rotation_pattern),
            CounterSignal("performed_by_documented_admin", 10, _eval_documented_admin),
        ]

    def generate_summary(self, cluster: Cluster) -> None:
        host = cluster.trigger_event.host_name
        trigger = cluster.trigger_name
        user = cluster.trigger_event.user or "unknown"
        cluster.summary = f"Log clearing detected on {host} by {user}: {trigger}. Evidence destruction / anti-forensic activity."

    def post_process(self, cluster: Cluster, db_conn: Any) -> None:
        """Register evidence disturbance for cleared logs."""
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

        window_start = (dt - timedelta(minutes=15)).isoformat()
        window_end = (dt + timedelta(minutes=15)).isoformat()

        disturbance_id = f"dist-logclear-{cluster.cluster_id}"

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
                    "LOG_CLEARING",
                    "LogClearingConstructor",
                    cluster.trigger_event.event_id if hasattr(cluster.trigger_event, 'event_id') else "unknown",
                    '{"cluster_id": "' + cluster.cluster_id + '", "trigger": "' + cluster.trigger_name + '"}',
                    datetime.now(timezone.utc).isoformat(),
                )
            )
        except Exception as e:
            # Log but don't fail the cluster creation
            import logging
            logging.getLogger("nighteye.constructors.log_clearing").warning(
                "Failed to register evidence disturbance: %s", e
            )
