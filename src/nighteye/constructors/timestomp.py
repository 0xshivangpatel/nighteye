"""Timestomp Constructor (Anti-Forensic).

Detects T1070.006 (Timestomp).
Constructs behavioral clusters for timestamp manipulation on files.
Also marks affected files with evidence_disturbed=true in graph.

References:
  - CONSTRUCTORS.md § 5.11
  - MITRE: TA0005, T1070.006
"""

from __future__ import annotations

from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import Cluster, Constructor, CounterSignal, SignalRule, TriggerRule

__all__ = ["TimestompConstructor"]

# ============================================================
# Trigger Evaluators
# ============================================================

def _is_si_fn_mismatch(event: CanonicalEvent) -> bool:
    """Detect $STANDARD_INFORMATION vs $FILE_NAME timestamp mismatch."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "timestomp" in name or "timestamp mismatch" in name or "si-fn" in name

def _is_si_before_fn(event: CanonicalEvent) -> bool:
    """Detect impossible SI before FN timestamps."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "impossible" in name and "timestamp" in name

def _is_rounded_timestamps(event: CanonicalEvent) -> bool:
    """Detect suspiciously rounded timestamps (.0000000)."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "rounded timestamp" in name or "suspicious timestamp" in name

def _is_backdated_file(event: CanonicalEvent) -> bool:
    """Detect files with creation dates before OS install."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "backdated" in name or "future timestamp" in name or "pre-install" in name

# ============================================================
# Supporting Signal Evaluators
# ============================================================

def _eval_affected_file_in_persistence_path(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if timestomped file is in persistence location."""
    for evt in context:
        path = (evt.target_file or "").lower()
        persistence_paths = [
            "\windows\system32\",
            "\windows\syswow64\",
            "\program files\",
            "\users\public\",
            "\startup\",
            "\run\",
        ]
        if any(p in path for p in persistence_paths):
            return True
    return False

def _eval_affected_file_unsigned(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if timestomped file is unsigned."""
    # Would need signature info from amcache or pe analysis
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if "unsigned" in name:
                return True
    return False

def _eval_affected_file_in_system32(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if timestomped file is in system32."""
    for evt in context:
        path = (evt.target_file or "").lower()
        if "\windows\system32\" in path or "\windows\syswow64\" in path:
            return True
    return False

def _eval_occurred_with_other_attacks(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if timestomping co-occurs with other attack signals."""
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if any(k in name for k in ["lateral", "persistence", "credential", "defense evasion"]):
                return True
    return False

# ============================================================
# Counter Signal Evaluators
# ============================================================

def _eval_known_installer_behavior(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if timestamp behavior matches known installer."""
    proc = cluster.trigger_event.process_name.lower()
    installers = ["msiexec.exe", "setup.exe", "install.exe", "update.exe"]
    if proc in installers:
        return True, "Timestamp manipulation by known installer"
    return False, ""

def _eval_file_restore_window(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if within file restore/recovery window."""
    return False, ""

# ============================================================
# Constructor
# ============================================================

class TimestompConstructor(Constructor):
    name = "Timestomp"
    mitre_tactic = "TA0005"
    mitre_techniques = ["T1070.006"]

    grouping_window_seconds = 0  # Instantaneous
    group_by = ["host", "file"]
    is_anti_forensic = True

    @property
    def triggers(self) -> list[TriggerRule]:
        return [
            TriggerRule("si_fn_timestamp_mismatch", 45, _is_si_fn_mismatch),
            TriggerRule("si_before_fn", 50, _is_si_before_fn),
            TriggerRule("rounded_second_timestamps", 35, _is_rounded_timestamps),
            TriggerRule("backdated_file", 40, _is_backdated_file),
        ]

    @property
    def supporting_signals(self) -> list[SignalRule]:
        return [
            SignalRule("affected_file_in_persistence_path", 14, _eval_affected_file_in_persistence_path),
            SignalRule("affected_file_unsigned", 10, _eval_affected_file_unsigned),
            SignalRule("affected_file_in_system32", 12, _eval_affected_file_in_system32),
            SignalRule("occurred_with_other_attack_signals", 10, _eval_occurred_with_other_attacks),
        ]

    @property
    def counter_signals(self) -> list[CounterSignal]:
        return [
            CounterSignal("matched_known_installer_behavior", 12, _eval_known_installer_behavior),
            CounterSignal("within_file_restore_window", 10, _eval_file_restore_window),
        ]

    def generate_summary(self, cluster: Cluster) -> None:
        host = cluster.trigger_event.host_name
        trigger = cluster.trigger_name
        file_path = cluster.trigger_event.target_file or "unknown file"
        cluster.summary = f"Timestomp detected on {host}: {trigger} affecting {file_path}. Evidence timestamp manipulation."

    def post_process(self, cluster: Cluster, db_conn: Any) -> None:
        """Mark affected files with evidence_disturbed in graph."""
        from nighteye.db import execute_with_retry
        from datetime import datetime, timezone

        file_path = cluster.trigger_event.target_file
        host = cluster.trigger_event.host_name

        if not file_path:
            return

        # Mark the file entity as disturbed
        try:
            entity_id = f"file-{host}-{file_path}"  # Simplified; real would use canonical_key rules
            execute_with_retry(
                db_conn,
                "UPDATE entities SET evidence_disturbed = 1 WHERE entity_id = ?",
                (entity_id,)
            )
        except Exception as e:
            import logging
            logging.getLogger("nighteye.constructors.timestomp").warning(
                "Failed to mark file as disturbed: %s", e
            )
