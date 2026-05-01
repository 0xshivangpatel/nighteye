"""Exfiltration Constructor.

Detects TA0010 (Exfiltration) techniques.
Constructs behavioral clusters for data staging, compression,
encryption, and large outbound transfers.

References:
  - CONSTRUCTORS.md § 5.8
  - MITRE: TA0010, T1020, T1030, T1041, T1048, T1567, T1567.001, T1567.002
"""

from __future__ import annotations

from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import Cluster, Constructor, CounterSignal, SignalRule, TriggerRule

__all__ = ["ExfiltrationConstructor"]

# ============================================================
# Trigger Evaluators
# ============================================================

def _is_large_outbound_transfer(event: CanonicalEvent) -> bool:
    """Detect large outbound network transfers."""
    if event.canonical_type != CanonicalType.NETWORK_CONNECTION:
        return False
    # Would need bytes_out field; simplified to check for bulk transfer indicators
    if not event.remote_ip or _is_internal_ip(event.remote_ip):
        return False
    return True

def _is_cloud_upload_tool(event: CanonicalEvent) -> bool:
    """Detect cloud upload tools (rclone, MEGASync, etc.)."""
    if event.canonical_type == CanonicalType.PROCESS_EXECUTION:
        cmd = event.command_line.lower()
        cloud_tools = ["rclone", "megasync", "dropbox", "google drive", "onedrive", "aws s3", "gsutil"]
        return any(tool in cmd for tool in cloud_tools)
    if event.canonical_type == CanonicalType.ALERT:
        name = event.alert_name.lower()
        return any(tool in name for tool in ["rclone", "megasync", "cloud upload"])
    return False

def _is_archive_before_transfer(event: CanonicalEvent) -> bool:
    """Detect archive creation followed by network activity."""
    if event.canonical_type != CanonicalType.FILE_CREATION:
        return False
    path = event.target_file.lower()
    archive_exts = (".zip", ".rar", ".7z", ".tar.gz", ".tar")
    if not path.endswith(archive_exts):
        return False
    # Check if in staging path
    staging_paths = ["\\temp\\", "\\appdata\\", "\\programdata\\", "\\users\\public\\"]
    return any(p in path for p in staging_paths)

def _is_dns_exfil_pattern(event: CanonicalEvent) -> bool:
    """Detect DNS exfiltration patterns."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "dns exfil" in name or "dns tunnel" in name or "dga" in name

def _is_https_to_non_standard(event: CanonicalEvent) -> bool:
    """Detect HTTPS to non-standard destination."""
    if event.canonical_type != CanonicalType.NETWORK_CONNECTION:
        return False
    if not event.remote_port:
        return False
    # HTTPS to non-443 port
    return event.remote_port != 443 and event.remote_port == 8443 or event.remote_port > 10000

def _is_smb_to_external(event: CanonicalEvent) -> bool:
    """Detect SMB connections to external IPs."""
    if event.canonical_type != CanonicalType.NETWORK_CONNECTION:
        return False
    if not event.remote_port:
        return False
    if event.remote_port not in (445, 139):
        return False
    return event.remote_ip and not _is_internal_ip(event.remote_ip)

# ============================================================
# Supporting Signal Evaluators
# ============================================================

def _eval_occurred_after_collection(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if exfiltration occurred after collection activity."""
    for evt in context:
        if evt.canonical_type == CanonicalType.ALERT:
            name = evt.alert_name.lower()
            if "collection" in name or "archive" in name or "file enumeration" in name:
                return True
    return False

def _eval_sensitive_file_types(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if sensitive file types were involved."""
    sensitive_exts = [".xlsx", ".docx", ".pdf", ".pst", ".db", ".sql", ".bak"]
    for evt in context:
        path = (evt.target_file or "").lower()
        if any(ext in path for ext in sensitive_exts):
            return True
    return False

def _eval_outside_business_hours(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if activity occurred outside business hours."""
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

def _eval_multiple_destinations(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Check if data went to multiple destinations."""
    destinations = set()
    for evt in context:
        if evt.remote_ip and not _is_internal_ip(evt.remote_ip):
            destinations.add(evt.remote_ip)
    return len(destinations) >= 2

# ============================================================
# Counter Signal Evaluators
# ============================================================

def _eval_documented_backup_routine(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if this matches documented backup routine."""
    proc = cluster.trigger_event.process_name.lower()
    backup_tools = ["backup.exe", "veeam", "acronis", "restic", "rclone"]
    # rclone is suspicious unless documented
    return False, ""

def _eval_known_software_sync(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if this matches known software sync."""
    proc = cluster.trigger_event.process_name.lower()
    sync_tools = ["dropbox.exe", "googledrivesync.exe", "onedrive.exe", "boxsync.exe"]
    if proc in sync_tools:
        return True, "Known cloud sync software"
    return False, ""

def _eval_user_travel(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if user is documented as traveling (different geo)."""
    return False, ""

# ============================================================
# Helpers
# ============================================================

def _is_internal_ip(ip: str) -> bool:
    """Check if IP is RFC1918 internal."""
    if not ip or ip in ("127.0.0.1", "::1"):
        return True
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2:
            try:
                second = int(parts[1])
                return 16 <= second <= 31
            except ValueError:
                pass
    return False

# ============================================================
# Constructor
# ============================================================

class ExfiltrationConstructor(Constructor):
    name = "Exfiltration"
    mitre_tactic = "TA0010"
    mitre_techniques = ["T1020", "T1030", "T1041", "T1048", "T1567", "T1567.001", "T1567.002"]

    grouping_window_seconds = 3600  # 1 hour
    group_by = ["host", "destination_ip_or_domain"]

    @property
    def triggers(self) -> list[TriggerRule]:
        return [
            TriggerRule("large_outbound_transfer", 35, _is_large_outbound_transfer),
            TriggerRule("cloud_upload_tool", 45, _is_cloud_upload_tool),
            TriggerRule("archive_before_transfer", 40, _is_archive_before_transfer),
            TriggerRule("dns_exfil_pattern", 50, _is_dns_exfil_pattern),
            TriggerRule("https_non_standard_port", 35, _is_https_to_non_standard),
            TriggerRule("smb_to_external", 45, _is_smb_to_external),
        ]

    @property
    def supporting_signals(self) -> list[SignalRule]:
        return [
            SignalRule("occurred_after_collection", 12, _eval_occurred_after_collection),
            SignalRule("sensitive_file_types", 10, _eval_sensitive_file_types),
            SignalRule("occurred_outside_business_hours", 8, _eval_outside_business_hours),
            SignalRule("multiple_destinations", 12, _eval_multiple_destinations),
        ]

    @property
    def counter_signals(self) -> list[CounterSignal]:
        return [
            CounterSignal("matched_documented_backup_routine", 12, _eval_documented_backup_routine),
            CounterSignal("known_software_sync", 10, _eval_known_software_sync),
            CounterSignal("user_documented_travel", 8, _eval_user_travel),
        ]

    def generate_summary(self, cluster: Cluster) -> None:
        host = cluster.trigger_event.host_name
        trigger = cluster.trigger_name
        dest = cluster.trigger_event.remote_ip or "unknown"
        cluster.summary = f"Exfiltration detected on {host}: {trigger} to {dest}. Possible data theft."
