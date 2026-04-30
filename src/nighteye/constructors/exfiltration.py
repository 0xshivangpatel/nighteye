"""Exfiltration Constructor.

Detects TA0010 (Exfiltration) techniques.
Constructs behavioral clusters for suspicious data staging, mass copying,
and anomalous outbound network traffic.

References:
    - CONSTRUCTORS.md § 5.8
    - MITRE: TA0010, T1041, T1048, T1567
"""

from __future__ import annotations

from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import Cluster, Constructor, CounterSignal, SignalRule, TriggerRule

__all__ = ["ExfiltrationConstructor"]


def _is_cloud_uploader_process(event: CanonicalEvent) -> bool:
    if event.canonical_type != CanonicalType.PROCESS_EXECUTION:
        return False
    image = event.process_name.lower()
    uploaders = ["rclone.exe", "megacmd.exe", "dropbox.exe", "onedrive.exe"]
    
    # Simple check for known uploaders
    return any(u in image for u in uploaders)


def _is_encrypted_archive_followed_by_upload(event: CanonicalEvent) -> bool:
    if event.canonical_type != CanonicalType.FILE_CREATION:
        return False
    path = event.target_file.lower()
    return path.endswith((".zip", ".rar", ".7z", ".tar.gz"))


class ExfiltrationConstructor(Constructor):
    name = "Exfiltration"
    mitre_tactic = "TA0010"
    mitre_techniques = ["T1041", "T1048", "T1567"]

    @property
    def triggers(self) -> list[TriggerRule]:
        return [
            TriggerRule("cloud_uploader_process", 45, _is_cloud_uploader_process),
            TriggerRule("archive_creation", 30, _is_encrypted_archive_followed_by_upload),
        ]

    @property
    def supporting_signals(self) -> list[SignalRule]:
        return []

    @property
    def counter_signals(self) -> list[CounterSignal]:
        return []

    def generate_summary(self, cluster: Cluster) -> None:
        host = cluster.trigger_event.host_name
        cluster.summary = f"Exfiltration pattern detected on {host}: {cluster.trigger_name}."
