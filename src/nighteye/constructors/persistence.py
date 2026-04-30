"""Persistence Constructor.

Detects TA0003 (Persistence) techniques.
Constructs behavioral clusters for mechanisms attackers use to maintain
access across restarts, such as Registry Run keys, Scheduled Tasks, and
Services.

References:
    - CONSTRUCTORS.md § 5.2
    - MITRE: TA0003, T1547.001, T1543.003, T1053.005
"""

from __future__ import annotations

from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.constructors.base import Cluster, Constructor, CounterSignal, SignalRule, TriggerRule

__all__ = ["PersistenceConstructor"]


def _is_registry_run_key(event: CanonicalEvent) -> bool:
    """Trigger: Addition or modification of Run/RunOnce registry keys."""
    if event.canonical_type != CanonicalType.REGISTRY_MODIFICATION:
        return False
    key = event.registry_key.lower()
    return "currentversion\\run" in key


def _is_service_persistent(event: CanonicalEvent) -> bool:
    """Trigger: Service installed with Auto/Demand start."""
    if event.canonical_type != CanonicalType.SERVICE_INSTALLATION:
        return False
    
    # We look for services.exe parent or specific event codes if mapped
    # For now, any service installation is a potential persistence mechanism.
    return True


def _is_scheduled_task(event: CanonicalEvent) -> bool:
    """Trigger: Scheduled task created or modified."""
    return event.canonical_type == CanonicalType.SCHEDULED_TASK


def _is_startup_folder_write(event: CanonicalEvent) -> bool:
    """Trigger: File written to a user's Startup folder."""
    if event.canonical_type not in (CanonicalType.FILE_CREATION, CanonicalType.FILE_MODIFICATION):
        return False
    path = event.target_file.lower()
    return "\\start menu\\programs\\startup" in path


def _is_sigma_persistence_match(event: CanonicalEvent) -> bool:
    """Trigger: Hayabusa/Chainsaw alert tagged with persistence."""
    if event.canonical_type != CanonicalType.ALERT:
        return False
    name = event.alert_name.lower()
    return "persistence" in name or "autorun" in name or "scheduled task" in name


# --- Supporting Signal Evaluators ---

def _eval_binary_path_unusual(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Checks if the associated binary is in an unusual path like AppData or Temp."""
    path = cluster.trigger_event.process_path.lower() or cluster.trigger_event.target_file.lower()
    if not path:
        return False
    
    return "\\appdata\\" in path or "\\temp\\" in path or "\\programdata\\" in path


def _eval_binary_unsigned(cluster: Cluster, context: list[CanonicalEvent]) -> bool:
    """Checks if the binary is unsigned (simulated)."""
    # Requires PE parsing/Amcache data correlation
    # For now we stub it based on missing signature fields in raw data
    raw = cluster.trigger_event.raw_data or {}
    return "signature" not in str(raw).lower()


# --- Counter Signal Evaluators ---

def _eval_binary_signed_microsoft(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if the binary is signed by Microsoft."""
    # Stubbed lookup
    return False, "binary not confirmed as Microsoft signed"


def _eval_known_software_baseline(cluster: Cluster, db: Any) -> tuple[bool, str]:
    """Check if the path/hash matches a known legitimate software deployment."""
    path = cluster.trigger_event.process_path.lower() or cluster.trigger_event.target_file.lower()
    if not path:
        return False, "no path available"
    
    # Stubbed lookup
    if "google\\chrome\\application" in path:
        return True, "matches known Chrome update mechanism"
        
    return False, "binary not in known software baseline"


class PersistenceConstructor(Constructor):
    """Constructor for detecting Persistence mechanisms."""
    
    name = "Persistence"
    mitre_tactic = "TA0003"
    mitre_techniques = ["T1547.001", "T1543.003", "T1053.005", "T1547.009"]

    @property
    def triggers(self) -> list[TriggerRule]:
        return [
            TriggerRule("registry_run_key_added", 40, _is_registry_run_key),
            TriggerRule("service_install_persistent", 35, _is_service_persistent),
            TriggerRule("scheduled_task_created", 30, _is_scheduled_task),
            TriggerRule("startup_folder_item_added", 45, _is_startup_folder_write),
            TriggerRule("sigma_persistence_match", 50, _is_sigma_persistence_match),
        ]

    @property
    def supporting_signals(self) -> list[SignalRule]:
        return [
            SignalRule("binary_path_unusual", 10, _eval_binary_path_unusual),
            SignalRule("binary_unsigned", 12, _eval_binary_unsigned),
        ]

    @property
    def counter_signals(self) -> list[CounterSignal]:
        return [
            CounterSignal("binary_signed_microsoft", 12, _eval_binary_signed_microsoft),
            CounterSignal("binary_in_known_software_baseline", 12, _eval_known_software_baseline),
        ]

    def generate_summary(self, cluster: Cluster) -> None:
        host = cluster.trigger_event.host_name
        path = cluster.trigger_event.process_path or cluster.trigger_event.target_file or "unknown file"
        
        parts = [f"Persistence mechanism detected on {host}"]
        
        if cluster.trigger_name == "registry_run_key_added":
            parts.append(f"Run key modified for {path}")
        elif cluster.trigger_name == "service_install_persistent":
            parts.append(f"Service installed pointing to {path}")
        elif cluster.trigger_name == "scheduled_task_created":
            parts.append(f"Scheduled task created")
        elif cluster.trigger_name == "startup_folder_item_added":
            parts.append(f"File added to Startup folder: {path}")
        elif cluster.trigger_name == "sigma_persistence_match":
            parts.append(f"Sigma detection: {cluster.trigger_event.alert_name}")
            
        cluster.summary = ", ".join(parts) + "."
