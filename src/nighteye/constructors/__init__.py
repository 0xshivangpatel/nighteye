"""NightEye behavior constructors.

14 MITRE-mapped constructors for deterministic behavioral clustering.
12 are TTP/anti-forensic; 2 are dataset-agnostic structural detectors
that consume Vol3 / MemProcFS / Hayabusa output.
"""

from __future__ import annotations

from nighteye.constructors.beaconing import BeaconingConstructor
from nighteye.constructors.collection import CollectionConstructor
from nighteye.constructors.credential_access import CredentialAccessConstructor
from nighteye.constructors.defense_evasion import DefenseEvasionConstructor
from nighteye.constructors.exfiltration import ExfiltrationConstructor
from nighteye.constructors.impact import ImpactConstructor
from nighteye.constructors.lateral_movement import LateralMovementConstructor
from nighteye.constructors.log_clearing import LogClearingConstructor
from nighteye.constructors.memory_anomaly import MemoryAnomalyConstructor
from nighteye.constructors.persistence import PersistenceConstructor
from nighteye.constructors.remote_execution import RemoteExecutionConstructor
from nighteye.constructors.shadow_deletion import ShadowDeletionConstructor
from nighteye.constructors.suspicious_lineage import SuspiciousLineageConstructor
from nighteye.constructors.timestomp import TimestompConstructor

__all__ = [
    "BeaconingConstructor",
    "CollectionConstructor",
    "CredentialAccessConstructor",
    "DefenseEvasionConstructor",
    "ExfiltrationConstructor",
    "ImpactConstructor",
    "LateralMovementConstructor",
    "LogClearingConstructor",
    "MemoryAnomalyConstructor",
    "PersistenceConstructor",
    "RemoteExecutionConstructor",
    "ShadowDeletionConstructor",
    "SuspiciousLineageConstructor",
    "TimestompConstructor",
]

# Registry for dynamic lookup
ALL_CONSTRUCTORS: list[type] = [
    LateralMovementConstructor,
    PersistenceConstructor,
    CredentialAccessConstructor,
    RemoteExecutionConstructor,
    DefenseEvasionConstructor,
    BeaconingConstructor,
    CollectionConstructor,
    ExfiltrationConstructor,
    ImpactConstructor,
    LogClearingConstructor,
    TimestompConstructor,
    ShadowDeletionConstructor,
    MemoryAnomalyConstructor,
    SuspiciousLineageConstructor,
]
