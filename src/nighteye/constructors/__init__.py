"""NightEye behavior constructors.

All 12 MITRE-mapped constructors for deterministic behavioral clustering.
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
from nighteye.constructors.persistence import PersistenceConstructor
from nighteye.constructors.remote_execution import RemoteExecutionConstructor
from nighteye.constructors.shadow_deletion import ShadowDeletionConstructor
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
    "PersistenceConstructor",
    "RemoteExecutionConstructor",
    "ShadowDeletionConstructor",
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
]
