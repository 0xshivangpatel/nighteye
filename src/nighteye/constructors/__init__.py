"""Constructors framework for NightEye.

Implements behavioral clustering by evaluating canonical events against
specific attacker methodologies (Lateral Movement, Persistence, etc.).
"""

from nighteye.constructors.base import Cluster, Constructor, CounterSignal, SignalRule, TriggerRule
from nighteye.constructors.lateral_movement import LateralMovementConstructor
from nighteye.constructors.persistence import PersistenceConstructor
from nighteye.constructors.defense_evasion import DefenseEvasionConstructor
from nighteye.constructors.credential_access import CredentialAccessConstructor
from nighteye.constructors.remote_execution import RemoteExecutionConstructor
from nighteye.constructors.exfiltration import ExfiltrationConstructor
from nighteye.constructors.scoring import calculate_cluster_score, get_tier, ClusterTier

__all__ = [
    "Cluster",
    "Constructor",
    "CounterSignal",
    "SignalRule",
    "TriggerRule",
    "LateralMovementConstructor",
    "PersistenceConstructor",
    "DefenseEvasionConstructor",
    "CredentialAccessConstructor",
    "RemoteExecutionConstructor",
    "ExfiltrationConstructor",
    "calculate_cluster_score",
    "get_tier",
    "ClusterTier",
]
