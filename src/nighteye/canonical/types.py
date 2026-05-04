"""Canonical event types.

Defines the normalized, cross-source event types that NightEye uses
for behavior construction.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["CanonicalType", "CanonicalEvent"]


class CanonicalType(str, Enum):
    """The normalized category of a forensic event."""
    # Execution
    PROCESS_EXECUTION = "PROCESS_EXECUTION"
    PROCESS_TERMINATION = "PROCESS_TERMINATION"
    
    # Network
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    
    # Auth
    AUTHENTICATION = "AUTHENTICATION"  # Logon/Logoff
    LSASS_ACCESS = "LSASS_ACCESS"
    TICKET_REQUEST = "TICKET_REQUEST"
    REPLICATION = "REPLICATION"
    LOG_CLEARED = "LOG_CLEARED"

    # Filesystem
    FILE_CREATION = "FILE_CREATION"
    FILE_MODIFICATION = "FILE_MODIFICATION"
    FILE_DELETION = "FILE_DELETION"

    # OS Mechanics
    REGISTRY_MODIFICATION = "REGISTRY_MODIFICATION"
    SERVICE_INSTALLATION = "SERVICE_INSTALLATION"
    SCHEDULED_TASK = "SCHEDULED_TASK"

    # Anti-forensic / Impact
    SHADOW_DELETED = "SHADOW_DELETED"
    DEFENDER_EXCLUSION_ADDED = "DEFENDER_EXCLUSION_ADDED"

    # Detections
    ALERT = "ALERT"


class CanonicalEvent:
    """A strictly normalized forensic event.

    Unlike ECS which is a generic schema, CanonicalEvent enforces that
    specific fields exist depending on the CanonicalType, enabling
    deterministic behavior construction rules.
    """
    def __init__(
        self,
        *,
        event_id: str,
        case_id: str,
        host_name: str,
        timestamp: str,
        canonical_type: CanonicalType,
        source_index: str,
        source_doc_id: str,
        user: str = "",
        process_name: str = "",
        process_path: str = "",
        pid: int | None = None,
        command_line: str = "",
        target_file: str = "",
        remote_ip: str = "",
        remote_port: int | None = None,
        registry_key: str = "",
        alert_name: str = "",
        alert_level: str = "",
        raw_data: dict | None = None,
    ):
        # Identity & Provenance
        self.event_id = event_id  # Deterministic hash of the canonical fields
        self.case_id = case_id
        self.host_name = host_name
        self.timestamp = timestamp
        self.canonical_type = canonical_type
        
        # Link back to the raw OpenSearch document
        self.source_index = source_index
        self.source_doc_id = source_doc_id
        
        # Core Context
        self.user = user
        self.process_name = process_name
        self.process_path = process_path
        self.pid = pid
        self.command_line = command_line
        
        # Specific Contexts
        self.target_file = target_file
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.registry_key = registry_key
        
        # Alerts
        self.alert_name = alert_name
        self.alert_level = alert_level
        
        # Fallback for constructor logic
        self.raw_data = raw_data or {}

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "event_id": self.event_id,
            "case_id": self.case_id,
            "host_name": self.host_name,
            "@timestamp": self.timestamp,
            "canonical_type": self.canonical_type.value,
            "source_index": self.source_index,
            "source_doc_id": self.source_doc_id,
            "user": self.user,
            "canonical_user": self.user,
            "process_name": self.process_name,
            "process_path": self.process_path,
            "command_line": self.command_line,
            "target_file": self.target_file,
            "remote_ip": self.remote_ip,
            "registry_key": self.registry_key,
            "alert_name": self.alert_name,
            "alert_level": self.alert_level,
        }
        # Only emit numeric fields when they are non-None to avoid
        # OpenSearch dynamic-mapping conflicts (null vs long).
        if self.pid is not None:
            d["pid"] = self.pid
        if self.remote_port is not None:
            d["remote_port"] = self.remote_port
        return d
