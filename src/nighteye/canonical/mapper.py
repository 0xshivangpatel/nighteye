"""Canonical Event Mapper.

Translates raw ECS OpenSearch documents into strongly-typed CanonicalEvents.
"""

from __future__ import annotations

import hashlib
from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType

__all__ = ["map_ecs_to_canonical"]


def map_ecs_to_canonical(
    doc: dict[str, Any],
    doc_id: str,
    index_name: str,
    case_id: str,
) -> CanonicalEvent | None:
    """Map a raw ECS document to a CanonicalEvent.

    Args:
        doc: The ECS document (usually from OpenSearch `_source`).
        doc_id: The OpenSearch document ID `_id`.
        index_name: The OpenSearch index name `_index`.
        case_id: The active case ID.

    Returns:
        A CanonicalEvent, or None if the document does not map to a
        supported canonical behavior type.
    """
    timestamp = doc.get("@timestamp")
    host_name = doc.get("host", {}).get("name", "")
    if not timestamp or not host_name:
        return None

    event_kind = doc.get("event", {}).get("kind", "")
    event_action = doc.get("event", {}).get("action", "")
    event_category = doc.get("event", {}).get("category", [])
    if isinstance(event_category, str):
        event_category = [event_category]

    canonical_type: CanonicalType | None = None
    
    # Common extraction
    user = doc.get("user", {}).get("name", "")
    process_name = doc.get("process", {}).get("name", "")
    process_path = doc.get("process", {}).get("executable", "") or doc.get("file", {}).get("path", "")
    pid = doc.get("process", {}).get("pid")
    command_line = doc.get("process", {}).get("command_line", "")
    target_file = doc.get("file", {}).get("path", "")
    
    remote_ip = doc.get("destination", {}).get("ip", "")
    remote_port = doc.get("destination", {}).get("port")
    if not remote_ip:
        # Check source if destination isn't set
        remote_ip = doc.get("source", {}).get("ip", "")
        remote_port = doc.get("source", {}).get("port")

    # ECS uses nested objects, not dotted keys. Support both the nested
    # form (correct) and a flattened form (some tools emit this).
    registry_obj = doc.get("registry") or {}
    if isinstance(registry_obj, dict):
        registry_key = (
            registry_obj.get("key")
            or registry_obj.get("path")
            or registry_obj.get("value_data", "")
        )
    else:
        registry_key = doc.get("registry.value_data", "") or doc.get("registry.key", "")

    rule_obj = doc.get("rule") or {}
    if isinstance(rule_obj, dict):
        alert_name = rule_obj.get("name", "")
        alert_level = rule_obj.get("level", "")
    else:
        alert_name = doc.get("rule.name", "")
        alert_level = doc.get("rule.level", "")

    # 1. Map Alerts
    if event_kind == "alert" or event_action == "sigma-alert":
        canonical_type = CanonicalType.ALERT

    # 2. Map Execution (EVTX 4688, Prefetch, Amcache, Shimcache)
    elif "process" in event_category and (
        "execution" in event_action or "executed" in event_action or "shimcache" in event_action
    ):
        canonical_type = CanonicalType.PROCESS_EXECUTION

    # 3. Map Authentication (EVTX 4624, 4625)
    elif "authentication" in event_category or "logon" in event_action:
        canonical_type = CanonicalType.AUTHENTICATION

    # 4. Map Network (EVTX network events, Volatility netscan)
    elif "network" in event_category or "network-connection" in event_action:
        canonical_type = CanonicalType.NETWORK_CONNECTION

    # 5. Map File Operations (MFT, EVTX file shares/access)
    elif "file" in event_category:
        if "creation" in event_action or "created" in event_action:
            canonical_type = CanonicalType.FILE_CREATION
        elif "deletion" in event_action or "deleted" in event_action:
            canonical_type = CanonicalType.FILE_DELETION
        else:
            canonical_type = CanonicalType.FILE_MODIFICATION

    # 6. Map Service / Scheduled Tasks (EVTX 7045, 4698)
    elif "service-installation" in event_action:
        canonical_type = CanonicalType.SERVICE_INSTALLATION
    elif "scheduled-task-created" in event_action:
        canonical_type = CanonicalType.SCHEDULED_TASK

    # 7. Map Registry (RECmd)
    elif "registry" in event_action:
        canonical_type = CanonicalType.REGISTRY_MODIFICATION

    if not canonical_type:
        return None

    # Compute deterministic Event ID
    # Hash of case + host + timestamp + canonical_type + src_id
    payload = f"{case_id}:{host_name}:{timestamp}:{canonical_type.value}:{doc_id}"
    event_id = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    return CanonicalEvent(
        event_id=event_id,
        case_id=case_id,
        host_name=host_name,
        timestamp=timestamp,
        canonical_type=canonical_type,
        source_index=index_name,
        source_doc_id=doc_id,
        user=user,
        process_name=process_name,
        process_path=process_path,
        pid=pid,
        command_line=command_line,
        target_file=target_file,
        remote_ip=remote_ip,
        remote_port=remote_port,
        registry_key=registry_key,
        alert_name=alert_name,
        alert_level=alert_level,
        raw_data=doc,
    )
