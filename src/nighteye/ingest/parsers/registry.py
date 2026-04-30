"""Registry hive parser — converts RECmd CSV output to ECS documents.

Parses registry key/value data from SYSTEM, SAM, SOFTWARE, SECURITY,
NTUSER.DAT, and UsrClass.dat hives.
"""

from __future__ import annotations

from typing import Any, Iterator

from nighteye.ingest.ecs import build_ecs_doc

__all__ = ["parse_registry_record"]


def parse_registry_record(
    record: dict[str, Any],
    *,
    host_name: str = "",
    source_file: str = "",
    audit_id: str = "",
) -> dict[str, Any] | None:
    """Parse a single registry record (from RECmd CSV) into an ECS doc."""
    key_path = record.get("HivePath", "") or record.get("KeyPath", "")
    value_name = record.get("ValueName", "")
    value_data = record.get("ValueData", "") or record.get("ValueData2", "")
    value_type = record.get("ValueType", "")
    last_write = record.get("LastWriteTimestamp", "") or record.get("LastWriteTime", "")
    description = record.get("Description", "")
    category = record.get("Category", "")

    if not key_path:
        return None

    return build_ecs_doc(
        timestamp=last_write or None,
        host_name=host_name,
        event_action="registry-key-modified",
        event_category="configuration",
        nighteye_source_file=source_file,
        nighteye_audit_id=audit_id,
        nighteye_parser="recmd",
        nighteye_canonical_type="REGISTRY",
        extra={
            "registry.key": key_path,
            "registry.value_name": value_name,
            "registry.value_data": value_data,
            "registry.value_type": value_type,
            "registry.description": description,
            "registry.category": category,
        },
    )
