"""Shimcache (AppCompatCache) parser — converts AppCompatCacheParser output to ECS.

Parses application compatibility cache entries for execution evidence.
"""

from __future__ import annotations

from typing import Any

from nighteye.ingest.ecs import build_ecs_doc

__all__ = ["parse_shimcache_record"]


def parse_shimcache_record(
    record: dict[str, Any],
    *,
    host_name: str = "",
    source_file: str = "",
    audit_id: str = "",
) -> dict[str, Any] | None:
    """Parse a single Shimcache record into an ECS doc."""
    cache_entry_pos = record.get("CacheEntryPosition", "")
    path = record.get("Path", "")
    last_modified = record.get("LastModifiedTimeUTC", "") or record.get("LastModified", "")
    executed = record.get("Executed", "")
    data_size = record.get("DataSize", "")
    control_set = record.get("ControlSet", "")

    if not path:
        return None

    process_name = path.rsplit("\\", 1)[-1] if path else ""

    return build_ecs_doc(
        timestamp=last_modified or None,
        host_name=host_name,
        event_action="shimcache-entry",
        event_category="process",
        process_name=process_name,
        process_executable=path,
        file_path=path,
        nighteye_source_file=source_file,
        nighteye_audit_id=audit_id,
        nighteye_parser="appcompatcacheparser",
        nighteye_canonical_type="SHIMCACHE",
        extra={
            "shimcache.position": str(cache_entry_pos),
            "shimcache.executed": str(executed),
            "shimcache.data_size": str(data_size),
            "shimcache.control_set": str(control_set),
        },
    )
