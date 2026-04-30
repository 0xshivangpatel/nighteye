"""Amcache parser — converts AmcacheParser CSV output to ECS documents.

Parses Amcache.hve entries for application execution and install evidence.
"""

from __future__ import annotations

from typing import Any

from nighteye.ingest.ecs import build_ecs_doc

__all__ = ["parse_amcache_record"]


def parse_amcache_record(
    record: dict[str, Any],
    *,
    host_name: str = "",
    source_file: str = "",
    audit_id: str = "",
) -> dict[str, Any] | None:
    """Parse a single Amcache record into an ECS doc."""
    full_path = record.get("FullPath", "") or record.get("ProgramName", "")
    sha1 = record.get("SHA1", "") or record.get("FileId", "")
    file_size = record.get("FileSize", "")
    publisher = record.get("Publisher", "")
    product_name = record.get("ProductName", "")
    product_version = record.get("ProductVersion", "")
    file_version = record.get("FileVersion", "")
    pe_header_hash = record.get("PeHeaderHash", "")
    link_date = record.get("LinkDate", "")
    last_modified = record.get("FileKeyLastWriteTimestamp", "") or record.get("LastModified", "")
    binary_type = record.get("BinaryType", "")
    is_pe = record.get("IsPeFile", "")
    is_os_component = record.get("IsOsComponent", "")

    if not full_path and not sha1:
        return None

    # Extract just the filename for process.name
    process_name = full_path.rsplit("\\", 1)[-1] if full_path else ""

    size_int = None
    if file_size:
        try:
            size_int = int(file_size)
        except (ValueError, TypeError):
            pass

    return build_ecs_doc(
        timestamp=last_modified or link_date or None,
        host_name=host_name,
        event_action="application-installed-or-executed",
        event_category="package",
        process_name=process_name,
        process_executable=full_path,
        file_path=full_path,
        nighteye_source_file=source_file,
        nighteye_audit_id=audit_id,
        nighteye_parser="amcacheparser",
        nighteye_canonical_type="AMCACHE",
        extra={
            "amcache.sha1": sha1,
            "amcache.publisher": publisher,
            "amcache.product_name": product_name,
            "amcache.product_version": product_version,
            "amcache.file_version": file_version,
            "amcache.pe_header_hash": pe_header_hash,
            "amcache.link_date": link_date,
            "amcache.binary_type": binary_type,
            "amcache.is_pe": str(is_pe),
            "amcache.is_os_component": str(is_os_component),
            "amcache.file_size": size_int,
        },
    )
