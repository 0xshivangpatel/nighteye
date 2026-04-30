"""MFT parser — converts MFTECmd CSV output to ECS documents.

Parses $MFT entries for file system timeline reconstruction.
"""

from __future__ import annotations

from typing import Any

from nighteye.ingest.ecs import build_ecs_doc

__all__ = ["parse_mft_record"]


def parse_mft_record(
    record: dict[str, Any],
    *,
    host_name: str = "",
    source_file: str = "",
    audit_id: str = "",
) -> dict[str, Any] | None:
    """Parse a single MFT record (from MFTECmd CSV) into an ECS doc."""
    entry_number = record.get("EntryNumber", "")
    parent_path = record.get("ParentPath", "")
    filename = record.get("FileName", "")
    extension = record.get("Extension", "")
    file_size = record.get("FileSize", "")
    is_directory = record.get("IsDirectory", "")

    # MFT has multiple timestamps
    created = record.get("Created0x10", "") or record.get("Created", "")
    modified = record.get("LastModified0x10", "") or record.get("LastModified", "")
    accessed = record.get("LastAccess0x10", "") or record.get("LastAccess", "")
    si_created = record.get("Created0x30", "")
    in_use = record.get("InUse", "")

    if not filename:
        return None

    full_path = f"{parent_path}\\{filename}" if parent_path else filename

    # Detect timestomping: SI vs FN timestamps divergence
    timestomped = ""
    if si_created and created and si_created != created:
        timestomped = "possible"

    size_int = None
    if file_size:
        try:
            size_int = int(file_size)
        except (ValueError, TypeError):
            pass

    return build_ecs_doc(
        timestamp=modified or created or None,
        host_name=host_name,
        event_action="file-metadata",
        event_category="file",
        file_path=full_path,
        nighteye_source_file=source_file,
        nighteye_audit_id=audit_id,
        nighteye_parser="mftecmd",
        nighteye_canonical_type="MFT_ENTRY",
        extra={
            "mft.entry_number": str(entry_number),
            "mft.created": created,
            "mft.modified": modified,
            "mft.accessed": accessed,
            "mft.si_created": si_created,
            "mft.in_use": str(in_use),
            "mft.is_directory": str(is_directory),
            "mft.extension": extension,
            "mft.file_size": size_int,
            "mft.timestomped": timestomped,
        },
    )
