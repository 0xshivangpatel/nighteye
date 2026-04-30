"""Prefetch parser — converts PECmd CSV output to ECS documents.

Parses Windows Prefetch files for execution evidence.
"""

from __future__ import annotations

from typing import Any

from nighteye.ingest.ecs import build_ecs_doc

__all__ = ["parse_prefetch_record"]


def parse_prefetch_record(
    record: dict[str, Any],
    *,
    host_name: str = "",
    source_file: str = "",
    audit_id: str = "",
) -> dict[str, Any] | None:
    """Parse a single Prefetch record (from PECmd CSV) into an ECS doc."""
    executable = record.get("ExecutableName", "") or record.get("SourceFilename", "")
    run_count = record.get("RunCount", "")
    last_run = record.get("LastRun", "") or record.get("SourceModified", "")
    prev_run_0 = record.get("PreviousRun0", "")
    prev_run_1 = record.get("PreviousRun1", "")
    prev_run_2 = record.get("PreviousRun2", "")
    volume_name = record.get("Volume0Name", "")
    volume_serial = record.get("Volume0Serial", "")
    pf_hash = record.get("Hash", "")
    directories = record.get("Directories", "")
    files_loaded = record.get("FilesLoaded", "")

    if not executable:
        return None

    run_count_int = None
    if run_count:
        try:
            run_count_int = int(run_count)
        except (ValueError, TypeError):
            pass

    return build_ecs_doc(
        timestamp=last_run or None,
        host_name=host_name,
        event_action="process-execution-evidence",
        event_category="process",
        process_name=executable,
        nighteye_source_file=source_file,
        nighteye_audit_id=audit_id,
        nighteye_parser="pecmd",
        nighteye_canonical_type="PREFETCH",
        extra={
            "prefetch.executable": executable,
            "prefetch.run_count": run_count_int,
            "prefetch.last_run": last_run,
            "prefetch.previous_runs": [
                r for r in [prev_run_0, prev_run_1, prev_run_2] if r
            ],
            "prefetch.hash": pf_hash,
            "prefetch.volume_name": volume_name,
            "prefetch.volume_serial": volume_serial,
            "prefetch.directories": directories,
        },
    )
