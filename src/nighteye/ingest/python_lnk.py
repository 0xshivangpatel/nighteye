"""LNK shortcut parser via pylnk3 — fallback when LECmd is unavailable.

Parses Windows .lnk shortcut files to extract target path, arguments,
working directory, icon location, and timestamps.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

logger = logging.getLogger("nighteye.ingest.python_lnk")


def parse_lnk(
    path: Path,
    *,
    host_name: str = "",
    source_file: str = "",
    audit_id: str = "",
) -> Iterator[dict[str, Any]]:
    """Yield one ECS document from a Windows .lnk shortcut file.

    Requires the ``pylnk3`` library. If not installed, logs a debug
    message and yields nothing.

    Args:
        path: Path to the .lnk file.
        host_name: Host name for the host.name ECS field.
        source_file: Source file path for provenance.
        audit_id: Audit trail ID.

    Yields:
        One ECS document dict.
    """
    try:
        from pylnk3 import LNK
    except ImportError:
        logger.debug("pylnk3 not installed; skipping LNK %s", path.name)
        return

    from nighteye.ingest.ecs import build_ecs_doc

    try:
        lnk = LNK.parse(str(path))
    except Exception as exc:
        logger.debug("Failed to parse LNK %s: %s", path.name, exc)
        return

    try:
        target_path = ""
        arguments = ""
        working_dir = ""
        icon_location = ""
        local_path = ""
        network_path = ""

        if hasattr(lnk, "link_info") and lnk.link_info is not None:
            li = lnk.link_info
            if hasattr(li, "local_base_path") and li.local_base_path:
                local_path = str(li.local_base_path)
            if hasattr(li, "network_path") and li.network_path:
                network_path = str(li.network_path)

        target_path = local_path or network_path or ""

        if hasattr(lnk, "arguments") and lnk.arguments:
            arguments = str(lnk.arguments)

        if hasattr(lnk, "working_directory") and lnk.working_directory:
            working_dir = str(lnk.working_directory)

        if hasattr(lnk, "icon_location") and lnk.icon_location:
            icon_location = str(lnk.icon_location)

        # Extract timestamps
        creation_time = None
        access_time = None
        write_time = None

        if hasattr(lnk, "creation_time") and lnk.creation_time:
            try:
                creation_time = _fmt_dt(lnk.creation_time)
            except Exception:
                pass

        if hasattr(lnk, "access_time") and lnk.access_time:
            try:
                access_time = _fmt_dt(lnk.access_time)
            except Exception:
                pass

        if hasattr(lnk, "write_time") and lnk.write_time:
            try:
                write_time = _fmt_dt(lnk.write_time)
            except Exception:
                pass

        timestamp = write_time or creation_time or access_time

        extra: dict[str, Any] = {
            "lnk.target_path": target_path,
            "lnk.arguments": arguments,
            "lnk.working_directory": working_dir,
            "lnk.icon_location": icon_location,
            "lnk.local_path": local_path,
            "lnk.network_path": network_path,
            "lnk.creation_time": creation_time,
            "lnk.access_time": access_time,
            "lnk.write_time": write_time,
            "lnk.file": str(path),
        }

        doc = build_ecs_doc(
            timestamp=timestamp,
            host_name=host_name,
            event_action="lnk-parsed",
            event_category="file",
            process_executable=target_path if target_path else None,
            file_path=str(path),
            nighteye_source_file=source_file or str(path),
            nighteye_audit_id=audit_id,
            nighteye_parser="pylnk3",
            nighteye_canonical_type="LNK_SHORTCUT",
            extra=extra,
        )
        yield doc

    except Exception as exc:
        logger.warning("Error extracting LNK fields from %s: %s", path.name, exc)


def _fmt_dt(dt: Any) -> str | None:
    """Convert a datetime-like object to ISO 8601 UTC string."""
    from datetime import datetime

    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.UTC)
        return dt.astimezone(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S") + "Z"
    return str(dt)
