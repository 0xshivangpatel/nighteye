"""SRUM parser — converts SrumECmd CSV output to ECS documents.

Parses System Resource Usage Monitor (SRUM) data for network usage,
application runtime, and energy consumption evidence.
"""

from __future__ import annotations

from typing import Any

from nighteye.ingest.ecs import build_ecs_doc

__all__ = ["parse_srum_record"]


def parse_srum_record(
    record: dict[str, Any],
    *,
    host_name: str = "",
    source_file: str = "",
    audit_id: str = "",
) -> dict[str, Any] | None:
    """Parse a single SRUM record into an ECS doc."""
    timestamp = record.get("Timestamp", "") or record.get("TimeStamp", "")
    exe_info = record.get("ExeInfo", "") or record.get("AppId", "")
    user_sid = record.get("SidType", "") or record.get("UserSid", "")
    bytes_sent = record.get("BytesSent", "")
    bytes_received = record.get("BytesRecvd", "") or record.get("BytesReceived", "")
    foreground_time = record.get("ForegroundCycleTime", "")
    background_time = record.get("BackgroundCycleTime", "")
    network_adapter = record.get("InterfaceLuid", "") or record.get("L2ProfileId", "")
    profile_name = record.get("ProfileName", "")

    if not exe_info and not timestamp:
        return None

    process_name = exe_info.rsplit("\\", 1)[-1] if exe_info and "\\" in exe_info else exe_info

    sent_int = None
    recv_int = None
    if bytes_sent:
        try:
            sent_int = int(bytes_sent)
        except (ValueError, TypeError):
            pass
    if bytes_received:
        try:
            recv_int = int(bytes_received)
        except (ValueError, TypeError):
            pass

    return build_ecs_doc(
        timestamp=timestamp or None,
        host_name=host_name,
        event_action="resource-usage",
        event_category="process",
        process_name=process_name,
        process_executable=exe_info if "\\" in str(exe_info) else "",
        user_id=user_sid,
        nighteye_source_file=source_file,
        nighteye_audit_id=audit_id,
        nighteye_parser="srumecmd",
        nighteye_canonical_type="SRUM",
        extra={
            "srum.bytes_sent": sent_int,
            "srum.bytes_received": recv_int,
            "srum.foreground_time": foreground_time,
            "srum.background_time": background_time,
            "srum.network_adapter": network_adapter,
            "srum.profile_name": profile_name,
        },
    )
