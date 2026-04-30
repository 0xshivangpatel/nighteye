"""EVTX file parser — converts Windows Event Log files to ECS documents.

Uses the ``evtx`` Python library (pure Python, no external tools needed)
to parse .evtx files and emit ECS-mapped documents for OpenSearch indexing.

For production scale (SRL-2015/2018), this also supports EvtxECmd (Eric
Zimmerman's tool) as an optional accelerator. Falls back to pure-Python
parsing when EvtxECmd is not installed.

References:
    - docs/ARCHITECTURE.md § 4 (Layer 1: EVTX ingestion)
    - docs/BUILD_PLAN.md D5 (EVTX ingest end-to-end)
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from nighteye.ingest.ecs import build_ecs_doc, compute_doc_id, normalize_timestamp

__all__ = [
    "parse_evtx_file",
    "parse_evtx_xml_event",
    "has_evtxecmd",
    "EVTXECMD_PATH",
]

logger = logging.getLogger("nighteye.ingest.evtx")

# XML namespace for Windows Event Log
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Path to EvtxECmd (optional, detected at import time)
EVTXECMD_PATH: str | None = shutil.which("EvtxECmd") or shutil.which("EvtxECmd.exe")


def has_evtxecmd() -> bool:
    """Check if EvtxECmd is available on PATH."""
    return EVTXECMD_PATH is not None


# ============================================================
# Pure-Python EVTX parsing (via evtx library)
# ============================================================


def parse_evtx_file(
    evtx_path: Path,
    *,
    case_id: str = "",
    host_name: str = "",
    audit_id: str = "",
    use_evtxecmd: bool = False,
) -> Iterator[dict[str, Any]]:
    """Parse an EVTX file and yield ECS-mapped documents.

    This is a generator — it yields one document per event, making it
    memory-efficient for large EVTX files (100MB+ with 500K+ events).

    Args:
        evtx_path: Path to the .evtx file.
        case_id: Case ID for doc ID computation.
        host_name: Host name for the host.name ECS field.
        audit_id: Audit trail ID for provenance tracking.
        use_evtxecmd: If True and EvtxECmd is available, use it
            for faster parsing. Falls back to pure-Python.

    Yields:
        ECS document dicts ready for OpenSearch indexing.
    """
    if use_evtxecmd and has_evtxecmd():
        yield from _parse_via_evtxecmd(evtx_path, case_id, host_name, audit_id)
        return

    # Pure-Python fallback using the `evtx` library
    try:
        import evtx as evtx_lib
    except ImportError:
        logger.warning(
            "Neither EvtxECmd nor python-evtx installed. "
            "Install with: pip install evtx"
        )
        return

    logger.info("Parsing EVTX (pure-Python): %s", evtx_path)
    source_file = str(evtx_path)
    event_count = 0

    try:
        with open(evtx_path, "rb") as f:
            parser = evtx_lib.PyEvtxParser(f)
            for record in parser.records():
                try:
                    xml_str = record.get("data", "")
                    if not xml_str:
                        continue

                    doc = parse_evtx_xml_event(
                        xml_str,
                        host_name=host_name,
                        source_file=source_file,
                        audit_id=audit_id,
                    )
                    if doc:
                        event_count += 1
                        yield doc
                except Exception as exc:
                    logger.debug("Failed to parse record: %s", exc)
                    continue

    except Exception as exc:
        logger.error("Failed to open EVTX file %s: %s", evtx_path, exc)
        return

    logger.info("Parsed %d events from %s", event_count, evtx_path.name)


def parse_evtx_xml_event(
    xml_str: str,
    *,
    host_name: str = "",
    source_file: str = "",
    audit_id: str = "",
) -> dict[str, Any] | None:
    """Parse a single EVTX XML event string into an ECS document.

    This handles the Windows Event Log XML schema and maps fields
    to ECS v8.x.

    Args:
        xml_str: Raw XML string from the EVTX record.
        host_name: Host name override (from directory detection).
        source_file: Source file path for provenance.
        audit_id: Audit trail ID.

    Returns:
        ECS document dict, or None if parsing fails.
    """
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    # Helper: find with namespace, fallback to bare name
    def _find(parent: ET.Element, tag: str) -> ET.Element | None:
        elem = parent.find(f"e:{tag}", _NS)
        if elem is not None:
            return elem
        return parent.find(tag)

    # Extract System fields
    system = _find(root, "System")
    if system is None:
        return None

    # Event ID
    event_id_elem = _find(system, "EventID")
    event_code = event_id_elem.text if event_id_elem is not None and event_id_elem.text else ""

    # Timestamp
    time_created = _find(system, "TimeCreated")
    timestamp = None
    if time_created is not None:
        timestamp = time_created.get("SystemTime", "")

    # Computer name (use as host if not overridden)
    computer_elem = _find(system, "Computer")
    computer = computer_elem.text if computer_elem is not None and computer_elem.text else ""
    if not host_name:
        host_name = computer

    # Channel (log name)
    channel_elem = _find(system, "Channel")
    channel = channel_elem.text if channel_elem is not None and channel_elem.text else ""

    # Provider
    provider_elem = _find(system, "Provider")
    provider_name = ""
    if provider_elem is not None:
        provider_name = provider_elem.get("Name", "")

    # Process ID and Thread ID from Execution
    execution_elem = _find(system, "Execution")
    process_id = None
    if execution_elem is not None:
        pid_str = execution_elem.get("ProcessID", "")
        if pid_str:
            try:
                process_id = int(pid_str)
            except ValueError:
                pass

    # Extract EventData fields
    event_data: dict[str, str] = {}
    event_data_elem = _find(root, "EventData")
    if event_data_elem is not None:
        for data_elem in event_data_elem:
            name = data_elem.get("Name", "")
            value = data_elem.text or ""
            if name:
                event_data[name] = value

    # Map common EventData fields to ECS
    user_name = event_data.get("TargetUserName", event_data.get("SubjectUserName", ""))
    user_domain = event_data.get("TargetDomainName", event_data.get("SubjectDomainName", ""))
    user_id = event_data.get("TargetUserSid", event_data.get("SubjectUserSid", ""))
    process_name = event_data.get("ProcessName", event_data.get("NewProcessName", ""))
    parent_process_name = event_data.get("ParentProcessName", "")
    command_line = event_data.get("CommandLine", "")
    source_ip = event_data.get("IpAddress", "")
    source_port_str = event_data.get("IpPort", "")
    logon_type = event_data.get("LogonType", "")

    # Determine event action from event ID
    event_action = _event_id_to_action(event_code)
    event_category = _event_id_to_category(event_code)

    source_port = None
    if source_port_str:
        try:
            source_port = int(source_port_str)
        except ValueError:
            pass

    # Build winlog metadata for extra fields
    winlog_extra: dict[str, Any] = {}
    if channel:
        winlog_extra["channel"] = channel
    if provider_name:
        winlog_extra["provider_name"] = provider_name

    # Build the ECS document
    doc = build_ecs_doc(
        timestamp=timestamp,
        host_name=host_name,
        event_code=event_code,
        event_action=event_action,
        event_category=event_category,
        user_name=user_name,
        user_domain=user_domain,
        user_id=user_id,
        process_pid=process_id,
        process_name=process_name,
        process_command_line=command_line,
        source_ip=source_ip if source_ip and source_ip != "-" else "",
        source_port=source_port,
        winlog_event_data=event_data if event_data else None,
        nighteye_source_file=source_file,
        nighteye_audit_id=audit_id,
        nighteye_parser="evtx-python",
        nighteye_canonical_type="WINDOWS_EVENT",
    )

    # Add winlog channel/provider as nested fields
    if winlog_extra:
        doc.setdefault("winlog", {}).update(winlog_extra)

    return doc


# ============================================================
# EvtxECmd accelerated parsing
# ============================================================


def _parse_via_evtxecmd(
    evtx_path: Path,
    case_id: str,
    host_name: str,
    audit_id: str,
) -> Iterator[dict[str, Any]]:
    """Parse EVTX using EvtxECmd for higher performance.

    EvtxECmd outputs JSON lines which we map to ECS.
    """
    assert EVTXECMD_PATH is not None
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = Path(tmpdir) / "output.json"
        cmd = [
            EVTXECMD_PATH,
            "-f", str(evtx_path),
            "--json", tmpdir,
            "--jsonf", "output.json",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 min max
            )
            if result.returncode != 0:
                logger.warning(
                    "EvtxECmd returned %d: %s",
                    result.returncode,
                    result.stderr[:500],
                )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.error("EvtxECmd failed: %s", exc)
            return

        if not out_file.exists():
            logger.warning("EvtxECmd produced no output for %s", evtx_path)
            return

        source_file = str(evtx_path)
        event_count = 0

        with open(out_file, "r", encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    doc = _evtxecmd_record_to_ecs(
                        record,
                        host_name=host_name,
                        source_file=source_file,
                        audit_id=audit_id,
                    )
                    if doc:
                        event_count += 1
                        yield doc
                except json.JSONDecodeError:
                    continue

        logger.info(
            "Parsed %d events from %s via EvtxECmd",
            event_count,
            evtx_path.name,
        )


def _evtxecmd_record_to_ecs(
    record: dict[str, Any],
    host_name: str,
    source_file: str,
    audit_id: str,
) -> dict[str, Any] | None:
    """Map an EvtxECmd JSON record to an ECS document."""
    event_code = str(record.get("EventId", ""))
    timestamp = record.get("TimeCreated", "")
    computer = record.get("Computer", "")
    channel = record.get("Channel", "")
    provider = record.get("Provider", "")

    if not host_name:
        host_name = computer

    # EvtxECmd puts parsed fields in PayloadData1-6
    payload_data: dict[str, str] = {}
    for i in range(1, 7):
        key = f"PayloadData{i}"
        val = record.get(key, "")
        if val:
            payload_data[key] = str(val)

    # Map event data
    map_desc = record.get("MapDescription", "")
    user_name = record.get("UserName", "")

    event_action = _event_id_to_action(event_code)
    event_category = _event_id_to_category(event_code)

    return build_ecs_doc(
        timestamp=timestamp,
        host_name=host_name,
        event_code=event_code,
        event_action=event_action or map_desc,
        event_category=event_category,
        user_name=user_name,
        nighteye_source_file=source_file,
        nighteye_audit_id=audit_id,
        nighteye_parser="evtxecmd",
        nighteye_canonical_type="WINDOWS_EVENT",
        winlog_event_data=payload_data if payload_data else None,
        extra={
            "winlog.channel": channel,
            "winlog.provider_name": provider,
        } if channel or provider else None,
    )


# ============================================================
# Event ID mapping tables
# ============================================================

# Security-relevant event IDs → human-readable actions
_EVENT_ACTIONS: dict[str, str] = {
    # Logon / Logoff
    "4624": "logon-success",
    "4625": "logon-failure",
    "4634": "logoff",
    "4647": "user-initiated-logoff",
    "4648": "explicit-credentials-logon",
    "4672": "special-privileges-assigned",
    # Account management
    "4720": "user-account-created",
    "4722": "user-account-enabled",
    "4724": "password-reset-attempt",
    "4725": "user-account-disabled",
    "4726": "user-account-deleted",
    "4728": "member-added-to-global-group",
    "4732": "member-added-to-local-group",
    "4756": "member-added-to-universal-group",
    # Process
    "4688": "process-created",
    "4689": "process-terminated",
    # Service
    "7045": "service-installed",
    "7036": "service-state-changed",
    # Scheduled task
    "4698": "scheduled-task-created",
    "4702": "scheduled-task-updated",
    # Object access
    "4663": "object-access-attempt",
    "4660": "object-deleted",
    "4656": "handle-requested",
    # Firewall
    "5156": "network-connection-allowed",
    "5157": "network-connection-blocked",
    # PowerShell
    "4104": "script-block-logged",
    "4103": "module-logged",
    # Remote Desktop
    "21": "rdp-logon-succeeded",
    "24": "rdp-session-disconnected",
    "25": "rdp-session-reconnected",
    # WMI
    "5861": "wmi-activity",
    # Sysmon
    "1": "process-create",
    "3": "network-connection",
    "7": "image-loaded",
    "8": "create-remote-thread",
    "10": "process-access",
    "11": "file-create",
    "12": "registry-object-added-deleted",
    "13": "registry-value-set",
    "15": "file-create-stream-hash",
    "22": "dns-query",
    "23": "file-delete",
    "25": "process-tampering",
}

_EVENT_CATEGORIES: dict[str, str] = {
    "4624": "authentication",
    "4625": "authentication",
    "4634": "authentication",
    "4647": "authentication",
    "4648": "authentication",
    "4672": "authentication",
    "4720": "iam",
    "4722": "iam",
    "4724": "iam",
    "4725": "iam",
    "4726": "iam",
    "4728": "iam",
    "4732": "iam",
    "4756": "iam",
    "4688": "process",
    "4689": "process",
    "7045": "configuration",
    "4698": "configuration",
    "4663": "file",
    "4660": "file",
    "4104": "process",
    "5156": "network",
    "5157": "network",
    "1": "process",
    "3": "network",
    "11": "file",
    "22": "network",
}


def _event_id_to_action(event_id: str) -> str:
    return _EVENT_ACTIONS.get(event_id, "")


def _event_id_to_category(event_id: str) -> str:
    return _EVENT_CATEGORIES.get(event_id, "")
