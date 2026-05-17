"""Plaso storage (.plaso) re-exporter → ECS documents.

Hosts that ship only as Plaso storage files (no raw E01) get processed
here. We invoke ``psort -o json_line`` to expand each event back to its
full structured form (rather than the lossy l2tcsv export the original
SANS distribution shipped) and yield ECS documents the executor can
bulk-index.

This is what gives nfury and controller — which have no raw artifacts —
canonical events with proper EventID + EventData + computer_name +
process_name fields, instead of the 17-column l2tcsv summary.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("nighteye.ingest.plaso_storage")

__all__ = ["is_psort_available", "parse_plaso_storage"]

# ---------------------------------------------------------------------------
# Plaso data_type / EVTX EventID → canonical type mapping
# ---------------------------------------------------------------------------

_DATATYPE_TO_CANONICAL: dict[str, str] = {
    "fs:stat": "FILE_MODIFICATION",
    "fs:stat:ntfs": "FILE_MODIFICATION",
    "windows:registry:key_value": "REGISTRY_MODIFICATION",
    "windows:registry:appcompatcache": "PROCESS_EXECUTION",
    "windows:registry:bagmru": "FILE_CREATION",
    "windows:registry:run": "REGISTRY_MODIFICATION",
    "windows:registry:userassist": "PROCESS_EXECUTION",
    "windows:registry:windows_version": "REGISTRY_MODIFICATION",
    "windows:lnk:link": "FILE_CREATION",
    "windows:prefetch:execution": "PROCESS_EXECUTION",
    "windows:shell_item:file_entry": "FILE_CREATION",
    "windows:tasks:job": "SCHEDULED_TASK",
    "msie:webcache:container": "NETWORK_CONNECTION",
    "msiecf:url": "NETWORK_CONNECTION",
    "firefox:places:bookmark": "NETWORK_CONNECTION",
    "firefox:places:page_visited": "NETWORK_CONNECTION",
}

_EVTX_EID_TO_CANONICAL: dict[str, str] = {
    "1": "PROCESS_EXECUTION", "4688": "PROCESS_EXECUTION", "4689": "PROCESS_EXECUTION",
    "3": "NETWORK_CONNECTION", "5156": "NETWORK_CONNECTION", "5157": "NETWORK_CONNECTION",
    "4624": "AUTHENTICATION", "4625": "AUTHENTICATION", "4634": "AUTHENTICATION",
    "4647": "AUTHENTICATION", "4648": "AUTHENTICATION", "4672": "AUTHENTICATION",
    "4768": "AUTHENTICATION", "4769": "TICKET_REQUEST", "4776": "AUTHENTICATION",
    "4778": "AUTHENTICATION", "4779": "AUTHENTICATION",
    "4656": "LSASS_ACCESS", "4663": "FILE_MODIFICATION",
    "11": "FILE_CREATION", "23": "FILE_DELETION",
    "12": "REGISTRY_MODIFICATION", "13": "REGISTRY_MODIFICATION", "4657": "REGISTRY_MODIFICATION",
    "7045": "SERVICE_INSTALLATION", "7036": "SERVICE_INSTALLATION", "4697": "SERVICE_INSTALLATION",
    "4698": "SCHEDULED_TASK", "4702": "SCHEDULED_TASK",
    "1102": "LOG_CLEARED", "104": "LOG_CLEARED",
    "4934": "REPLICATION", "4935": "REPLICATION",
}

_EVENT_DATA_KEYS = (
    "LogonType", "IpAddress", "TargetUserName", "WorkstationName",
    "ProcessCommandLine", "ProcessName", "ServiceName", "SubjectUserName",
)

# ---------------------------------------------------------------------------
# Windows Security-channel Strings-array decoders
# ---------------------------------------------------------------------------
# Plaso renders winevt records with the EventData StringArray printed
# positionally (e.g. `Strings: ['S-1-..', 'user', 'domain', ...]`). We
# decode each known EventID back into named fields so constructors see
# the same `winlog.event_data.LogonType` / `IpAddress` / etc. they get
# from EvtxECmd-derived events. Positions come from Microsoft's
# documented event schemas (EventID 4624, 4688, 4697, 4769, etc.).

# Mapping: event_id (str) → list[str] of field names in order
# Use empty string for positions we don't care to name.
_EVENT_STRINGS_LAYOUT: dict[str, list[str]] = {
    # 4624 - Successful logon
    "4624": [
        "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
        "TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId",
        "LogonType", "LogonProcessName", "AuthenticationPackageName",
        "WorkstationName", "LogonGuid", "TransmittedServices", "LmPackageName",
        "KeyLength", "ProcessId", "ProcessName", "IpAddress", "IpPort",
    ],
    # 4625 - Failed logon (same prefix as 4624 up through LogonType, then differs)
    "4625": [
        "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
        "TargetUserSid", "TargetUserName", "TargetDomainName", "Status",
        "FailureReason", "SubStatus", "LogonType", "LogonProcessName",
        "AuthenticationPackageName", "WorkstationName", "TransmittedServices",
        "LmPackageName", "KeyLength", "ProcessId", "ProcessName",
        "IpAddress", "IpPort",
    ],
    # 4634 - Logoff
    "4634": ["TargetUserSid", "TargetUserName", "TargetDomainName",
             "TargetLogonId", "LogonType"],
    # 4647 - User-initiated logoff
    "4647": ["TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId"],
    # 4648 - Explicit credential logon (RunAs)
    "4648": [
        "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
        "LogonGuid", "TargetUserName", "TargetDomainName", "TargetLogonGuid",
        "TargetServerName", "TargetInfo", "ProcessId", "ProcessName",
        "IpAddress", "IpPort",
    ],
    # 4672 - Special privileges assigned to new logon
    "4672": ["SubjectUserSid", "SubjectUserName", "SubjectDomainName",
             "SubjectLogonId", "PrivilegeList"],
    # 4688 - Process creation
    "4688": [
        "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
        "NewProcessId", "NewProcessName", "TokenElevationType", "ProcessId",
        "CommandLine", "TargetUserSid", "TargetUserName", "TargetDomainName",
        "TargetLogonId", "ParentProcessName", "MandatoryLabel",
    ],
    # 4697 - Service installed (Security channel)
    "4697": [
        "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
        "ServiceName", "ServiceFileName", "ServiceType", "ServiceStartType",
        "ServiceAccount",
    ],
    # 7045 - Service installed (System channel)
    "7045": ["ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName"],
    # 4768 - Kerberos TGT requested
    "4768": [
        "TargetUserName", "TargetDomainName", "TargetSid", "ServiceName",
        "ServiceSid", "TicketOptions", "Status", "TicketEncryptionType",
        "PreAuthType", "IpAddress", "IpPort", "CertIssuerName",
        "CertSerialNumber", "CertThumbprint",
    ],
    # 4769 - Kerberos service ticket requested
    "4769": [
        "TargetUserName", "TargetDomainName", "ServiceName", "ServiceSid",
        "TicketOptions", "TicketEncryptionType", "IpAddress", "IpPort",
        "Status", "LogonGuid", "TransmittedServices",
    ],
    # 4770 - Kerberos service ticket renewed
    "4770": ["TargetUserName", "TargetDomainName", "ServiceName", "ServiceSid",
             "TicketOptions", "TicketEncryptionType"],
    # 4776 - NTLM credential validation
    "4776": ["PackageName", "TargetUserName", "Workstation", "Status"],
    # 4778 - Session reconnected (RDP)
    "4778": ["AccountName", "AccountDomain", "LogonID", "SessionName",
             "ClientName", "ClientAddress"],
    # 4779 - Session disconnected
    "4779": ["AccountName", "AccountDomain", "LogonID", "SessionName",
             "ClientName", "ClientAddress"],
    # 4656 - Object access (LSASS handle requested)
    "4656": [
        "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
        "ObjectServer", "ObjectType", "ObjectName", "HandleId", "TransactionId",
        "AccessList", "AccessReason", "AccessMask", "PrivilegeList",
        "RestrictedSidCount", "ProcessId", "ProcessName", "ResourceAttributes",
    ],
    # 4663 - Object access attempted
    "4663": [
        "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
        "ObjectServer", "ObjectType", "ObjectName", "HandleId", "AccessList",
        "AccessMask", "ProcessId", "ProcessName", "ResourceAttributes",
    ],
    # 1102 - Audit log cleared
    "1102": ["SubjectUserSid", "SubjectUserName", "SubjectDomainName",
             "SubjectLogonId"],
}

# Regex finds the python-list-repr that plaso prints after "Strings:".
_STRINGS_LIST_RE = re.compile(
    r"Strings:\s*\[(.*?)\](?:\s+Computer Name|\s+Record Number|\s*$)",
    re.DOTALL,
)
# Inside the list, items are single-quoted strings or `None`. Quotes can
# contain escaped chars and commas inside paths, so we use a tokenizer
# that respects single-quoted runs. `None` is captured in its own group
# so positional offsets stay correct — empty positions must still
# advance the index.
_STRING_ITEM_RE = re.compile(r"'((?:[^'\\]|\\.)*)'|(None)|([^,\s][^,]*)")


def _parse_strings_array(message: str, event_id: str) -> dict[str, str]:
    """Decode plaso's `Strings: [...]` field into named EventData fields.

    Returns an empty dict if no Strings list is present or no layout is
    known for this event_id. Critical that positional integrity is
    preserved: a `None` in the middle of the list must take its slot
    or every subsequent field is misaligned.
    """
    if not message or not event_id:
        return {}
    layout = _EVENT_STRINGS_LAYOUT.get(event_id)
    if not layout:
        return {}
    m = _STRINGS_LIST_RE.search(message)
    if not m:
        return {}
    body = m.group(1)
    items: list[str] = []
    for tok in _STRING_ITEM_RE.finditer(body):
        quoted, none_tok, bare = tok.group(1), tok.group(2), tok.group(3)
        if quoted is not None:
            items.append(quoted)
        elif none_tok == "None":
            items.append("")
        elif bare:
            items.append(bare.strip())
    out: dict[str, str] = {}
    for name, value in zip(layout, items):
        if name and value not in ("", "-"):
            out[name] = value
    return out


def is_psort_available() -> bool:
    """psort lives in the venv (installed via `pip install plaso`)."""
    return shutil.which("psort") is not None or shutil.which("psort.py") is not None


def _filetime_to_iso(ft: int) -> str:
    """Windows FILETIME (100-ns intervals since 1601-01-01) → ISO-8601 UTC."""
    if not isinstance(ft, (int, float)) or ft <= 0:
        return ""
    try:
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        return (epoch + timedelta(microseconds=ft / 10)).isoformat()
    except (ValueError, OverflowError, OSError):
        return ""


def _extract_event_data(message: str) -> dict[str, str]:
    """Pull common EventData fields out of the Plaso message string."""
    out: dict[str, str] = {}
    if not message:
        return out
    for key in _EVENT_DATA_KEYS:
        m = re.search(rf"{key}[:\s=]+([^\s,;'\"\)]+)", message)
        if m:
            out[key] = m.group(1).strip()
    return out


def _plaso_event_to_ecs(ev: dict[str, Any], host: str, case_id: str) -> dict[str, Any] | None:
    """Convert one Plaso event-attribute container to an ECS document."""
    if ev.get("__container_type__") != "event":
        return None

    # Timestamp
    dt_block = ev.get("date_time", {})
    ts = ""
    if isinstance(dt_block, dict):
        ts = _filetime_to_iso(dt_block.get("timestamp", 0))
    if not ts:
        ts_micro = ev.get("timestamp", 0)
        if ts_micro:
            try:
                ts = datetime.fromtimestamp(ts_micro / 1_000_000, tz=timezone.utc).isoformat()
            except (ValueError, OverflowError, OSError):
                ts = ""
    if not ts:
        return None

    data_type = ev.get("data_type", "")
    eid = str(ev.get("event_identifier", "") or ev.get("event_id", "") or "")
    message = ev.get("message", "") or ev.get("xml_string", "") or ev.get("display_name", "")

    canonical = _DATATYPE_TO_CANONICAL.get(data_type, "")
    if data_type == "windows:evtx:record" and eid:
        canonical = _EVTX_EID_TO_CANONICAL.get(eid, "PROCESS_EXECUTION")
    if not canonical:
        canonical = "ALERT" if data_type else ""

    # Two-stage extraction: positional Strings-array decoding gives us
    # the rich EventData fields constructors need (LogonType, IpAddress,
    # CommandLine, TargetUserName by position). Fall back to the
    # key:value regex for non-EVTX plaso data_types.
    strings_fields = _parse_strings_array(message, eid)
    parsed = {**_extract_event_data(message), **strings_fields}

    user = (parsed.get("TargetUserName")
            or parsed.get("SubjectUserName")
            or parsed.get("AccountName")
            or ev.get("user", "") or ev.get("username", ""))
    cmdline = (parsed.get("CommandLine")
               or parsed.get("ProcessCommandLine", ""))
    proc_name = (parsed.get("NewProcessName")
                 or parsed.get("ProcessName", "")
                 or ev.get("process_name", ""))
    proc_path = (ev.get("process_executable", "")
                 or parsed.get("ImagePath")
                 or parsed.get("ServiceFileName")
                 or proc_name)
    remote_ip = (parsed.get("IpAddress")
                 or parsed.get("ClientAddress", ""))
    service_name = parsed.get("ServiceName", "")

    return {
        "@timestamp": ts,
        "host": {"name": host, "hostname": ev.get("computer_name", "")},
        "host_name": host,
        "case_id": case_id,
        "event": {
            "code": eid or data_type,
            "action": data_type,
            "category": ["process"] if "evtx" in data_type or "execution" in data_type else ["artifact"],
        },
        "process": {
            "name": proc_name,
            "command_line": cmdline,
            "executable": proc_path,
        },
        "user": user,
        "user_name": user,
        "file": {"path": ev.get("filename", "") or ev.get("display_name", "")},
        "winlog": {
            "event_id": eid,
            "channel": ev.get("source_name", "") or ev.get("channel", ""),
            "computer": ev.get("computer_name", ""),
            "event_data": parsed,
        },
        "message": (message[:1500] if message else ""),
        "canonical_type": canonical,
        "command_line": cmdline,
        "process_name": proc_name,
        "process_path": proc_path,
        "registry_key": ev.get("key_path", "") or ev.get("registry_key", ""),
        "target_file": (ev.get("filename", "")
                         or parsed.get("ObjectName", "")
                         or ev.get("display_name", "")),
        "remote_ip": remote_ip,
        "service_name": service_name,
        "alert_name": "",
        "nighteye": {
            "ingest_id": "psort-jsonl",
            "audit_id": f"ingest-psort-{host}",
            "parser": "psort_json_line",
            "canonical_type": canonical,
            "case_id": case_id,
        },
    }


def parse_plaso_storage(
    path: Path,
    *,
    host_name: str,
    case_id: str,
) -> Iterator[dict[str, Any]]:
    """Run psort -o json_line on a .plaso storage file and yield ECS docs."""
    if not is_psort_available():
        logger.warning("psort not available — skipping %s", path.name)
        return

    psort = shutil.which("psort") or shutil.which("psort.py")
    out_jsonl = Path(tempfile.mkdtemp(prefix="psort_")) / f"{host_name}.jsonl"

    logger.info("psort -o json_line %s → %s", path.name, out_jsonl)
    cmd = [psort, "-o", "json_line", "-w", str(out_jsonl), str(path)]
    try:
        subprocess.run(cmd, capture_output=True, timeout=3600)
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.error("psort failed for %s: %s", path.name, exc)
        return

    if not out_jsonl.exists():
        logger.error("psort produced no output for %s", path.name)
        return

    count = 0
    skipped = 0
    try:
        with open(out_jsonl, encoding="utf-8") as f:
            for line in f:
                line = line.strip().rstrip(",")
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    skipped += 1
                    continue
                doc = _plaso_event_to_ecs(ev, host_name, case_id)
                if doc is None:
                    skipped += 1
                    continue
                count += 1
                yield doc
    finally:
        shutil.rmtree(out_jsonl.parent, ignore_errors=True)

    logger.info("psort yielded %d ECS docs from %s (%d skipped)",
                count, path.name, skipped)
