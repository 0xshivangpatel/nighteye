"""EZ Tool CSV Ingest — EvtxECmd, MFTECmd, RECmd, PECmd output.

Parses the CSV output from Eric Zimmerman's forensic tools and converts
rows into ECS documents for NightEye ingest.

Columns vary by tool but all share a common CSV structure.
"""
from __future__ import annotations

import csv
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from nighteye.ingest.ecs import build_ecs_doc, compute_doc_id, make_index_name
from nighteye.ingest.opensearch_client import NightEyeOSClient

__all__ = ["ingest_evtxecmd_csv", "ingest_mftecmd_csv", "ingest_recmd_csv"]

logger = logging.getLogger("nighteye.ingest.ez_csv")


def _parse_dt(val: str | None) -> str:
    """Parse a Z-tool datetime to ISO-8601."""
    if not val or not val.strip():
        return datetime.now(timezone.utc).isoformat()
    for fmt in [
        "%Y-%m-%d %H:%M:%S.%f",   # EvtxECmd: 2012-03-29 05:03:05.6081226
        "%Y-%m-%d %H:%M:%S",      # MFTECmd, RECmd
        "%m/%d/%Y %H:%M:%S",
    ]:
        try:
            return datetime.strptime(val.strip(), fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# EvtxECmd CSV
# Columns: TimeCreated, EventId, MapDescription, UserName, RemoteHost,
#          Channel, Computer, ExecutableInfo, Payload, ...
# ---------------------------------------------------------------------------

def ingest_evtxecmd_csv(
    csv_path: Path, host: str, case_id: str, client: NightEyeOSClient
) -> dict[str, int]:
    """Ingest EvtxECmd CSV output for a host."""
    stats = {"documents_indexed": 0, "errors": 0}
    index_name = make_index_name(case_id, f"evtx-{host}")
    logger.info("Ingesting EvtxECmd CSV: %s → %s", csv_path.name, index_name)

    try:
        with open(csv_path, encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ts = _parse_dt(row.get("TimeCreated"))
                eid = row.get("EventId", "").strip()
                channel = row.get("Channel", "Security")
                desc = row.get("MapDescription", "")
                user = row.get("UserName", "")
                computer = row.get("Computer", host)
                proc_info = row.get("ExecutableInfo", "")
                payload_raw = row.get("Payload", "")

                # Determine event category and extract key fields
                evt_category = ["artifact"]
                evt_action = "unknown"
                winlog_data = {}

                if channel == "Security":
                    if eid == "4624":
                        evt_category = ["authentication"]
                        evt_action = "logon-success"
                    elif eid == "4625":
                        evt_category = ["authentication"]
                        evt_action = "logon-failure"
                    elif eid == "4634":
                        evt_category = ["authentication"]
                        evt_action = "logoff"
                    elif eid == "4648":
                        evt_category = ["authentication"]
                        evt_action = "explicit-credential-logon"
                    elif eid == "4672":
                        evt_category = ["authentication"]
                        evt_action = "special-privilege-logon"
                    elif eid == "4663":
                        evt_category = ["file"]
                        evt_action = "object-access"
                    elif eid in ("4697", "7045"):
                        evt_category = ["configuration"]
                        evt_action = "service-installed"
                    elif eid == "4698":
                        evt_category = ["configuration"]
                        evt_action = "scheduled-task-created"
                    elif eid == "4719":
                        evt_category = ["configuration"]
                        evt_action = "audit-policy-changed"
                    elif eid == "1102":
                        evt_category = ["iam"]
                        evt_action = "log-cleared"
                    else:
                        evt_category = ["process"] if proc_info else ["artifact"]
                        evt_action = "windows-event"
                elif "System" in channel:
                    evt_category = ["configuration"]
                    evt_action = "system-event" if eid != "7045" else "service-installed"
                elif "PowerShell" in channel:
                    evt_category = ["process"]
                    evt_action = "powershell-activity"

                # Try to extract process info from Payload XML
                proc_name = ""
                proc_cmdline = ""
                if proc_info:
                    proc_name = proc_info.split("\\")[-1] if "\\" in proc_info else proc_info
                    proc_cmdline = proc_info

                doc = build_ecs_doc(
                    timestamp=ts,
                    host_name=host,
                    event_code=eid,
                    event_action=evt_action,
                    event_category=evt_category,
                    user_name=user,
                    process_name=proc_name,
                    process_executable=proc_info if proc_info else "",
                    process_command_line=proc_cmdline,
                    extra={
                        "winlog": {
                            "channel": channel,
                            "event_id": eid,
                            "description": desc,
                            "computer": computer,
                            "provider": row.get("Provider", ""),
                        },
                        "message": desc or f"Event {eid}",
                    },
                )
                doc_id = compute_doc_id(doc)
                client.index_document(index_name, doc_id, doc)
                stats["documents_indexed"] += 1

    except Exception as exc:
        logger.error("EvtxECmd ingest failed for %s: %s", csv_path, exc)
        stats["errors"] += 1

    logger.info("EvtxECmd ingest done: %s → %d docs", csv_path.name, stats["documents_indexed"])
    return stats


# ---------------------------------------------------------------------------
# MFTECmd CSV
# Columns: EntryNumber,SequenceNumber,InUse,ParentEntryNumber,ParentPath,
#          FileName,Extension,FileSize,ReferenceCount,...
#          Created0x10,LastModified0x30,LastRecordChange0x30,LastAccess0x30
# ---------------------------------------------------------------------------

def ingest_mftecmd_csv(
    csv_path: Path, host: str, case_id: str, client: NightEyeOSClient
) -> dict[str, int]:
    """Ingest MFTECmd CSV output for a host."""
    stats = {"documents_indexed": 0, "errors": 0}
    index_name = make_index_name(case_id, f"mft-{host}")
    logger.info("Ingesting MFTECmd CSV: %s → %s", csv_path.name, index_name)

    try:
        with open(csv_path, encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            batch = []
            for row in reader:
                if row.get("InUse", "True") != "True":
                    continue  # skip deleted records
                fname = row.get("FileName", "")
                ext = row.get("Extension", "")
                parent = row.get("ParentPath", "")
                path = f"{parent}\\{fname}" if parent else fname
                if not path:
                    continue
                # Simplify path
                path = path.replace("\\", "/").replace("//", "/")

                # Use Created0x10 for the timestamp
                ts = _parse_dt(row.get("Created0x10"))

                doc = build_ecs_doc(
                    timestamp=ts,
                    host_name=host,
                    event_action="file-created",
                    event_category=["file"],
                    file_path=path,
                    extra={
                        "file": {
                            "path": path,
                            "name": fname,
                            "extension": ext,
                            "size": row.get("FileSize", "0"),
                        },
                        "mft": {
                            "entry_number": row.get("EntryNumber", ""),
                            "in_use": True,
                            "created": ts,
                            "modified": _parse_dt(row.get("LastModified0x30")),
                            "accessed": _parse_dt(row.get("LastAccess0x30")),
                        },
                    },
                )
                batch.append(doc)
                if len(batch) >= 500:
                    client.bulk_index_iter(index_name, batch)
                    stats["documents_indexed"] += len(batch)
                    batch = []

            if batch:
                client.bulk_index_iter(index_name, batch)
                stats["documents_indexed"] += len(batch)

    except Exception as exc:
        logger.error("MFTECmd ingest failed for %s: %s", csv_path, exc)
        stats["errors"] += 1

    logger.info("MFTECmd ingest done: %s → %d docs", csv_path.name, stats["documents_indexed"])
    return stats


# ---------------------------------------------------------------------------
# RECmd CSV
# Columns vary by batch file. Common: HivePath,KeyPath,ValueName,ValueData,
# LastWriteTime,...
# ---------------------------------------------------------------------------

def ingest_recmd_csv(
    csv_path: Path, host: str, case_id: str, client: NightEyeOSClient
) -> dict[str, int]:
    """Ingest RECmd CSV output for a host."""
    stats = {"documents_indexed": 0, "errors": 0}
    index_name = make_index_name(case_id, f"registry-{host}")
    logger.info("Ingesting RECmd CSV: %s → %s", csv_path.name, index_name)

    try:
        with open(csv_path, encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            batch = []
            for row in reader:
                hive = row.get("HivePath", "") or row.get("HiveName", "")
                key = row.get("KeyPath", "") or row.get("RegistryPath", "")
                value = row.get("ValueName", "")
                data = row.get("ValueData", "")
                lwt = row.get("LastWriteTime", row.get("LastWriteTimestamp", ""))

                doc = build_ecs_doc(
                    timestamp=_parse_dt(lwt) if lwt else datetime.now(timezone.utc).isoformat(),
                    host_name=host,
                    event_action="registry-modified",
                    event_category=["configuration", "registry"],
                    extra={
                        "registry": {
                            "hive": hive,
                            "key": key,
                            "value_name": value,
                            "value_data": data,
                            "last_write": _parse_dt(lwt) if lwt else "",
                        },
                    },
                )
                batch.append(doc)
                if len(batch) >= 500:
                    client.bulk_index_iter(index_name, batch)
                    stats["documents_indexed"] += len(batch)
                    batch = []

            if batch:
                client.bulk_index_iter(index_name, batch)
                stats["documents_indexed"] += len(batch)

    except Exception as exc:
        logger.error("RECmd ingest failed for %s: %s", csv_path, exc)
        stats["errors"] += 1

    logger.info("RECmd ingest done: %s → %d docs", csv_path.name, stats["documents_indexed"])
    return stats
