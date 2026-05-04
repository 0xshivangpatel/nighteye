"""SRL 2015 Precooked Data Ingest.

Parses Plaso CSV, supertimeline CSV, and shimcache CSV files that are
shipped with the SANS SRL 2015 dataset (precooked folder inside each
host zip).  These files contain parsed Windows Event Logs, file-system
timeline entries, shimcache, prefetch, registry and browser artefacts.

The module converts each row into an ECS document and bulk-indexes it
into OpenSearch under the ``case-{case_id}-evtx-{host}`` or
``case-{case_id}-shimcache-{host}`` indices so that the existing
normalisation pass can consume them just like native EVTX / Prefetch
artefacts.

References:
    - docs/ARCHITECTURE.md § 5 (Layer 1: Wide Evidence Ingestion)
"""

from __future__ import annotations

import csv
import hashlib
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from nighteye.ingest.ecs import build_ecs_doc, compute_doc_id, make_index_name
from nighteye.ingest.opensearch_client import NightEyeOSClient

__all__ = ["ingest_srl2015_precooked"]

logger = logging.getLogger("nighteye.ingest.srl2015")

# ------------------------------------------------------------------
# Host-name mapping: directory basename -> canonical host name
# ------------------------------------------------------------------
_HOST_ALIASES: dict[str, str] = {
    "win7-32-nromanoff-10.3.58.5": "nromanoff",
    "win7-64-nfury-10.3.58.6": "nfury",
    "xp-tdungan-10.3.58.7": "tdungan",
    "win2008R2-controller-10.3.58.4": "controller",
}

# Plaso 'host' column values -> canonical host name
_COMPUTER_MAP: dict[str, str] = {
    "WKS-WIN732BITA": "nromanoff",
    "WKS-WIN764BITA": "nfury",
    "WKS-WINXP32BIT": "tdungan",
    "DC01": "controller",
}


def _canonical_host(host_val: str, default: str = "unknown") -> str:
    """Map a Plaso host column to NightEye canonical host name.

    The CSV *host* column is the original Windows computer name.
    We try to map it to a known canonical host; if no mapping exists
    we trust the path-resolved *default* hostname (which comes from
    NightEye's host resolution) over an unknown Windows hostname.
    """
    if not host_val or host_val == "-":
        return default
    bare = host_val.split(".")[0]
    return _COMPUTER_MAP.get(bare, default)


# ------------------------------------------------------------------
# Plaso sourcetype -> ECS event category / action hints
# ------------------------------------------------------------------
_PLACO_EVENT_CODE_MAP: dict[str, str] = {
    "WinEVTX": "evtx",
    "WinPrefetch": "prefetch",
    "AppCompatCache Registry Entry": "shimcache",
    "File entry shell item": "shellitem",
    "MSIE Cache File URL record": "webhist",
    "Firefox History": "webhist",
    "Firefox Cache": "webhist",
}


def _plaso_to_event_action(sourcetype: str) -> str:
    return _PLACO_EVENT_CODE_MAP.get(sourcetype, "artifact")


# ------------------------------------------------------------------
# XML helpers for WinEVTX extra column
# ------------------------------------------------------------------
_XML_EVENT_ID_RE = re.compile(r"<EventID>(\d+)</EventID>")
_XML_COMPUTER_RE = re.compile(r"<Computer>([^<]+)</Computer>")
_XML_PID_RE = re.compile(r'ProcessID="(\d+)"')
_XML_SID_RE = re.compile(r'UserID="([^"]+)"')
_XML_CHANNEL_RE = re.compile(r"<Channel>([^<]+)</Channel>")
_XML_TIME_RE = re.compile(r'SystemTime="([^"]+)"')


def _extract_xml_field(text: str, pattern: re.Pattern) -> str:
    m = pattern.search(text)
    return m.group(1) if m else ""


# ------------------------------------------------------------------
# Row -> ECS document
# ------------------------------------------------------------------

def _parse_plaso_row(row: dict[str, str], default_host: str) -> dict[str, Any] | None:
    """Convert a Plaso CSV row into an ECS document.

    Returns *None* when the row is not useful (missing timestamp, etc.).
    """
    date_str = str(row.get("date") or "").strip()
    time_str = str(row.get("time") or "").strip()
    if not date_str or not time_str:
        return None

    # Timestamp
    try:
        dt = datetime.strptime(f"{date_str} {time_str}", "%m/%d/%Y %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
        ts = dt.isoformat()
    except ValueError:
        return None

    sourcetype = str(row.get("sourcetype") or "").strip()
    extra = str(row.get("extra") or "")
    short = str(row.get("short") or "")
    filename = str(row.get("filename") or "")
    user = str(row.get("user") or "").strip()
    host = _canonical_host(str(row.get("host") or ""), default_host)

    # WinEVTX: grab EventID / PID / SID / Channel from XML snippet
    event_code = ""
    pid: int | None = None
    user_sid = ""
    channel = ""
    if sourcetype == "WinEVTX" and extra:
        event_code = _extract_xml_field(extra, _XML_EVENT_ID_RE)
        pid_str = _extract_xml_field(extra, _XML_PID_RE)
        if pid_str.isdigit():
            pid = int(pid_str)
        user_sid = _extract_xml_field(extra, _XML_SID_RE)
        channel = _extract_xml_field(extra, _XML_CHANNEL_RE)
        # Prefer SID-derived user when user column is generic
        if user_sid and (not user or user in ("-", "systemprofile")):
            user = user_sid

    # File-system rows often carry a TSK filename like TSK:/Windows/...
    file_path = ""
    if filename.startswith("TSK:"):
        file_path = filename[4:]
    elif filename:
        file_path = filename

    # Build ECS doc
    return build_ecs_doc(
        timestamp=ts,
        host_name=host,
        event_code=event_code or _plaso_to_event_action(sourcetype),
        event_action=_plaso_to_event_action(sourcetype),
        event_category=["artifact"] if sourcetype != "WinEVTX" else ["process", "authentication", "network", "file"],
        event_outcome="success",
        user_name=user,
        process_pid=pid,
        process_name="",
        process_command_line=short[:512],
        file_path=file_path,
        source_ip="",
        destination_ip="",
        destination_port=None,
        network_protocol="",
        nighteye_ingest_id="srl2015-plaso",
        nighteye_source_file=filename,
        nighteye_audit_id="srl2015-plaso",
        nighteye_parser="plaso_csv",
        nighteye_canonical_type="",
        extra={
            "plaso.sourcetype": sourcetype,
            "plaso.short": short,
            "plaso.desc": str(row.get("desc") or "")[:512],
            "plaso.channel": channel,
            "plaso.version": str(row.get("version") or ""),
            "plaso.notes": str(row.get("notes") or ""),
            "plaso.format": str(row.get("format") or ""),
        },
    )


def _parse_shimcache_row(row: dict[str, str], default_host: str) -> dict[str, Any] | None:
    """Convert a shimcache CSV row into an ECS PROCESS_EXECUTION doc."""
    last_modified = str(row.get("Last Modified") or "").strip()
    path = str(row.get("Path") or "").strip()
    if not last_modified or not path:
        return None

    # Shimcache timestamps are like "01/12/11 12:08:00"
    try:
        dt = datetime.strptime(last_modified, "%m/%d/%y %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
        ts = dt.isoformat()
    except ValueError:
        return None

    # Extract image name from path
    image_name = path.split("\\")[-1]

    return build_ecs_doc(
        timestamp=ts,
        host_name=default_host,
        event_code="shimcache",
        event_action="shimcache-execution",
        event_category=["process"],
        event_outcome="success",
        process_name=image_name,
        process_executable=path,
        file_path=path,
        nighteye_ingest_id="srl2015-shimcache",
        nighteye_source_file=path,
        nighteye_audit_id="srl2015-shimcache",
        nighteye_parser="shimcache_csv",
    )


# ------------------------------------------------------------------
# Bulk index helpers
# ------------------------------------------------------------------

def _index_docs(
    client: NightEyeOSClient,
    case_id: str,
    host: str,
    artifact: str,
    docs: list[dict[str, Any]],
    batch_size: int = 2000,
) -> tuple[int, int]:
    """Bulk-index a list of ECS docs.  Returns (indexed, errors)."""
    if not docs:
        return 0, 0

    index_name = make_index_name(case_id, artifact, host)
    total_indexed = 0
    total_errors = 0

    for i in range(0, len(docs), batch_size):
        batch = docs[i : i + batch_size]
        doc_ids = [
            compute_doc_id(
                case_id,
                artifact,
                host,
                f"{d.get('@timestamp')}:{d.get('event', {}).get('code', '')}:{d.get('nighteye', {}).get('source_file', '')}:{idx}",
            )
            for idx, d in enumerate(batch)
        ]
        result = client.bulk_index(index_name, batch, doc_ids=doc_ids)
        total_indexed += result.get("indexed", 0)
        total_errors += result.get("errors", 0)

    logger.info(
        "Indexed %d/%d docs to %s (%d errors)",
        total_indexed,
        len(docs),
        index_name,
        total_errors,
    )
    return total_indexed, total_errors


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def ingest_srl2015_precooked(
    client: NightEyeOSClient,
    case_id: str,
    base_dir: str | Path,
) -> dict[str, Any]:
    """Ingest SRL 2015 precooked artefacts from extracted host directories.

    Expects *base_dir* to contain sub-directories like
    ``win7-32-nromanoff-10.3.58.5_nighteye``.

    Returns a statistics dict.
    """
    base = Path(base_dir)
    stats: dict[str, Any] = {
        "hosts_processed": [],
        "plaso_rows": 0,
        "plaso_indexed": 0,
        "shimcache_rows": 0,
        "shimcache_indexed": 0,
        "errors": 0,
    }

    for host_dir in sorted(base.glob("*_nighteye")):
        dir_name = host_dir.name.replace("_nighteye", "")
        host = _HOST_ALIASES.get(dir_name, dir_name.lower())
        logger.info("Processing SRL 2015 precooked data for host: %s", host)

        # ------------------------------------------------------------------
        # 1. Plaso CSV
        # ------------------------------------------------------------------
        plaso_paths = list(host_dir.rglob("precooked/timeline/plaso.csv"))
        for plaso_path in plaso_paths:
            logger.info("Reading Plaso CSV: %s", plaso_path)
            docs: list[dict[str, Any]] = []
            rows = 0
            with open(plaso_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    rows += 1
                    doc = _parse_plaso_row(row, host)
                    if doc:
                        docs.append(doc)
                    if len(docs) >= 5000:
                        idx, err = _index_docs(client, case_id, host, "evtx", docs)
                        stats["plaso_indexed"] += idx
                        stats["errors"] += err
                        docs = []
            if docs:
                idx, err = _index_docs(client, case_id, host, "evtx", docs)
                stats["plaso_indexed"] += idx
                stats["errors"] += err
            stats["plaso_rows"] += rows
            logger.info(
                "Plaso %s: %d rows read, %d indexed",
                host,
                rows,
                stats["plaso_indexed"],
            )

        # ------------------------------------------------------------------
        # 2. Shimcache CSV
        # ------------------------------------------------------------------
        shim_paths = list(host_dir.rglob("precooked/shimcache/shimcache.csv"))
        for shim_path in shim_paths:
            logger.info("Reading Shimcache CSV: %s", shim_path)
            docs = []
            rows = 0
            with open(shim_path, "r", encoding="utf-8-sig", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    rows += 1
                    doc = _parse_shimcache_row(row, host)
                    if doc:
                        docs.append(doc)
                    if len(docs) >= 5000:
                        idx, err = _index_docs(client, case_id, host, "shimcache", docs)
                        stats["shimcache_indexed"] += idx
                        stats["errors"] += err
                        docs = []
            if docs:
                idx, err = _index_docs(client, case_id, host, "shimcache", docs)
                stats["shimcache_indexed"] += idx
                stats["errors"] += err
            stats["shimcache_rows"] += rows
            logger.info(
                "Shimcache %s: %d rows read, %d indexed",
                host,
                rows,
                stats["shimcache_indexed"],
            )

        if plaso_paths or shim_paths:
            stats["hosts_processed"].append(host)

    return stats
