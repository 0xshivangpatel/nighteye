"""MCP Evidence Search Tools.

Tools for querying raw and canonical evidence from OpenSearch.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from nighteye.db import connect, execute_with_retry
from nighteye.ingest.opensearch_client import NightEyeOSClient
from nighteye.ingest.ecs import case_index_pattern, make_index_name

__all__ = [
    "search_evidence",
    "get_evidence_details",
    "list_evidence_types",
    "get_host_timeline",
    "get_process_tree",
    "get_file_history",
    "get_network_connections",
    "get_registry_changes",
    "get_service_changes",
    "get_authentication_events",
]

logger = logging.getLogger("nighteye.mcp.tools.evidence")

# ============================================================
# Core Search Tool
# ============================================================

def search_evidence(
    case_id: str,
    query: str,
    evidence_type: str | None = None,
    host: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    limit: int = 50,
    client: NightEyeOSClient | None = None,
) -> dict[str, Any]:
    """Search evidence using natural language or structured query.

    Args:
        case_id: Active case ID
        query: Search terms or field:value pairs
        evidence_type: Filter by type (process, file, network, auth, registry, service, alert)
        host: Filter by host name
        start_time: ISO timestamp lower bound
        end_time: ISO timestamp upper bound
        limit: Max results (default 50)

    Returns:
        Search results with summaries
    """
    if not client:
        client = NightEyeOSClient()

    # NightEye stores two doc shapes:
    #   - canonical-{host}: flat fields (case_id, host_name, canonical_type, command_line)
    #   - raw indices (win_timeline, evtx, mft, registry, redline_mans):
    #     ECS-nested (host.name, process.command_line, etc.) with nighteye.case_id
    # The query below uses `bool/should` to match either shape so a single
    # search hits both.

    must_clauses: list[dict] = []

    # case_id filter — try both flat and nighteye-prefixed forms
    must_clauses.append({
        "bool": {
            "should": [
                {"term": {"case_id.keyword": case_id}},
                {"term": {"case_id": case_id}},
                {"term": {"nighteye.case_id.keyword": case_id}},
                {"term": {"nighteye.case_id": case_id}},
            ],
            "minimum_should_match": 1,
        }
    })

    # canonical_type filter accepts user-friendly aliases (e.g.
    # "process_execution") and the canonical enum form (PROCESS_EXECUTION)
    if evidence_type:
        et_upper = evidence_type.upper()
        must_clauses.append({
            "bool": {
                "should": [
                    {"term": {"canonical_type.keyword": et_upper}},
                    {"term": {"canonical_type": et_upper}},
                    {"term": {"nighteye.canonical_type.keyword": et_upper}},
                ],
                "minimum_should_match": 1,
            }
        })

    if host:
        must_clauses.append({
            "bool": {
                "should": [
                    {"term": {"host_name.keyword": host}},
                    {"term": {"host_name": host}},
                    {"term": {"host.name.keyword": host}},
                    {"term": {"host.name": host}},
                ],
                "minimum_should_match": 1,
            }
        })

    if start_time or end_time:
        ts_range: dict[str, str] = {}
        if start_time:
            ts_range["gte"] = start_time
        if end_time:
            ts_range["lte"] = end_time
        must_clauses.append({"range": {"@timestamp": ts_range}})

    # Parse query string
    if query and query.strip() and query.strip() != "*":
        if ":" in query and not query.startswith(("http", "https")):
            # Field:value search — exact match on the named field
            field, value = query.split(":", 1)
            must_clauses.append({"match": {field.strip(): value.strip()}})
        else:
            # Free text — use BOTH match (for tokenized words) AND wildcard
            # against `.keyword` subfields (so "lsass" finds the substring
            # in path strings like "C:\\Windows\\system32\\lsass.exe" that
            # the standard analyzer tokenizes as one big token).
            qval = query.strip()
            wildcard_val = f"*{qval.lower()}*"
            text_fields = [
                "command_line", "process.command_line",
                "target_file", "file.path",
                "registry_key", "registry.key",
                "user", "user.name",
                "host_name", "host.name",
                "alert_name", "rule.name",
                "process_name", "process.name",
                "event.action", "message",
            ]
            keyword_fields = [
                "command_line.keyword", "process.command_line.keyword",
                "target_file.keyword", "file.path.keyword",
                "registry_key.keyword", "registry.key.keyword",
                "process_name.keyword", "process.name.keyword",
                "alert_name.keyword", "rule.name.keyword",
            ]
            should: list[dict[str, Any]] = [
                {"multi_match": {
                    "query": qval,
                    "fields": [f + "^2" for f in text_fields],
                    "type": "best_fields",
                }},
            ]
            for kf in keyword_fields:
                should.append({"wildcard": {kf: {"value": wildcard_val, "case_insensitive": True}}})
            must_clauses.append({"bool": {"should": should, "minimum_should_match": 1}})

    dsl = {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}}

    # Search across all indices for this case
    indices = client.list_indices(case_index_pattern(case_id))
    if not indices:
        return {"results": [], "total": 0, "indices_searched": 0, "query": query}

    all_results: list[dict[str, Any]] = []
    for index in indices:
        if len(all_results) >= limit:
            break
        try:
            hits = client.search(index=index, query=dsl, size=min(limit, 100))
            for doc in hits:
                all_results.append({
                    "id": doc.get("event_id") or doc.get("_id"),
                    "index": index,
                    "type": (
                        doc.get("canonical_type")
                        or doc.get("nighteye", {}).get("canonical_type", "unknown")
                    ),
                    "host": (
                        doc.get("host_name")
                        or doc.get("host", {}).get("name", "")
                    ),
                    "timestamp": doc.get("@timestamp"),
                    "summary": _summarize_doc(doc),
                    "raw": doc,
                })
                if len(all_results) >= limit:
                    break
        except Exception as exc:
            logger.debug("Search failed for %s: %s", index, exc)

    return {
        "results": all_results[:limit],
        "total": len(all_results),
        "indices_searched": len(indices),
        "query": query,
    }


def get_evidence_details(
    case_id: str,
    evidence_id: str,
    index_name: str,
    client: NightEyeOSClient | None = None,
) -> dict[str, Any]:
    """Get full details of a specific evidence document."""
    if not client:
        client = NightEyeOSClient()

    try:
        doc = client.get_document(index_name, evidence_id)
        return {
            "found": True,
            "id": evidence_id,
            "index": index_name,
            "document": doc,
        }
    except Exception as exc:
        return {
            "found": False,
            "id": evidence_id,
            "index": index_name,
            "error": str(exc),
        }


def list_evidence_types(
    case_id: str,
    client: NightEyeOSClient | None = None,
) -> dict[str, Any]:
    """List all evidence types available for a case."""
    if not client:
        client = NightEyeOSClient()

    indices = client.list_indices(case_index_pattern(case_id))
    types = set()
    host_counts: dict[str, int] = {}

    for idx in indices:
        parts = idx.split("-")
        if len(parts) >= 4:
            evidence_type = parts[-2] if parts[-1] == "*" else parts[-2]
            host = parts[-1] if parts[-1] != "*" else "unknown"
            types.add(evidence_type)
            host_counts[host] = host_counts.get(host, 0) + 1

    return {
        "evidence_types": sorted(types),
        "hosts": list(host_counts.keys()),
        "total_indices": len(indices),
    }


# ============================================================
# Specialized Timeline Tools
# ============================================================

def get_host_timeline(
    case_id: str,
    host: str,
    start_time: str | None = None,
    end_time: str | None = None,
    granularity: str = "minute",
    client: NightEyeOSClient | None = None,
) -> dict[str, Any]:
    """Get chronological timeline of all events for a host."""
    if not client:
        client = NightEyeOSClient()

    indices = client.list_indices(case_index_pattern(case_id, f"*-{host}"))

    all_events = []
    for index in indices:
        try:
            for page in client.scroll_search_iter(
                index=index,
                query={
                    "bool": {
                        "must": [
                            {"term": {"nighteye.case_id": case_id}},
                            {"term": {"host.name": host}},
                        ]
                    }
                },
                page_size=500,
            ):
                for doc in page:
                    all_events.append({
                        "timestamp": doc.get("@timestamp"),
                        "type": doc.get("nighteye", {}).get("canonical_type", "unknown"),
                        "summary": _summarize_doc(doc),
                        "id": doc.get("_id"),
                    })
        except Exception as exc:
            logger.debug("Timeline query failed for %s: %s", index, exc)

    # Sort by timestamp
    all_events.sort(key=lambda x: x["timestamp"] or "")

    return {
        "host": host,
        "event_count": len(all_events),
        "time_range": {
            "start": all_events[0]["timestamp"] if all_events else None,
            "end": all_events[-1]["timestamp"] if all_events else None,
        },
        "events": all_events,
    }


def get_process_tree(
    case_id: str,
    host: str,
    root_pid: int | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    client: NightEyeOSClient | None = None,
) -> dict[str, Any]:
    """Get process execution tree for a host."""
    if not client:
        client = NightEyeOSClient()

    # Query process execution events
    results = search_evidence(
        case_id=case_id,
        query="canonical_type:PROCESS_EXECUTION",
        host=host,
        start_time=start_time,
        end_time=end_time,
        limit=1000,
        client=client,
    )

    processes: dict[int, dict] = {}
    root_processes: list[dict] = []

    for r in results["results"]:
        raw = r.get("raw", {})
        pid = raw.get("process", {}).get("pid")
        ppid = raw.get("process", {}).get("parent", {}).get("pid")

        if pid is None:
            continue

        proc = {
            "pid": pid,
            "ppid": ppid,
            "name": raw.get("process", {}).get("name", ""),
            "command_line": raw.get("process", {}).get("command_line", ""),
            "user": raw.get("user", {}).get("name", ""),
            "timestamp": raw.get("@timestamp"),
            "children": [],
        }
        processes[pid] = proc

    # Build tree
    for pid, proc in processes.items():
        if proc["ppid"] and proc["ppid"] in processes:
            processes[proc["ppid"]]["children"].append(proc)
        else:
            root_processes.append(proc)

    # Filter by root_pid if specified
    if root_pid and root_pid in processes:
        root_processes = [processes[root_pid]]

    return {
        "host": host,
        "total_processes": len(processes),
        "root_processes": root_processes,
    }


def get_file_history(
    case_id: str,
    host: str,
    file_path: str,
    client: NightEyeOSClient | None = None,
) -> dict[str, Any]:
    """Get history of a specific file (creation, modification, deletion)."""
    if not client:
        client = NightEyeOSClient()

    results = search_evidence(
        case_id=case_id,
        query=f"file.path:{file_path}",
        host=host,
        limit=100,
        client=client,
    )

    events = []
    for r in results["results"]:
        raw = r.get("raw", {})
        events.append({
            "timestamp": raw.get("@timestamp"),
            "action": raw.get("event", {}).get("action", "unknown"),
            "user": raw.get("user", {}).get("name", ""),
            "process": raw.get("process", {}).get("name", ""),
            "hash": raw.get("file", {}).get("hash", {}).get("sha256", ""),
        })

    events.sort(key=lambda x: x["timestamp"] or "")

    return {
        "file_path": file_path,
        "host": host,
        "event_count": len(events),
        "events": events,
    }


def get_network_connections(
    case_id: str,
    host: str | None = None,
    remote_ip: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    client: NightEyeOSClient | None = None,
) -> dict[str, Any]:
    """Get network connection events."""
    if not client:
        client = NightEyeOSClient()

    query_parts = ["canonical_type:NETWORK_CONNECTION"]
    if remote_ip:
        query_parts.append(f"destination.ip:{remote_ip}")

    results = search_evidence(
        case_id=case_id,
        query=" AND ".join(query_parts),
        host=host,
        start_time=start_time,
        end_time=end_time,
        limit=500,
        client=client,
    )

    connections = []
    for r in results["results"]:
        raw = r.get("raw", {})
        connections.append({
            "timestamp": raw.get("@timestamp"),
            "source_ip": (raw.get("source") or {}).get("ip", ""),
            "source_port": (raw.get("source") or {}).get("port", ""),
            "dest_ip": raw.get("remote_ip") or (raw.get("destination") or {}).get("ip", ""),
            "dest_port": raw.get("remote_port") or (raw.get("destination") or {}).get("port", ""),
            "process": raw.get("process_name") or (raw.get("process") or {}).get("name", ""),
            "user": raw.get("user") if isinstance(raw.get("user"), str) else (raw.get("user") or {}).get("name", ""),
            "action": (raw.get("event") or {}).get("action", ""),
        })

    return {
        "total_connections": len(connections),
        "unique_destinations": len(set(c["dest_ip"] for c in connections if c["dest_ip"])),
        "connections": connections,
    }


def get_registry_changes(
    case_id: str,
    host: str | None = None,
    registry_key: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    client: NightEyeOSClient | None = None,
) -> dict[str, Any]:
    """Get registry modification events."""
    if not client:
        client = NightEyeOSClient()

    query = "canonical_type:REGISTRY_MODIFICATION"
    if registry_key:
        query += f" registry.key:{registry_key}"

    results = search_evidence(
        case_id=case_id,
        query=query,
        host=host,
        start_time=start_time,
        end_time=end_time,
        limit=500,
        client=client,
    )

    changes = []
    for r in results["results"]:
        raw = r.get("raw", {})
        changes.append({
            "timestamp": raw.get("@timestamp"),
            "key": raw.get("registry_key") or (raw.get("registry") or {}).get("key", ""),
            "value": (raw.get("registry") or {}).get("value", ""),
            "action": (raw.get("event") or {}).get("action", ""),
            "process": raw.get("process_name") or (raw.get("process") or {}).get("name", ""),
            "user": raw.get("user") if isinstance(raw.get("user"), str) else (raw.get("user") or {}).get("name", ""),
        })

    return {
        "total_changes": len(changes),
        "unique_keys": len(set(c["key"] for c in changes if c["key"])),
        "changes": changes,
    }


def get_service_changes(
    case_id: str,
    host: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    client: NightEyeOSClient | None = None,
) -> dict[str, Any]:
    """Get service installation and modification events."""
    if not client:
        client = NightEyeOSClient()

    results = search_evidence(
        case_id=case_id,
        query="canonical_type:SERVICE_INSTALLATION",
        host=host,
        start_time=start_time,
        end_time=end_time,
        limit=500,
        client=client,
    )

    services = []
    for r in results["results"]:
        raw = r.get("raw", {})
        services.append({
            "timestamp": raw.get("@timestamp"),
            "service_name": (raw.get("service") or {}).get("name", "") or raw.get("alert_name", ""),
            "action": (raw.get("event") or {}).get("action", ""),
            "process": raw.get("process_name") or (raw.get("process") or {}).get("name", ""),
            "user": raw.get("user") if isinstance(raw.get("user"), str) else (raw.get("user") or {}).get("name", ""),
        })

    return {
        "total_changes": len(services),
        "services": services,
    }


def get_authentication_events(
    case_id: str,
    host: str | None = None,
    user: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    client: NightEyeOSClient | None = None,
) -> dict[str, Any]:
    """Get authentication events (logon, logoff, failure)."""
    if not client:
        client = NightEyeOSClient()

    query = "canonical_type:AUTHENTICATION"
    if user:
        query = f"user:{user}"

    results = search_evidence(
        case_id=case_id,
        query=query,
        host=host,
        start_time=start_time,
        end_time=end_time,
        limit=500,
        client=client,
    )

    events = []
    for r in results["results"]:
        raw = r.get("raw", {})
        events.append({
            "timestamp": raw.get("@timestamp"),
            "action": (raw.get("event") or {}).get("action", ""),
            "user": raw.get("user") if isinstance(raw.get("user"), str) else (raw.get("user") or {}).get("name", ""),
            "source_ip": (raw.get("source") or {}).get("ip", "") or raw.get("winlog.event_data.IpAddress", ""),
            "logon_type": (raw.get("winlog") or {}).get("event_data", {}).get("LogonType", "") or raw.get("winlog.event_data.LogonType", ""),
            "result": "success" if "success" in str((raw.get("event") or {}).get("outcome", "")).lower() else "failure",
        })

    return {
        "total_events": len(events),
        "success_count": sum(1 for e in events if e["result"] == "success"),
        "failure_count": sum(1 for e in events if e["result"] == "failure"),
        "events": events,
    }


# ============================================================
# Helpers
# ============================================================

def _summarize_doc(doc: dict[str, Any]) -> str:
    """Generate a human-readable summary of an evidence document.

    Handles both canonical (flat fields) and ECS-nested raw documents.
    """
    parts: list[str] = []

    # Event action — only present on raw ECS docs
    action = (doc.get("event") or {}).get("action", "")
    if action and action not in ("artifact",):
        parts.append(action)

    # Canonical type marker — present on canonical docs
    ctype = doc.get("canonical_type")
    if ctype:
        parts.append(ctype)

    # Process — flat first, then ECS-nested
    proc_name = doc.get("process_name") or (doc.get("process") or {}).get("name", "")
    if proc_name:
        parts.append(f"Process: {proc_name}")

    cmd = doc.get("command_line") or (doc.get("process") or {}).get("command_line", "")
    if cmd:
        if len(cmd) > 100:
            cmd = cmd[:100] + "…"
        parts.append(f"Cmd: {cmd}")

    # File
    file_path = doc.get("target_file") or (doc.get("file") or {}).get("path", "")
    if file_path:
        if len(file_path) > 80:
            file_path = "…" + file_path[-77:]
        parts.append(f"File: {file_path}")

    # Network
    dst = doc.get("destination") or {}
    if dst.get("ip"):
        parts.append(f"→ {dst['ip']}:{dst.get('port', '')}")
    elif doc.get("remote_ip"):
        parts.append(f"→ {doc['remote_ip']}")

    # User
    user = doc.get("user") if isinstance(doc.get("user"), str) else None
    if user is None:
        user = (doc.get("user") or {}).get("name", "") if isinstance(doc.get("user"), dict) else ""
    if user and user != "-":
        parts.append(f"User: {user}")

    # Registry
    reg_key = doc.get("registry_key") or (doc.get("registry") or {}).get("key", "")
    if reg_key:
        parts.append(f"Reg: {reg_key}")

    # Alert
    alert_name = doc.get("alert_name") or (doc.get("rule") or {}).get("name", "")
    if alert_name:
        level = doc.get("alert_level") or (doc.get("rule") or {}).get("level", "")
        parts.append(f"Alert: {alert_name}" + (f" ({level})" if level else ""))

    return " | ".join(parts) if parts else "Event"
