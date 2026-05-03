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

    # Build OpenSearch query
    must_clauses: list[dict] = [{"term": {"nighteye.case_id": case_id}}]

    if evidence_type:
        must_clauses.append({"term": {"nighteye.canonical_type": evidence_type}})
    if host:
        must_clauses.append({"term": {"host.name": host}})
    if start_time or end_time:
        range_query: dict[str, Any] = {"range": {"@timestamp": {}}}
        if start_time:
            range_query["range"]["@timestamp"]["gte"] = start_time
        if end_time:
            range_query["range"]["@timestamp"]["lte"] = end_time
        must_clauses.append(range_query)

    # Parse query string
    if ":" in query:
        # Field:value search
        field, value = query.split(":", 1)
        must_clauses.append({"match": {field.strip(): value.strip()}})
    else:
        # Full text search
        must_clauses.append({
            "multi_match": {
                "query": query,
                "fields": [
                    "process.command_line^3",
                    "file.path^2",
                    "registry.key^2",
                    "user.name^2",
                    "host.name",
                    "event.action",
                    "message",
                ],
            }
        })

    dsl = {"bool": {"must": must_clauses}}

    # Search across all indices for this case (case-insensitive helper —
    # the wildcard must match OpenSearch's lowercased index names).
    indices = client.list_indices(case_index_pattern(case_id))
    if not indices:
        return {"results": [], "total": 0, "indices_searched": 0}

    all_results = []
    for index in indices:
        try:
            page = client.scroll_search(
                index=index,
                query=dsl,
                page_size=min(limit, 100),
            )
            for doc in page:
                all_results.append({
                    "id": doc.get("_id"),
                    "index": index,
                    "type": doc.get("nighteye", {}).get("canonical_type", "unknown"),
                    "host": doc.get("host", {}).get("name", ""),
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
        query="canonical_type:process_execution",
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

    query_parts = ["canonical_type:network_connection"]
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
            "source_ip": raw.get("source", {}).get("ip", ""),
            "source_port": raw.get("source", {}).get("port", ""),
            "dest_ip": raw.get("destination", {}).get("ip", ""),
            "dest_port": raw.get("destination", {}).get("port", ""),
            "process": raw.get("process", {}).get("name", ""),
            "user": raw.get("user", {}).get("name", ""),
            "action": raw.get("event", {}).get("action", ""),
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

    query = "canonical_type:registry_modification"
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
            "key": raw.get("registry", {}).get("key", ""),
            "value": raw.get("registry", {}).get("value", ""),
            "action": raw.get("event", {}).get("action", ""),
            "process": raw.get("process", {}).get("name", ""),
            "user": raw.get("user", {}).get("name", ""),
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
        query="canonical_type:service_installation",
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
            "service_name": raw.get("service", {}).get("name", ""),
            "action": raw.get("event", {}).get("action", ""),
            "process": raw.get("process", {}).get("name", ""),
            "user": raw.get("user", {}).get("name", ""),
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

    query = "canonical_type:authentication"
    if user:
        query += f" user.name:{user}"

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
            "action": raw.get("event", {}).get("action", ""),
            "user": raw.get("user", {}).get("name", ""),
            "source_ip": raw.get("source", {}).get("ip", ""),
            "logon_type": raw.get("winlog", {}).get("event_data", {}).get("LogonType", ""),
            "result": "success" if "success" in str(raw.get("event", {}).get("outcome", "")).lower() else "failure",
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
    """Generate a human-readable summary of an evidence document."""
    parts = []

    # Event action
    action = doc.get("event", {}).get("action", "")
    if action:
        parts.append(action)

    # Process info
    proc = doc.get("process", {})
    if proc.get("name"):
        parts.append(f"Process: {proc['name']}")
    if proc.get("command_line"):
        cmd = proc["command_line"]
        if len(cmd) > 100:
            cmd = cmd[:100] + "..."
        parts.append(f"Cmd: {cmd}")

    # File info
    file = doc.get("file", {})
    if file.get("path"):
        parts.append(f"File: {file['path']}")

    # Network info
    src = doc.get("source", {})
    dst = doc.get("destination", {})
    if dst.get("ip"):
        parts.append(f"→ {dst['ip']}:{dst.get('port', '')}")

    # User
    user = doc.get("user", {}).get("name", "")
    if user:
        parts.append(f"User: {user}")

    # Alert info
    rule = doc.get("rule", {})
    if rule.get("name"):
        parts.append(f"Alert: {rule['name']} ({rule.get('level', '')})")

    return " | ".join(parts) if parts else "Unknown event"
