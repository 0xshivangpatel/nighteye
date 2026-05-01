"""MCP Cluster Investigation Tools.

Tools for querying behavioral clusters and their evidence.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from nighteye.db import connect, execute_with_retry
from nighteye.ingest.opensearch_client import NightEyeOSClient

__all__ = [
    "list_clusters",
    "get_cluster_details",
    "get_cluster_timeline",
    "get_cluster_artifacts",
    "get_cluster_counter_evidence",
]

logger = logging.getLogger("nighteye.mcp.tools.cluster")

# ============================================================
# Cluster Query Tools
# ============================================================

def list_clusters(
    case_id: str,
    constructor_name: str | None = None,
    host: str | None = None,
    min_score: int = 0,
    status: str | None = None,
    limit: int = 100,
    db_path: str | None = None,
) -> dict[str, Any]:
    """List behavioral clusters for a case.

    Args:
        case_id: Case ID
        constructor_name: Filter by constructor (LateralMovement, Persistence, etc.)
        host: Filter by host
        min_score: Minimum cluster score
        status: Filter by status
        limit: Max results
        db_path: Path to graph.db

    Returns:
        List of clusters with summaries
    """
    if not db_path:
        from nighteye.case import get_active_case
        active = get_active_case()
        db_path = active.graph_db if active else "graph.db"

    sql = """
        SELECT cluster_id, cluster_type, primary_host, score, strength, 
               triggers_fired, time_start, summary, created_at
        FROM clusters WHERE case_id = ? AND score >= ?
    """
    params = [case_id, min_score]

    if constructor_name:
        sql += " AND cluster_type = ?"
        params.append(constructor_name)
    if host:
        sql += " AND primary_host = ?"
        params.append(host)

    sql += " ORDER BY score DESC LIMIT ?"
    params.append(limit)

    with connect(db_path, read_only=True) as conn:
        rows = conn.execute(sql, params).fetchall()

    clusters = []
    for row in rows:
        # Parse triggers
        triggers = []
        if row["triggers_fired"]:
            try:
                triggers = json.loads(row["triggers_fired"])
            except:
                pass

        clusters.append({
            "id": row["cluster_id"],
            "constructor": row["cluster_type"],
            "host": row["primary_host"],
            "score": row["score"],
            "strength": row["strength"],
            "trigger": triggers[0] if triggers else "unknown",
            "trigger_time": row["time_start"],
            "summary": row["summary"],
            "created_at": row["created_at"],
        })

    return {
        "total": len(clusters),
        "clusters": clusters,
    }


def get_cluster_details(
    cluster_id: str,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Get full details of a specific cluster.

    Returns:
        Complete cluster information including events, signals, and counter-evidence
    """
    if not db_path:
        from nighteye.case import get_active_case
        active = get_active_case()
        db_path = active.graph_db if active else "graph.db"

    with connect(db_path, read_only=True) as conn:
        row = conn.execute(
            "SELECT * FROM clusters WHERE cluster_id = ?",
            (cluster_id,),
        ).fetchone()

        if not row:
            return {"found": False, "cluster_id": cluster_id}

        cluster = dict(row)

        # Parse JSON fields
        for field in ["triggers_fired", "supporting_signals", "counter_evidence_details", 
                       "contradicting_clusters", "member_canonical_ids", "secondary_hosts", "technique_ids"]:
            if cluster.get(field):
                try:
                    cluster[field] = json.loads(cluster[field])
                except (json.JSONDecodeError, TypeError):
                    pass

    return {
        "found": True,
        "cluster": cluster,
    }


def get_cluster_timeline(
    cluster_id: str,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Get chronological timeline of events within a cluster.

    Returns:
        Timeline events sorted by timestamp
    """
    if not db_path:
        from nighteye.case import get_active_case
        active = get_active_case()
        db_path = active.graph_db if active else "graph.db"

    with connect(db_path, read_only=True) as conn:
        row = conn.execute(
            "SELECT member_canonical_ids, time_start, time_end FROM clusters WHERE cluster_id = ?",
            (cluster_id,),
        ).fetchone()

        if not row:
            return {"found": False, "cluster_id": cluster_id}

        events = []

        # Add trigger event
        trigger = row["trigger_event"]
        if trigger:
            try:
                trigger_data = json.loads(trigger)
                events.append({
                    "timestamp": row["trigger_event_timestamp"],
                    "type": "trigger",
                    "event": trigger_data,
                })
            except (json.JSONDecodeError, TypeError):
                pass

        # Add member events
        members = row["member_events"]
        if members:
            try:
                member_list = json.loads(members)
                for m in member_list:
                    events.append({
                        "timestamp": m.get("timestamp", ""),
                        "type": "member",
                        "event": m,
                    })
            except (json.JSONDecodeError, TypeError):
                pass

        # Sort by timestamp
        events.sort(key=lambda x: x["timestamp"] or "")

    return {
        "found": True,
        "cluster_id": cluster_id,
        "event_count": len(events),
        "timeline": events,
    }


def get_cluster_artifacts(
    cluster_id: str,
    db_path: str | None = None,
    client: Any | None = None,
) -> dict[str, Any]:
    """Get all artifacts (raw evidence) associated with a cluster.

    Returns:
        List of evidence documents referenced by the cluster
    """
    if not db_path:
        from nighteye.case import get_active_case
        active = get_active_case()
        db_path = active.graph_db if active else "graph.db"

    with connect(db_path, read_only=True) as conn:
        row = conn.execute(
            "SELECT member_canonical_ids FROM clusters WHERE cluster_id = ?",
            (cluster_id,),
        ).fetchone()

        if not row:
            return {"found": False, "cluster_id": cluster_id}

        # Collect all event IDs
        event_ids = set()

        trigger = row["trigger_event"]
        if trigger:
            try:
                trigger_data = json.loads(trigger)
                if trigger_data.get("event_id"):
                    event_ids.add(trigger_data["event_id"])
            except (json.JSONDecodeError, TypeError):
                pass

        members = row["member_events"]
        if members:
            try:
                member_list = json.loads(members)
                for m in member_list:
                    if m.get("event_id"):
                        event_ids.add(m["event_id"])
            except (json.JSONDecodeError, TypeError):
                pass

    # Fetch evidence documents from OpenSearch
    artifacts = []
    if client and event_ids:
        for event_id in event_ids:
            try:
                # Search across all indices for this event
                result = client.scroll_search(
                    index="*",
                    query={"term": {"_id": event_id}},
                    page_size=1,
                )
                for doc in result:
                    artifacts.append({
                        "id": event_id,
                        "index": doc.get("_index", ""),
                        "document": doc,
                    })
            except Exception as exc:
                logger.debug("Failed to fetch artifact %s: %s", event_id, exc)

    return {
        "found": True,
        "cluster_id": cluster_id,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
    }


def get_cluster_counter_evidence(
    cluster_id: str,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Get counter-evidence attached to a cluster.

    Returns:
        Counter-evidence details and contradicting clusters
    """
    if not db_path:
        from nighteye.case import get_active_case
        active = get_active_case()
        db_path = active.graph_db if active else "graph.db"

    with connect(db_path, read_only=True) as conn:
        row = conn.execute(
            "SELECT counter_evidence_details, contradicting_clusters FROM clusters WHERE cluster_id = ?",
            (cluster_id,),
        ).fetchone()

        if not row:
            return {"found": False, "cluster_id": cluster_id}

        counter_evidence = []
        contradicting = []

        if row["counter_evidence_details"]:
            try:
                counter_evidence = json.loads(row["counter_evidence_details"])
            except (json.JSONDecodeError, TypeError):
                pass

        if row["contradicting_clusters"]:
            try:
                contradicting = json.loads(row["contradicting_clusters"])
            except (json.JSONDecodeError, TypeError):
                pass

    return {
        "found": True,
        "cluster_id": cluster_id,
        "counter_evidence_count": len(counter_evidence),
        "contradicting_cluster_count": len(contradicting),
        "counter_evidence": counter_evidence,
        "contradicting_clusters": contradicting,
    }
