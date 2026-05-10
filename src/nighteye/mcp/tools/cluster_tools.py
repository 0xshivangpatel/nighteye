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

    Returns the time-bracket bounds plus any member canonical event IDs
    so the caller can pivot to ``get_evidence_details`` / ``search_evidence``.
    """
    if not db_path:
        from nighteye.case import get_active_case
        active = get_active_case()
        db_path = active.graph_db if active else "graph.db"

    with connect(db_path, read_only=True) as conn:
        row = conn.execute(
            "SELECT member_canonical_ids, time_start, time_end, primary_host "
            "FROM clusters WHERE cluster_id = ?",
            (cluster_id,),
        ).fetchone()

        if not row:
            return {"found": False, "cluster_id": cluster_id}

        try:
            member_ids = json.loads(row["member_canonical_ids"] or "[]")
        except (json.JSONDecodeError, TypeError):
            member_ids = []

    return {
        "found": True,
        "cluster_id": cluster_id,
        "host": row["primary_host"],
        "time_start": row["time_start"],
        "time_end": row["time_end"],
        "event_count": len(member_ids),
        "member_canonical_ids": member_ids,
        "hint": (
            "Pivot to tool_search_evidence with start_time=time_start and "
            "end_time=time_end on this host to see surrounding context."
        ),
    }


def get_cluster_artifacts(
    cluster_id: str,
    db_path: str | None = None,
    client: Any | None = None,
) -> dict[str, Any]:
    """Fetch the underlying canonical-event documents that built this cluster.

    Looks up ``member_canonical_ids`` and resolves each one against the
    case's canonical-* indices via OpenSearch. Falls back to a wildcard
    search when the host index isn't known up-front.
    """
    if not db_path:
        from nighteye.case import get_active_case
        active = get_active_case()
        db_path = active.graph_db if active else "graph.db"

    with connect(db_path, read_only=True) as conn:
        row = conn.execute(
            "SELECT case_id, member_canonical_ids, primary_host "
            "FROM clusters WHERE cluster_id = ?",
            (cluster_id,),
        ).fetchone()

        if not row:
            return {"found": False, "cluster_id": cluster_id}

        try:
            event_ids = json.loads(row["member_canonical_ids"] or "[]")
        except (json.JSONDecodeError, TypeError):
            event_ids = []

        case_id = row["case_id"]
        host = row["primary_host"]

    if client is None:
        client = NightEyeOSClient()

    # Prefer the host-specific canonical index; fall back to all canonical
    # indices for this case if the per-host one is missing.
    from nighteye.ingest.ecs import case_index_pattern, make_index_name

    candidate_indices: list[str] = []
    if host and host != "unknown":
        candidate_indices.append(make_index_name(case_id, "canonical", host))
    candidate_indices.append(case_index_pattern(case_id, "canonical-*"))

    artifacts: list[dict[str, Any]] = []
    for event_id in event_ids:
        # Try by `event_id` field first (canonical schema), then by `_id`.
        doc = None
        for idx in candidate_indices:
            try:
                hits = client.search(
                    index=idx,
                    query={
                        "bool": {
                            "should": [
                                {"term": {"event_id.keyword": event_id}},
                                {"term": {"event_id": event_id}},
                                {"term": {"_id": event_id}},
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                    size=1,
                )
                if hits:
                    doc = hits[0]
                    artifacts.append({
                        "id": event_id,
                        "index": idx,
                        "document": doc,
                    })
                    break
            except Exception as exc:
                logger.debug("Failed to fetch artifact %s from %s: %s", event_id, idx, exc)
        if doc is None:
            artifacts.append({
                "id": event_id,
                "index": None,
                "document": None,
                "error": "not found in any canonical index",
            })

    return {
        "found": True,
        "cluster_id": cluster_id,
        "artifact_count": len(artifacts),
        "found_count": sum(1 for a in artifacts if a.get("document")),
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
