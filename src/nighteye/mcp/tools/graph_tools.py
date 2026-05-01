"""MCP Graph Query Tools.

Tools for querying the entity-relationship graph.
"""

from __future__ import annotations

import logging
from typing import Any

from nighteye.db import connect
from nighteye.graph.graph import (
    query_entity as _query_entity,
    query_neighbors as _query_neighbors,
    find_path as _find_path,
)
from nighteye.case import get_active_case

__all__ = [
    "query_entity",
    "query_neighbors",
    "find_path",
    "get_entity_details",
    "search_entities",
]

logger = logging.getLogger("nighteye.mcp.tools.graph")

# ============================================================
# Graph Query Tools
# ============================================================

def query_entity(
    entity_id: str,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Query a single entity by ID.

    Returns:
        Entity details or not found
    """
    if not db_path:
        active = get_active_case()
        db_path = active.graph_db if active else "graph.db"

    try:
        entity = _query_entity(db_path, entity_id)
        if not entity:
            return {"found": False, "entity_id": entity_id}

        return {
            "found": True,
            "entity": entity,
        }
    except Exception as exc:
        logger.exception("Failed to query entity")
        return {"success": False, "error": str(exc)}


def query_neighbors(
    entity_id: str,
    edge_type: str | None = None,
    direction: str = "both",
    db_path: str | None = None,
) -> dict[str, Any]:
    """Query neighbors of an entity.

    Args:
        entity_id: Starting entity ID
        edge_type: Optional filter by edge type (e.g., "connected_to", "wrote")
        direction: "in", "out", or "both"
        db_path: Path to graph.db

    Returns:
        List of neighbor entities
    """
    if not db_path:
        active = get_active_case()
        db_path = active.graph_db if active else "graph.db"

    try:
        neighbors = _query_neighbors(db_path, entity_id, edge_type, direction)

        return {
            "success": True,
            "entity_id": entity_id,
            "neighbor_count": len(neighbors),
            "neighbors": [
                {
                    "entity_id": n["entity_id"],
                    "entity_type": n["entity_type"],
                    "canonical_key": n["canonical_key"],
                    "properties": n.get("properties", {}),
                    "edge_type": n.get("edge_type", ""),
                    "edge_properties": n.get("edge_properties", {}),
                    "edge_timestamp": n.get("edge_timestamp", ""),
                }
                for n in neighbors
            ],
        }
    except Exception as exc:
        logger.exception("Failed to query neighbors")
        return {"success": False, "error": str(exc)}


def find_path(
    from_entity_id: str,
    to_entity_id: str,
    max_depth: int = 5,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Find paths between two entities.

    Args:
        from_entity_id: Starting entity
        to_entity_id: Target entity
        max_depth: Maximum path length (default 5)
        db_path: Path to graph.db

    Returns:
        List of paths between entities
    """
    if not db_path:
        active = get_active_case()
        db_path = active.graph_db if active else "graph.db"

    try:
        paths = _find_path(db_path, from_entity_id, to_entity_id, max_depth)

        return {
            "success": True,
            "from_entity": from_entity_id,
            "to_entity": to_entity_id,
            "path_count": len(paths),
            "max_depth": max_depth,
            "paths": [
                [
                    {
                        "edge_id": edge.get("edge_id", ""),
                        "from_entity": edge.get("from_entity", ""),
                        "to_entity": edge.get("to_entity", ""),
                        "edge_type": edge.get("edge_type", ""),
                        "timestamp": edge.get("timestamp", ""),
                    }
                    for edge in path
                ]
                for path in paths
            ],
        }
    except Exception as exc:
        logger.exception("Failed to find path")
        return {"success": False, "error": str(exc)}


def get_entity_details(
    entity_id: str,
    include_neighbors: bool = True,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Get comprehensive entity details including neighbors.

    Returns:
        Entity with full context
    """
    if not db_path:
        active = get_active_case()
        db_path = active.graph_db if active else "graph.db"

    try:
        entity = _query_entity(db_path, entity_id)
        if not entity:
            return {"found": False, "entity_id": entity_id}

        result = {
            "found": True,
            "entity": entity,
        }

        if include_neighbors:
            neighbors = _query_neighbors(db_path, entity_id)
            result["neighbors"] = [
                {
                    "entity_id": n["entity_id"],
                    "entity_type": n["entity_type"],
                    "canonical_key": n["canonical_key"],
                    "edge_type": n.get("edge_type", ""),
                }
                for n in neighbors
            ]
            result["neighbor_count"] = len(neighbors)

        return result
    except Exception as exc:
        logger.exception("Failed to get entity details")
        return {"success": False, "error": str(exc)}


def search_entities(
    case_id: str,
    entity_type: str | None = None,
    canonical_key_pattern: str | None = None,
    limit: int = 100,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Search entities by type or key pattern.

    Args:
        case_id: Case ID
        entity_type: Filter by type (host, process, file, user, network, registry, service)
        canonical_key_pattern: Pattern to match in canonical_key
        limit: Max results
        db_path: Path to graph.db

    Returns:
        Matching entities
    """
    if not db_path:
        active = get_active_case()
        db_path = active.graph_db if active else "graph.db"

    try:
        sql = "SELECT * FROM entities WHERE case_id = ?"
        params = [case_id]

        if entity_type:
            sql += " AND entity_type = ?"
            params.append(entity_type)
        if canonical_key_pattern:
            sql += " AND canonical_key LIKE ?"
            params.append(f"%{canonical_key_pattern}%")

        sql += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)

        with connect(db_path, read_only=True) as conn:
            rows = conn.execute(sql, params).fetchall()

        entities = []
        for row in rows:
            entities.append({
                "entity_id": row["entity_id"],
                "entity_type": row["entity_type"],
                "canonical_key": row["canonical_key"],
                "properties": row.get("properties", {}),
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "seen_count": row["seen_count"],
            })

        return {
            "success": True,
            "total": len(entities),
            "entities": entities,
        }
    except Exception as exc:
        logger.exception("Failed to search entities")
        return {"success": False, "error": str(exc)}
