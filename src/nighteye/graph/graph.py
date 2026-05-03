"""Entity & Relationship Graph Engine.

Populates the SQLite graph database from canonical events.
Provides graph traversal, entity resolution, and relationship queries.

References:
  - docs/ARCHITECTURE.md § 7 (Layer 3: Entity & Relationship Graph)
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.db import connect, execute_with_retry, transaction
from nighteye.ingest.ecs import case_index_pattern

__all__ = [
    "GraphEngine",
    "build_graph_from_canonical",
    "query_entity",
    "query_neighbors",
    "find_path",
]

logger = logging.getLogger("nighteye.graph")

# ============================================================
# Entity Extraction
# ============================================================

def _make_entity_id(case_id: str, entity_type: str, canonical_key: str) -> str:
    """Generate deterministic entity ID per ARCHITECTURE.md §7."""
    payload = f"{case_id}:{entity_type}:{canonical_key}"
    return hashlib.sha256(payload.encode()).hexdigest()[:32]

def _extract_host_entity(event: CanonicalEvent) -> dict[str, Any] | None:
    """Extract host entity from canonical event."""
    if not event.host_name:
        return None
    return {
        "entity_type": "host",
        "canonical_key": event.host_name,
        "properties": {
            "name": event.host_name,
        },
    }

def _extract_process_entity(event: CanonicalEvent) -> dict[str, Any] | None:
    """Extract process entity from canonical event."""
    if event.canonical_type != CanonicalType.PROCESS_EXECUTION:
        return None
    if not event.process_name or not event.pid:
        return None
    # canonical_key: host:pid:create_time (use timestamp as proxy for create_time)
    canonical_key = f"{event.host_name}:{event.pid}:{event.timestamp}"
    return {
        "entity_type": "process",
        "canonical_key": canonical_key,
        "properties": {
            "host": event.host_name,
            "pid": event.pid,
            "ppid": None,  # Would need parent info
            "name": event.process_name,
            "cmdline": event.command_line,
            "user": event.user,
            "image_path": event.process_path,
        },
    }

def _extract_file_entity(event: CanonicalEvent) -> dict[str, Any] | None:
    """Extract file entity from canonical event."""
    if event.canonical_type not in (CanonicalType.FILE_CREATION, CanonicalType.FILE_DELETION, CanonicalType.FILE_MODIFICATION):
        return None
    if not event.target_file:
        return None
    # canonical_key: host:path:sha256 (sha256 unknown from canonical, use path)
    canonical_key = f"{event.host_name}:{event.target_file}"
    return {
        "entity_type": "file",
        "canonical_key": canonical_key,
        "properties": {
            "host": event.host_name,
            "path": event.target_file,
        },
    }

def _extract_user_entity(event: CanonicalEvent) -> dict[str, Any] | None:
    """Extract user entity from canonical event."""
    if not event.user:
        return None
    # canonical_key: domain:sid (SID unknown, use name)
    canonical_key = event.user
    return {
        "entity_type": "user",
        "canonical_key": canonical_key,
        "properties": {
            "name": event.user,
        },
    }

def _extract_network_entity(event: CanonicalEvent) -> dict[str, Any] | None:
    """Extract network entity from canonical event."""
    if event.canonical_type != CanonicalType.NETWORK_CONNECTION:
        return None
    if not event.remote_ip:
        return None
    return {
        "entity_type": "network",
        "canonical_key": event.remote_ip,
        "properties": {
            "address": event.remote_ip,
            "scope": "internal" if _is_internal_ip(event.remote_ip) else "external",
        },
    }

def _extract_registry_entity(event: CanonicalEvent) -> dict[str, Any] | None:
    """Extract registry entity from canonical event."""
    if event.canonical_type != CanonicalType.REGISTRY_MODIFICATION:
        return None
    if not event.registry_key:
        return None
    canonical_key = f"{event.host_name}:{event.registry_key}"
    return {
        "entity_type": "registry",
        "canonical_key": canonical_key,
        "properties": {
            "host": event.host_name,
            "key_path": event.registry_key,
        },
    }

def _extract_service_entity(event: CanonicalEvent) -> dict[str, Any] | None:
    """Extract service entity from canonical event."""
    if event.canonical_type != CanonicalType.SERVICE_INSTALLATION:
        return None
    # Service name from alert or process context
    service_name = event.alert_name or event.process_name or "unknown"
    canonical_key = f"{event.host_name}:{service_name}"
    return {
        "entity_type": "service",
        "canonical_key": canonical_key,
        "properties": {
            "host": event.host_name,
            "name": service_name,
        },
    }

def _is_internal_ip(ip: str) -> bool:
    """Check if IP is RFC1918 internal."""
    if not ip or ip in ("127.0.0.1", "::1"):
        return True
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2:
            try:
                second = int(parts[1])
                return 16 <= second <= 31
            except ValueError:
                pass
    return False

# ============================================================
# Edge Extraction
# ============================================================

def _extract_edges(event: CanonicalEvent, entity_map: dict[str, str]) -> list[dict[str, Any]]:
    """Extract edges from canonical event given resolved entity IDs."""
    edges = []
    ts = event.timestamp or datetime.now(timezone.utc).isoformat()

    host_id = entity_map.get("host")
    process_id = entity_map.get("process")
    user_id = entity_map.get("user")
    file_id = entity_map.get("file")
    network_id = entity_map.get("network")
    registry_id = entity_map.get("registry")
    service_id = entity_map.get("service")

    # User authenticated on host
    if user_id and host_id:
        edges.append({
            "from_entity": user_id,
            "to_entity": host_id,
            "edge_type": "authenticated_as",
            "properties": {},
        })

    # Process spawned on host
    if process_id and host_id:
        edges.append({
            "from_entity": process_id,
            "to_entity": host_id,
            "edge_type": "spawned_by",
            "properties": {},
        })

    # Process wrote file
    if process_id and file_id and event.canonical_type == CanonicalType.FILE_CREATION:
        edges.append({
            "from_entity": process_id,
            "to_entity": file_id,
            "edge_type": "wrote",
            "properties": {"operation": "create"},
        })

    # File observed on host (metadata docs: no process context available)
    if file_id and host_id and event.canonical_type in (
        CanonicalType.FILE_CREATION, CanonicalType.FILE_MODIFICATION,
        CanonicalType.FILE_DELETION,
    ) and not process_id:
        edges.append({
            "from_entity": file_id,
            "to_entity": host_id,
            "edge_type": "accessed",
            "properties": {"operation": event.canonical_type.value.lower()},
        })

    # Process connected to network
    if process_id and network_id and event.canonical_type == CanonicalType.NETWORK_CONNECTION:
        edges.append({
            "from_entity": process_id,
            "to_entity": network_id,
            "edge_type": "connected_to",
            "properties": {
                "dst_port": event.remote_port,
                "protocol": "tcp",  # Default
            },
        })

    # Process modified registry
    if process_id and registry_id and event.canonical_type == CanonicalType.REGISTRY_MODIFICATION:
        edges.append({
            "from_entity": process_id,
            "to_entity": registry_id,
            "edge_type": "modified",
            "properties": {},
        })

    # Service persists via registry (if registry is a run key)
    if service_id and registry_id:
        reg_key = event.registry_key or ""
        if any(k in reg_key.lower() for k in ["run", "runonce", "service"]):
            edges.append({
                "from_entity": service_id,
                "to_entity": registry_id,
                "edge_type": "persists_via",
                "properties": {"mechanism": "registry_run"},
            })

    # Generic entity→host edge for events without process context.
    # Ensures file/registry/network entities connect to their host
    # even when metadata docs lack process/user info.
    if host_id:
        for etype_name, eid in [
            ("file", file_id), ("registry", registry_id),
            ("network", network_id), ("service", service_id),
        ]:
            if eid:
                edges.append({
                    "from_entity": eid,
                    "to_entity": host_id,
                    "edge_type": "accessed",
                    "properties": {"source": etype_name},
                })

    return edges

# ============================================================
# Graph Engine
# ============================================================

class GraphEngine:
    """Manages entity and relationship graph operations."""

    def __init__(self, db_path: str):
        self.db_path = db_path

    def upsert_entity(self, case_id: str, entity_type: str, canonical_key: str, 
                      properties: dict[str, Any], timestamp: str) -> str:
        """Insert or update an entity in the graph."""
        entity_id = _make_entity_id(case_id, entity_type, canonical_key)
        now = datetime.now(timezone.utc).isoformat()

        with connect(self.db_path) as conn:
            execute_with_retry(
                conn,
                """
                INSERT INTO entities (entity_id, entity_type, case_id, canonical_key, properties, 
                                      first_seen, last_seen, seen_count, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(entity_id) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    seen_count = seen_count + 1,
                    properties = excluded.properties
                """,
                (entity_id, entity_type, case_id, canonical_key, json.dumps(properties), 
                 timestamp, timestamp, now),
            )
            conn.commit()

        return entity_id

    def upsert_edge(self, case_id: str, from_entity: str, to_entity: str, 
                    edge_type: str, timestamp: str, properties: dict[str, Any],
                    source_audit_id: str, confidence_basis: str = "parsed_artifact") -> str:
        """Insert or update an edge in the graph."""
        edge_id = hashlib.sha256(
            f"{from_entity}:{to_entity}:{edge_type}:{timestamp}".encode()
        ).hexdigest()[:32]
        now = datetime.now(timezone.utc).isoformat()

        with connect(self.db_path) as conn:
            execute_with_retry(
                conn,
                """
                INSERT INTO edges (edge_id, from_entity, to_entity, edge_type, case_id, 
                                   timestamp, properties, source_audit_id, confidence_basis, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(edge_id) DO UPDATE SET
                    properties = excluded.properties
                """,
                (edge_id, from_entity, to_entity, edge_type, case_id, timestamp,
                 json.dumps(properties), source_audit_id, confidence_basis, now),
            )
            conn.commit()

        return edge_id

    def process_canonical_event(self, event: CanonicalEvent, case_id: str, 
                                audit_id: str) -> dict[str, str]:
        """Process a canonical event and update the graph."""
        entity_map: dict[str, str] = {}
        ts = event.timestamp or datetime.now(timezone.utc).isoformat()

        # Extract all applicable entities
        extractors = [
            ("host", _extract_host_entity),
            ("process", _extract_process_entity),
            ("file", _extract_file_entity),
            ("user", _extract_user_entity),
            ("network", _extract_network_entity),
            ("registry", _extract_registry_entity),
            ("service", _extract_service_entity),
        ]

        for entity_key, extractor in extractors:
            entity_data = extractor(event)
            if entity_data:
                entity_id = self.upsert_entity(
                    case_id,
                    entity_data["entity_type"],
                    entity_data["canonical_key"],
                    entity_data["properties"],
                    ts,
                )
                entity_map[entity_key] = entity_id

        # Extract and create edges
        edges = _extract_edges(event, entity_map)
        for edge in edges:
            self.upsert_edge(
                case_id,
                edge["from_entity"],
                edge["to_entity"],
                edge["edge_type"],
                ts,
                edge["properties"],
                audit_id,
            )

        return entity_map


# ============================================================
# Batch Graph Builder
# ============================================================

def build_graph_from_canonical(client, case_id: str, db_path: str) -> dict[str, int]:
    """Build the entire entity graph from canonical events.

    Args:
        client: NightEyeOSClient
        case_id: Case ID
        db_path: Path to graph.db

    Returns:
        Statistics dict
    """
    engine = GraphEngine(db_path)
    stats = {"entities_created": 0, "edges_created": 0, "events_processed": 0, "errors": 0}

    canonical_indices = client.list_indices(
        case_index_pattern(case_id, "canonical-*")
    )

    for index_name in canonical_indices:
        logger.info("Building graph from %s", index_name)

        try:
            for page in client.scroll_search_iter(
                index=index_name,
                query={"match_all": {}},
                page_size=1000,
            ):
                for doc in page:
                    try:
                        from nighteye.canonical.engine import normalize_document
                        event = normalize_document(doc, case_id)
                        if event:
                            engine.process_canonical_event(
                                event, case_id, 
                                doc.get("nighteye", {}).get("audit_id", "unknown")
                            )
                            stats["events_processed"] += 1
                    except Exception as exc:
                        logger.debug("Graph build error for doc: %s", exc)
                        stats["errors"] += 1

        except Exception as exc:
            logger.warning("Failed to build graph from %s: %s", index_name, exc)

    # Count final entities and edges
    with connect(db_path, read_only=True) as conn:
        stats["entities_created"] = conn.execute(
            "SELECT COUNT(*) FROM entities WHERE case_id = ?", (case_id,)
        ).fetchone()[0]
        stats["edges_created"] = conn.execute(
            "SELECT COUNT(*) FROM edges WHERE case_id = ?", (case_id,)
        ).fetchone()[0]

    logger.info(
        "Graph build complete: %d events, %d entities, %d edges, %d errors",
        stats["events_processed"], stats["entities_created"], 
        stats["edges_created"], stats["errors"],
    )

    return stats


# ============================================================
# Graph Queries
# ============================================================

def query_entity(db_path: str, entity_id: str) -> dict[str, Any] | None:
    """Query a single entity by ID."""
    with connect(db_path, read_only=True) as conn:
        row = conn.execute(
            "SELECT * FROM entities WHERE entity_id = ?", (entity_id,)
        ).fetchone()
        if row:
            return dict(row)
        return None


def query_neighbors(db_path: str, entity_id: str, 
                    edge_type: str | None = None,
                    direction: str = "both") -> list[dict[str, Any]]:
    """Query neighbors of an entity.

    Args:
        db_path: Path to graph.db
        entity_id: Starting entity
        edge_type: Optional filter by edge type
        direction: "in", "out", or "both"

    Returns:
        List of neighbor entities with edge info
    """
    results = []

    with connect(db_path, read_only=True) as conn:
        if direction in ("out", "both"):
            sql = """
                SELECT e.*, ed.edge_type, ed.properties as edge_properties, ed.timestamp as edge_timestamp
                FROM edges ed
                JOIN entities e ON ed.to_entity = e.entity_id
                WHERE ed.from_entity = ?
            """
            params = [entity_id]
            if edge_type:
                sql += " AND ed.edge_type = ?"
                params.append(edge_type)

            for row in conn.execute(sql, params):
                results.append(dict(row))

        if direction in ("in", "both"):
            sql = """
                SELECT e.*, ed.edge_type, ed.properties as edge_properties, ed.timestamp as edge_timestamp
                FROM edges ed
                JOIN entities e ON ed.from_entity = e.entity_id
                WHERE ed.to_entity = ?
            """
            params = [entity_id]
            if edge_type:
                sql += " AND ed.edge_type = ?"
                params.append(edge_type)

            for row in conn.execute(sql, params):
                results.append(dict(row))

    return results


def find_path(db_path: str, from_entity: str, to_entity: str,
              max_depth: int = 5) -> list[list[dict[str, Any]]]:
    """Find paths between two entities using BFS.

    Returns:
        List of paths, where each path is a list of (entity, edge) dicts
    """
    from collections import deque

    paths: list[list[dict]] = []
    visited = set()
    queue = deque([(from_entity, [])])

    with connect(db_path, read_only=True) as conn:
        while queue:
            current, path = queue.popleft()

            if len(path) > max_depth:
                continue

            if current == to_entity and path:
                paths.append(path)
                continue

            if current in visited:
                continue
            visited.add(current)

            # Get outgoing edges
            for row in conn.execute(
                "SELECT * FROM edges WHERE from_entity = ?", (current,)
            ):
                edge = dict(row)
                next_entity = edge["to_entity"]
                if next_entity not in visited:
                    queue.append((next_entity, path + [edge]))

    return paths
