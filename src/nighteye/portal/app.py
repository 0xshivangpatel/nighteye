"""NightEye Explainability Portal.

Web UI for human review of AI investigation results.
Connects to real graph.db and OpenSearch for live data.

References:
  - docs/ARCHITECTURE.md § 12 (Layer 8: Explainability Portal)
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from nighteye.db import connect
from nighteye.case import get_active_case, CaseInfo
from nighteye.ingest.opensearch_client import NightEyeOSClient

__all__ = ["create_portal_app"]

logger = logging.getLogger("nighteye.portal")

# ============================================================
# App Factory
# ============================================================

def create_portal_app(
    db_path: str | None = None,
    template_dir: str | None = None,
    static_dir: str | None = None,
) -> FastAPI:
    """Create the NightEye Portal FastAPI application."""

    app = FastAPI(title="NightEye Portal", version="1.0.0")

    # Resolve paths
    if not template_dir:
        template_dir = str(Path(__file__).parent / "templates")
    if not static_dir:
        static_dir = str(Path(__file__).parent / "static")

    templates = Jinja2Templates(directory=template_dir)

    try:
        app.mount("/static", StaticFiles(directory=static_dir), name="static")
    except RuntimeError:
        logger.warning("Static directory not found: %s", static_dir)

    # ========================================================
    # Helpers
    # ========================================================

    def _get_db():
        """Get database connection."""
        active = get_active_case()
        path = db_path or (active.graph_db if active else "graph.db")
        return connect(path, read_only=True)

    def _get_case_id() -> str:
        """Get active case ID."""
        active = get_active_case()
        if not active:
            raise HTTPException(status_code=400, detail="No active case")
        return active.id

    def _get_client() -> NightEyeOSClient:
        """Get OpenSearch client."""
        return NightEyeOSClient()

    def _detect_disturbances(case_id: str) -> list[dict[str, Any]]:
        """Auto-detect anti-forensic disturbances from clusters and insert them."""
        disturbances: list[dict[str, Any]] = []
        try:
            with connect(get_active_case().graph_db, read_only=False) as conn:
                # Check if any already exist
                existing = conn.execute(
                    "SELECT COUNT(*) FROM evidence_disturbances WHERE case_id = ?", (case_id,)
                ).fetchone()[0]
                if existing > 0:
                    return []

                # Look for anti-forensic cluster types
                rows = conn.execute(
                    """
                    SELECT cluster_id, cluster_type, primary_host, score,
                           time_start, time_end, triggers_fired, summary
                    FROM clusters
                    WHERE case_id = ? AND cluster_type IN (
                        'log_clearing', 'shadow_deletion', 'timestomp',
                        'wevutil_clear', 'eventlog_disabled', 'backup_deletion'
                    )
                    """,
                    (case_id,),
                ).fetchall()

                for r in rows:
                    triggers = []
                    try:
                        triggers = json.loads(r["triggers_fired"] or "[]")
                    except (json.JSONDecodeError, TypeError):
                        pass

                    dist_id = f"dist-{r['cluster_id'][:16]}"
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO evidence_disturbances
                        (disturbance_id, case_id, host, window_start, window_end,
                         disturbance_type, detected_by, source_audit_id, details, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            dist_id,
                            case_id,
                            r["primary_host"] or "unknown",
                            r["time_start"],
                            r["time_end"],
                            r["cluster_type"],
                            "constructor",
                            r["cluster_id"],
                            json.dumps({"score": r["score"], "triggers": triggers, "summary": r["summary"]}),
                            datetime.now(timezone.utc).isoformat(),
                        ),
                    )
                    disturbances.append({
                        "disturbance_id": dist_id,
                        "host": r["primary_host"] or "unknown",
                        "window_start": r["time_start"],
                        "window_end": r["time_end"],
                        "disturbance_type": r["cluster_type"],
                        "detected_by": "constructor",
                        "details": json.dumps({"score": r["score"], "triggers": triggers}),
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    })
        except Exception as exc:
            logger.warning("Auto-detect disturbances failed: %s", exc)
        return disturbances

    def _detect_gaps(case_id: str) -> list[dict[str, Any]]:
        """Auto-detect evidence gaps from case capabilities and clusters."""
        gaps: list[dict[str, Any]] = []
        try:
            with connect(get_active_case().graph_db, read_only=False) as conn:
                existing = conn.execute(
                    "SELECT COUNT(*) FROM evidence_gaps WHERE case_id = ?", (case_id,)
                ).fetchone()[0]
                if existing > 0:
                    return []

                # Get case capabilities
                cap_row = conn.execute(
                    "SELECT artifact_types, has_memory, has_network FROM case_capabilities WHERE case_id = ?",
                    (case_id,),
                ).fetchone()

                if not cap_row:
                    return []

                artifact_types: list[str] = []
                try:
                    artifact_types = json.loads(cap_row["artifact_types"] or "[]")
                except (json.JSONDecodeError, TypeError):
                    pass

                # Check for missing core evidence types
                expected_types = {
                    "evtx": ("No Windows Event Logs ingested", "Ingest Security.evtx, System.evtx, Application.evtx"),
                    "memory": ("No memory dump available", "Ingest a .mem or .raw memory dump"),
                    "pcap": ("No network capture available", "Ingest a .pcap or .pcapng file"),
                    "registry": ("No registry hives ingested", "Ingest SAM, SYSTEM, SOFTWARE hives"),
                }

                for key, (question, resolve) in expected_types.items():
                    has_it = key in [a.lower() for a in artifact_types]
                    if key == "memory":
                        has_it = bool(cap_row["has_memory"])
                    if key == "pcap":
                        has_it = bool(cap_row["has_network"])
                    if not has_it:
                        gap_id = f"gap-{key}-{case_id[:8]}"
                        conn.execute(
                            """
                            INSERT OR IGNORE INTO evidence_gaps
                            (gap_id, case_id, question, what_would_resolve, blocks_hypothesis,
                             blocks_report, registered_at, registered_by)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                gap_id,
                                case_id,
                                question,
                                resolve,
                                None,
                                0,
                                datetime.now(timezone.utc).isoformat(),
                                "auto-detection",
                            ),
                        )
                        gaps.append({
                            "gap_id": gap_id,
                            "question": question,
                            "what_would_resolve": resolve,
                            "blocks_hypothesis": None,
                            "registered_at": datetime.now(timezone.utc).isoformat(),
                            "registered_by": "auto-detection",
                        })

                # Check cluster diversity: if only one constructor type, that's a gap
                cluster_types = conn.execute(
                    "SELECT DISTINCT cluster_type FROM clusters WHERE case_id = ?",
                    (case_id,),
                ).fetchall()
                if len(cluster_types) <= 1:
                    gap_id = f"gap-diversity-{case_id[:8]}"
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO evidence_gaps
                        (gap_id, case_id, question, what_would_resolve, blocks_hypothesis,
                         blocks_report, registered_at, registered_by)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            gap_id,
                            case_id,
                            "Only one behavioral cluster type detected",
                            "Ingest additional evidence types (EVTX, memory, network) to trigger more constructors",
                            None,
                            0,
                            datetime.now(timezone.utc).isoformat(),
                            "auto-detection",
                        ),
                    )
                    gaps.append({
                        "gap_id": gap_id,
                        "question": "Only one behavioral cluster type detected",
                        "what_would_resolve": "Ingest additional evidence types (EVTX, memory, network) to trigger more constructors",
                        "blocks_hypothesis": None,
                        "registered_at": datetime.now(timezone.utc).isoformat(),
                        "registered_by": "auto-detection",
                    })
        except Exception as exc:
            logger.warning("Auto-detect gaps failed: %s", exc)
        return gaps

    # ========================================================
    # Routes
    # ========================================================

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        """Portal home page."""
        try:
            case_id = _get_case_id()
            with _get_db() as conn:
                # Get case summary
                case_row = conn.execute(
                    "SELECT * FROM case_capabilities WHERE case_id = ?", (case_id,)
                ).fetchone()

                # Get counts
                clusters = conn.execute(
                    "SELECT COUNT(*) FROM clusters WHERE case_id = ?", (case_id,)
                ).fetchone()[0]

                hypotheses = conn.execute(
                    "SELECT COUNT(*) FROM hypotheses WHERE case_id = ?", (case_id,)
                ).fetchone()[0]

                approved = conn.execute(
                    "SELECT COUNT(*) FROM hypotheses WHERE case_id = ? AND status = 'APPROVED'",
                    (case_id,),
                ).fetchone()[0]

                entities = conn.execute(
                    "SELECT COUNT(*) FROM entities WHERE case_id = ?", (case_id,)
                ).fetchone()[0]

                disturbances = conn.execute(
                    "SELECT COUNT(*) FROM evidence_disturbances WHERE case_id = ?",
                    (case_id,),
                ).fetchone()[0]

                # Get top clusters
                top_clusters = conn.execute(
                    """
                    SELECT cluster_id, cluster_type, primary_host, score, strength, summary
                    FROM clusters WHERE case_id = ? ORDER BY score DESC LIMIT 10
                    """,
                    (case_id,),
                ).fetchall()

                # Get recent hypotheses
                recent_hypotheses = conn.execute(
                    """
                    SELECT hypothesis_id, title, status, confidence_score, confidence_tier, staged_at
                    FROM hypotheses WHERE case_id = ?
                    ORDER BY staged_at DESC LIMIT 10
                    """,
                    (case_id,),
                ).fetchall()

                # Get open evidence gaps
                gaps_rows = conn.execute(
                    """
                    SELECT gap_id, question, blocks_hypothesis, registered_at
                    FROM evidence_gaps WHERE case_id = ? AND resolved_at IS NULL
                    ORDER BY registered_at DESC LIMIT 10
                    """,
                    (case_id,),
                ).fetchall()
        except sqlite3.OperationalError as exc:
            logger.warning("Database schema error in dashboard: %s", exc)
            case_row = None
            clusters = hypotheses = approved = entities = disturbances = 0
            top_clusters = []
            recent_hypotheses = []
            gaps_rows = []
        except HTTPException:
            raise
        except Exception as exc:
            logger.warning("Failed to load dashboard data: %s", exc)
            case_row = None
            clusters = hypotheses = approved = entities = disturbances = 0
            top_clusters = []
            recent_hypotheses = []
            gaps_rows = []

        active_case = get_active_case()
        return templates.TemplateResponse(request, "index.html", {
            "case": active_case.__dict__ if active_case else {},
            "stats": {
                "clusters": clusters,
                "hypotheses": hypotheses,
                "approved": approved,
                "entities": entities,
                "disturbances": disturbances,
            },
            "top_clusters": [dict(c) for c in top_clusters],
            "recent_hypotheses": [dict(h) for h in recent_hypotheses],
            "gaps": [dict(g) for g in gaps_rows],
        })

    @app.get("/clusters", response_class=HTMLResponse)
    async def clusters_page(request: Request):
        """Clusters list page."""
        try:
            case_id = _get_case_id()
            with _get_db() as conn:
                rows = conn.execute(
                    """
                    SELECT cluster_id, cluster_type, primary_host, score, strength, 
                           time_start, summary, created_at
                    FROM clusters WHERE case_id = ?
                    ORDER BY score DESC
                    """,
                    (case_id,),
                ).fetchall()
                clusters = [dict(r) for r in rows]
        except sqlite3.OperationalError as exc:
            logger.error("Database schema error loading clusters: %s", exc)
            clusters = []
        except Exception as exc:
            logger.warning("Failed to load clusters: %s", exc)
            clusters = []

        return templates.TemplateResponse(request, "clusters.html", {
            "clusters": clusters,
        })

    @app.get("/clusters/{cluster_id}", response_class=HTMLResponse)
    async def cluster_detail(request: Request, cluster_id: str):
        """Single cluster detail page."""
        try:
            with _get_db() as conn:
                row = conn.execute(
                    "SELECT * FROM clusters WHERE cluster_id = ?", (cluster_id,)
                ).fetchone()

                if not row:
                    raise HTTPException(status_code=404, detail="Cluster not found")

                cluster = dict(row)
                # Parse JSON fields
                for field in ["trigger_event", "supporting_signals", "counter_evidence_details",
                              "contradicting_clusters", "member_events"]:
                    if cluster.get(field):
                        try:
                            cluster[field] = json.loads(cluster[field])
                        except (json.JSONDecodeError, TypeError):
                            pass

                # Get related hypotheses
                hypotheses = conn.execute(
                    """
                    SELECT hypothesis_id, title, status, confidence_score, interpretation
                    FROM hypotheses WHERE suggested_by_cluster = ?
                    """,
                    (cluster_id,),
                ).fetchall()
        except HTTPException:
            raise
        except Exception as exc:
            logger.warning("Failed to load cluster %s: %s", cluster_id, exc)
            cluster = {}
            hypotheses = []

        return templates.TemplateResponse(request, "cluster_detail.html", {
            "cluster": cluster,
            "hypotheses": [dict(h) for h in hypotheses],
        })

    @app.get("/hypotheses", response_class=HTMLResponse)
    async def hypotheses_page(request: Request):
        """Hypotheses list page."""
        try:
            case_id = _get_case_id()
            with _get_db() as conn:
                rows = conn.execute(
                    """
                    SELECT hypothesis_id, title, status, confidence_score, confidence_tier,
                           staged_at, approved_at, technique_ids
                    FROM hypotheses WHERE case_id = ?
                    ORDER BY staged_at DESC
                    """,
                    (case_id,),
                ).fetchall()
                hypotheses = []
                for r in rows:
                    h = dict(r)
                    if h.get("technique_ids"):
                        try:
                            h["technique_ids"] = json.loads(h["technique_ids"])
                        except (json.JSONDecodeError, TypeError):
                            h["technique_ids"] = []
                    hypotheses.append(h)
        except sqlite3.OperationalError as exc:
            logger.error("Database schema error loading hypotheses: %s", exc)
            hypotheses = []
        except Exception as exc:
            logger.warning("Failed to load hypotheses: %s", exc)
            hypotheses = []

        return templates.TemplateResponse(request, "hypotheses.html", {
            "hypotheses": hypotheses,
        })

    @app.get("/hypotheses/{hypothesis_id}", response_class=HTMLResponse)
    async def hypothesis_detail(request: Request, hypothesis_id: str):
        """Single hypothesis detail page."""
        try:
            with _get_db() as conn:
                row = conn.execute(
                    "SELECT * FROM hypotheses WHERE hypothesis_id = ?", (hypothesis_id,)
                ).fetchone()

                if not row:
                    raise HTTPException(status_code=404, detail="Hypothesis not found")

                hypothesis = dict(row)
                # Parse JSON fields
                for field in ["technique_ids", "evidence_refs", "audit_ids", 
                              "confidence_breakdown", "causal_links"]:
                    if hypothesis.get(field):
                        try:
                            hypothesis[field] = json.loads(hypothesis[field])
                        except (json.JSONDecodeError, TypeError):
                            pass

                # Get related clusters
                related_clusters = conn.execute(
                    """
                    SELECT cluster_id, cluster_type, summary, score
                    FROM clusters WHERE cluster_id IN (
                        SELECT suggested_by_cluster FROM hypotheses WHERE hypothesis_id = ?
                    )
                    """,
                    (hypothesis_id,),
                ).fetchall()
        except HTTPException:
            raise
        except Exception as exc:
            logger.warning("Failed to load hypothesis %s: %s", hypothesis_id, exc)
            hypothesis = {}
            related_clusters = []

        return templates.TemplateResponse(request, "hypothesis_detail.html", {
            "hypothesis": hypothesis,
            "related_clusters": [dict(c) for c in related_clusters],
        })

    @app.get("/timeline", response_class=HTMLResponse)
    async def timeline_page(request: Request):
        """Interactive timeline page."""
        try:
            case_id = _get_case_id()
            with _get_db() as conn:
                rows = conn.execute(
                    """
                    SELECT timestamp, edge_type, from_entity, to_entity, properties
                    FROM edges WHERE case_id = ? AND timestamp IS NOT NULL
                    ORDER BY timestamp ASC
                    LIMIT 500
                    """,
                    (case_id,),
                ).fetchall()

                events = []
                for r in rows:
                    evt = dict(r)
                    if evt.get("properties"):
                        try:
                            evt["properties"] = json.loads(evt["properties"])
                        except (json.JSONDecodeError, TypeError):
                            pass
                    events.append(evt)
        except Exception as exc:
            logger.warning("Failed to load timeline: %s", exc)
            events = []

        return templates.TemplateResponse(request, "timeline.html", {
            "events": events,
        })

    @app.get("/evidence", response_class=HTMLResponse)
    async def evidence_page(
        request: Request,
        canonical_type: str = "",
        host: str = "",
        limit: int = 500,
    ):
        """Browse ingested canonical events."""
        try:
            case_id = _get_case_id()
            client = _get_client()
            from nighteye.ingest.ecs import case_index_pattern

            indices = client.list_indices(case_index_pattern(case_id, "canonical-*"))
            events: list[dict] = []
            type_counts: dict[str, int] = {}
            host_counts: dict[str, int] = {}

            for index_name in indices:
                query: dict = {"match_all": {}}
                if canonical_type or host:
                    must: list[dict] = []
                    if canonical_type:
                        must.append({"term": {"canonical_type": canonical_type}})
                    if host:
                        must.append({"term": {"host_name": host}})
                    query = {"bool": {"must": must}}

                try:
                    for page in client.scroll_search_iter(
                        index=index_name,
                        query=query,
                        page_size=1000,
                    ):
                        for doc in page:
                            source = doc.get("_source", doc)
                            ev = {
                                "index": index_name,
                                "event_id": source.get("event_id", ""),
                                "canonical_type": source.get("canonical_type", "UNKNOWN"),
                                "host_name": source.get("host_name", "unknown"),
                                "timestamp": source.get("@timestamp", source.get("timestamp", "")),
                                "user": source.get("user", ""),
                                "process_name": source.get("process_name", ""),
                                "command_line": source.get("command_line", ""),
                                "target_file": source.get("target_file", ""),
                                "registry_key": source.get("registry_key", ""),
                                "remote_ip": source.get("remote_ip", ""),
                                "alert_name": source.get("alert_name", ""),
                            }
                            events.append(ev)
                            type_counts[ev["canonical_type"]] = type_counts.get(ev["canonical_type"], 0) + 1
                            host_counts[ev["host_name"]] = host_counts.get(ev["host_name"], 0) + 1
                            if len(events) >= limit:
                                break
                        if len(events) >= limit:
                            break
                except Exception as exc:
                    logger.warning("Failed to query canonical index %s: %s", index_name, exc)

            events.sort(key=lambda e: e.get("timestamp") or "", reverse=True)
        except Exception as exc:
            logger.warning("Failed to load evidence: %s", exc)
            events = []
            type_counts = {}
            host_counts = {}
            indices = []

        return templates.TemplateResponse(request, "evidence.html", {
            "events": events,
            "type_counts": type_counts,
            "host_counts": host_counts,
            "indices": indices,
            "filter_type": canonical_type,
            "filter_host": host,
        })

    @app.get("/indices", response_class=HTMLResponse)
    async def indices_page(request: Request):
        """Show OpenSearch indices for this case."""
        try:
            case_id = _get_case_id()
            client = _get_client()

            raw_indices = client.list_case_indices(case_id)
            index_info: list[dict] = []
            for info in sorted(raw_indices, key=lambda x: x.get("index", "")):
                index_info.append({
                    "name": info.get("index", ""),
                    "docs": info.get("docs_count", 0),
                    "size": info.get("size", "0b"),
                })
        except Exception as exc:
            logger.warning("Failed to load indices: %s", exc)
            index_info = []

        return templates.TemplateResponse(request, "indices.html", {
            "indices": index_info,
        })

    @app.get("/index/{index_name}", response_class=HTMLResponse)
    async def index_detail_page(
        request: Request,
        index_name: str,
        q: str = "",
        page: int = 1,
        page_size: int = 50,
    ):
        """Drill into a single OpenSearch index and list documents."""
        docs: list[dict] = []
        total = 0
        try:
            client = _get_client()
            # Validate the index exists and belongs to this case
            case_id = _get_case_id()
            raw_indices = client.list_case_indices(case_id)
            valid_names = {i.get("index", "") for i in raw_indices}
            if index_name not in valid_names:
                raise HTTPException(status_code=404, detail="Index not found for this case")

            query: dict = {"match_all": {}}
            if q:
                query = {
                    "query_string": {
                        "query": q,
                        "default_operator": "AND",
                    }
                }

            result = client.search_raw(
                index=index_name,
                query=query,
                from_=(page - 1) * page_size,
                size=page_size,
            )
            hits = result.get("hits", {})
            total = hits.get("total", {}).get("value", 0)
            for hit in hits.get("hits", []):
                source = hit.get("_source", {})
                docs.append({
                    "id": hit.get("_id", ""),
                    "source": source,
                    "preview": json.dumps(source, indent=2, default=str)[:500],
                })
        except HTTPException:
            raise
        except Exception as exc:
            logger.warning("Failed to query index %s: %s", index_name, exc)
            docs = []
            total = 0

        total_pages = (total + page_size - 1) // page_size
        return templates.TemplateResponse(request, "index_docs.html", {
            "index_name": index_name,
            "docs": docs,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "q": q,
        })

    @app.get("/graph", response_class=HTMLResponse)
    async def graph_page(request: Request, entity_type: str = ""):
        """Interactive graph visualization page."""
        try:
            case_id = _get_case_id()
            with _get_db() as conn:
                # Build entity query with optional filter
                entity_sql = """
                    SELECT entity_id, entity_type, canonical_key, properties, first_seen, last_seen
                    FROM entities WHERE case_id = ?
                """
                entity_params: list = [case_id]
                if entity_type:
                    entity_sql += " AND entity_type = ?"
                    entity_params.append(entity_type)
                entity_sql += " LIMIT 100"

                entity_rows = conn.execute(entity_sql, entity_params).fetchall()

                entity_ids = {r["entity_id"] for r in entity_rows}

                # Get edges for these entities
                if entity_ids:
                    placeholders = ",".join("?" * len(entity_ids))
                    edge_rows = conn.execute(
                        f"""
                        SELECT from_entity, to_entity, edge_type, timestamp, properties
                        FROM edges WHERE case_id = ?
                        AND (from_entity IN ({placeholders}) OR to_entity IN ({placeholders}))
                        LIMIT 500
                        """,
                        (case_id,) + tuple(entity_ids) + tuple(entity_ids),
                    ).fetchall()
                else:
                    edge_rows = []

                nodes = []
                for r in entity_rows:
                    n = dict(r)
                    if n.get("properties"):
                        try:
                            n["properties"] = json.loads(n["properties"])
                        except (json.JSONDecodeError, TypeError):
                            pass
                    nodes.append(n)

                links = []
                for r in edge_rows:
                    l = dict(r)
                    if l.get("properties"):
                        try:
                            l["properties"] = json.loads(l["properties"])
                        except (json.JSONDecodeError, TypeError):
                            pass
                    links.append(l)

                # Build Mermaid diagram — grouped by entity_type in subgraphs, TD layout
                mermaid_lines = ["flowchart TD"]
                by_type: dict[str, list[dict]] = {}
                for node in nodes:
                    by_type.setdefault(node["entity_type"], []).append(node)

                for etype, nlist in by_type.items():
                    safe_etype = etype.replace(" ", "_").replace("-", "_")
                    mermaid_lines.append(f"    subgraph {safe_etype} [{etype}]")
                    for node in nlist:
                        label = node["canonical_key"].replace('"', "'").replace("]", "&#93;").replace("[", "&#91;")
                        if len(label) > 40:
                            label = label[:37] + "..."
                        safe_id = node["entity_id"].replace('"', "'")
                        mermaid_lines.append(f'        {safe_id}["{label}"]')
                    mermaid_lines.append("    end")

                for link in links:
                    mermaid_lines.append(
                        f'    {link["from_entity"]} -->|{link["edge_type"]}| {link["to_entity"]}'
                    )

                mermaid_graph = "\n".join(mermaid_lines)

                # Available entity types for filter dropdown
                type_rows = conn.execute(
                    "SELECT DISTINCT entity_type FROM entities WHERE case_id = ?",
                    (case_id,),
                ).fetchall()
                available_types = [r["entity_type"] for r in type_rows]

        except Exception as exc:
            logger.warning("Failed to load graph: %s", exc)
            nodes = []
            links = []
            mermaid_graph = "flowchart TD\n    Empty[No data available]"
            available_types = []
            entity_type = ""

        return templates.TemplateResponse(request, "graph.html", {
            "nodes": nodes,
            "links": links,
            "mermaid_graph": mermaid_graph,
            "available_types": available_types,
            "current_type": entity_type,
        })

    @app.get("/disturbances", response_class=HTMLResponse)
    async def disturbances_page(request: Request):
        """Evidence disturbances page."""
        try:
            case_id = _get_case_id()
            # Auto-detect if table appears empty
            _detect_disturbances(case_id)
            with _get_db() as conn:
                rows = conn.execute(
                    """
                    SELECT disturbance_id, host, window_start, window_end, 
                           disturbance_type, detected_by, details, created_at
                    FROM evidence_disturbances WHERE case_id = ?
                    ORDER BY window_start DESC
                    """,
                    (case_id,),
                ).fetchall()
                disturbances = [dict(r) for r in rows]
        except Exception as exc:
            logger.warning("Failed to load disturbances: %s", exc)
            disturbances = []

        return templates.TemplateResponse(request, "disturbances.html", {
            "disturbances": disturbances,
        })

    @app.get("/gaps", response_class=HTMLResponse)
    async def gaps_page(request: Request):
        """Evidence gaps page."""
        try:
            case_id = _get_case_id()
            # Auto-detect if table appears empty
            _detect_gaps(case_id)
            with _get_db() as conn:
                rows = conn.execute(
                    """
                    SELECT gap_id, question, what_would_resolve, blocks_hypothesis,
                           registered_at, registered_by
                    FROM evidence_gaps WHERE case_id = ?
                    ORDER BY registered_at DESC
                    """,
                    (case_id,),
                ).fetchall()
                gaps = [dict(r) for r in rows]
        except Exception as exc:
            logger.warning("Failed to load gaps: %s", exc)
            gaps = []

        return templates.TemplateResponse(request, "gaps.html", {
            "gaps": gaps,
        })

    # ========================================================
    # API Endpoints
    # ========================================================

    @app.get("/api/case/{case_id}/status")
    async def api_case_status(case_id: str):
        """API: Get case status."""
        try:
            with _get_db() as conn:
                case_row = conn.execute(
                    "SELECT * FROM case_capabilities WHERE case_id = ?", (case_id,)
                ).fetchone()

                if not case_row:
                    raise HTTPException(status_code=404, detail="Case not found")

                counts = {
                    "clusters": conn.execute(
                        "SELECT COUNT(*) FROM clusters WHERE case_id = ?", (case_id,)
                    ).fetchone()[0],
                    "hypotheses": conn.execute(
                        "SELECT COUNT(*) FROM hypotheses WHERE case_id = ?", (case_id,)
                    ).fetchone()[0],
                    "approved": conn.execute(
                        "SELECT COUNT(*) FROM hypotheses WHERE case_id = ? AND status = 'APPROVED'",
                        (case_id,),
                    ).fetchone()[0],
                    "entities": conn.execute(
                        "SELECT COUNT(*) FROM entities WHERE case_id = ?", (case_id,)
                    ).fetchone()[0],
                    "edges": conn.execute(
                        "SELECT COUNT(*) FROM edges WHERE case_id = ?", (case_id,)
                    ).fetchone()[0],
                }

                return JSONResponse({
                    "case": dict(case_row),
                    "counts": counts,
                })
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("API error")
            raise HTTPException(status_code=500, detail=str(exc))

    @app.get("/api/clusters")
    async def api_clusters(
        constructor: str | None = None,
        host: str | None = None,
        min_score: int = 0,
        limit: int = 100,
    ):
        """API: List clusters with filtering."""
        try:
            case_id = _get_case_id()
            with _get_db() as conn:
                sql = """
                    SELECT cluster_id, cluster_type as constructor_name, primary_host as host, 
                           score, strength, mitre_tactic as status, triggers_fired, summary, created_at
                    FROM clusters WHERE case_id = ? AND score >= ?
                """
                params = [case_id, min_score]

                if constructor:
                    sql += " AND cluster_type = ?"
                    params.append(constructor)
                if host:
                    sql += " AND primary_host = ?"
                    params.append(host)

                sql += " ORDER BY score DESC LIMIT ?"
                params.append(limit)

                rows = conn.execute(sql, params).fetchall()
                return JSONResponse({
                    "clusters": [dict(r) for r in rows],
                    "total": len(rows),
                })
        except Exception as exc:
            logger.exception("API error")
            raise HTTPException(status_code=500, detail=str(exc))

    @app.get("/api/hypotheses")
    async def api_hypotheses(
        status: str | None = None,
        limit: int = 50,
    ):
        """API: List hypotheses."""
        try:
            case_id = _get_case_id()
            with _get_db() as conn:
                sql = """
                    SELECT hypothesis_id, title, status, confidence_score, confidence_tier,
                           staged_at, technique_ids
                    FROM hypotheses WHERE case_id = ?
                """
                params = [case_id]

                if status:
                    sql += " AND status = ?"
                    params.append(status)

                sql += " ORDER BY staged_at DESC LIMIT ?"
                params.append(limit)

                rows = conn.execute(sql, params).fetchall()
                hypotheses = []
                for r in rows:
                    h = dict(r)
                    if h.get("technique_ids"):
                        try:
                            h["technique_ids"] = json.loads(h["technique_ids"])
                        except (json.JSONDecodeError, TypeError):
                            pass
                    hypotheses.append(h)

                return JSONResponse({
                    "hypotheses": hypotheses,
                    "total": len(hypotheses),
                })
        except Exception as exc:
            logger.exception("API error")
            raise HTTPException(status_code=500, detail=str(exc))

    @app.get("/api/entities")
    async def api_entities(
        entity_type: str | None = None,
        limit: int = 100,
    ):
        """API: List entities."""
        try:
            case_id = _get_case_id()
            with _get_db() as conn:
                sql = "SELECT * FROM entities WHERE case_id = ?"
                params = [case_id]

                if entity_type:
                    sql += " AND entity_type = ?"
                    params.append(entity_type)

                sql += " ORDER BY last_seen DESC LIMIT ?"
                params.append(limit)

                rows = conn.execute(sql, params).fetchall()
                entities = []
                for r in rows:
                    e = dict(r)
                    if e.get("properties"):
                        try:
                            e["properties"] = json.loads(e["properties"])
                        except (json.JSONDecodeError, TypeError):
                            pass
                    entities.append(e)

                return JSONResponse({
                    "entities": entities,
                    "total": len(entities),
                })
        except Exception as exc:
            logger.exception("API error")
            raise HTTPException(status_code=500, detail=str(exc))

    @app.get("/api/timeline")
    async def api_timeline(
        start: str | None = None,
        end: str | None = None,
        limit: int = 500,
    ):
        """API: Get timeline events."""
        try:
            case_id = _get_case_id()
            with _get_db() as conn:
                sql = """
                    SELECT timestamp, edge_type, from_entity, to_entity, properties
                    FROM edges WHERE case_id = ? AND timestamp IS NOT NULL
                """
                params = [case_id]

                if start:
                    sql += " AND timestamp >= ?"
                    params.append(start)
                if end:
                    sql += " AND timestamp <= ?"
                    params.append(end)

                sql += " ORDER BY timestamp ASC LIMIT ?"
                params.append(limit)

                rows = conn.execute(sql, params).fetchall()
                events = []
                for r in rows:
                    e = dict(r)
                    if e.get("properties"):
                        try:
                            e["properties"] = json.loads(e["properties"])
                        except (json.JSONDecodeError, TypeError):
                            pass
                    events.append(e)

                return JSONResponse({
                    "events": events,
                    "total": len(events),
                })
        except Exception as exc:
            logger.exception("API error")
            raise HTTPException(status_code=500, detail=str(exc))

    @app.get("/api/graph-data")
    async def api_graph_data(
        entity_type: str | None = None,
        limit: int = 300,
    ):
        """API: Get graph data for visualization."""
        try:
            case_id = _get_case_id()
            with _get_db() as conn:
                # Get entities
                sql = """
                    SELECT entity_id, entity_type, canonical_key, properties
                    FROM entities WHERE case_id = ?
                """
                params = [case_id]

                if entity_type:
                    sql += " AND entity_type = ?"
                    params.append(entity_type)

                sql += " LIMIT ?"
                params.append(limit)

                entity_rows = conn.execute(sql, params).fetchall()

                # Get edges for these entities
                entity_ids = {r["entity_id"] for r in entity_rows}
                if entity_ids:
                    placeholders = ",".join("?" * len(entity_ids))
                    edge_rows = conn.execute(
                        f"""
                        SELECT from_entity, to_entity, edge_type, timestamp, properties
                        FROM edges WHERE case_id = ? 
                        AND from_entity IN ({placeholders}) AND to_entity IN ({placeholders})
                        LIMIT 500
                        """,
                        (case_id,) + tuple(entity_ids) + tuple(entity_ids),
                    ).fetchall()
                else:
                    edge_rows = []

                nodes = []
                for r in entity_rows:
                    n = dict(r)
                    if n.get("properties"):
                        try:
                            props = json.loads(n["properties"])
                            n["label"] = props.get("name", props.get("path", n["canonical_key"]))
                        except (json.JSONDecodeError, TypeError):
                            n["label"] = n["canonical_key"]
                    nodes.append(n)

                links = []
                for r in edge_rows:
                    l = dict(r)
                    if l.get("properties"):
                        try:
                            l["properties"] = json.loads(l["properties"])
                        except (json.JSONDecodeError, TypeError):
                            pass
                    links.append(l)

                return JSONResponse({
                    "nodes": nodes,
                    "links": links,
                })
        except Exception as exc:
            logger.exception("API error")
            raise HTTPException(status_code=500, detail=str(exc))

    @app.get("/api/search")
    async def api_search(
        q: str,
        type: str | None = None,
        limit: int = 50,
    ):
        """API: Search across all data."""
        try:
            case_id = _get_case_id()
            results = {"clusters": [], "hypotheses": [], "entities": []}

            with _get_db() as conn:
                # Search clusters
                if not type or type == "cluster":
                    rows = conn.execute(
                        """
                        SELECT cluster_id, constructor_name, host, score, summary
                        FROM clusters WHERE case_id = ? 
                        AND (summary LIKE ? OR constructor_name LIKE ? OR host LIKE ?)
                        LIMIT ?
                        """,
                        (case_id, f"%{q}%", f"%{q}%", f"%{q}%", limit),
                    ).fetchall()
                    results["clusters"] = [dict(r) for r in rows]

                # Search hypotheses
                if not type or type == "hypothesis":
                    rows = conn.execute(
                        """
                        SELECT hypothesis_id, title, interpretation, status
                        FROM hypotheses WHERE case_id = ?
                        AND (title LIKE ? OR interpretation LIKE ? OR observation LIKE ?)
                        LIMIT ?
                        """,
                        (case_id, f"%{q}%", f"%{q}%", f"%{q}%", limit),
                    ).fetchall()
                    results["hypotheses"] = [dict(r) for r in rows]

                # Search entities
                if not type or type == "entity":
                    rows = conn.execute(
                        """
                        SELECT entity_id, entity_type, canonical_key
                        FROM entities WHERE case_id = ?
                        AND (canonical_key LIKE ? OR entity_type LIKE ?)
                        LIMIT ?
                        """,
                        (case_id, f"%{q}%", f"%{q}%", limit),
                    ).fetchall()
                    results["entities"] = [dict(r) for r in rows]

            return JSONResponse(results)
        except Exception as exc:
            logger.exception("API error")
            raise HTTPException(status_code=500, detail=str(exc))

    return app


# ============================================================
# Entry Point
# ============================================================

def main() -> None:
    """Run the portal."""
    import uvicorn

    app = create_portal_app()
    uvicorn.run(app, host="127.0.0.1", port=4510)


if __name__ == "__main__":
    main()
