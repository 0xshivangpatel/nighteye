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
        except sqlite3.OperationalError as exc:
            logger.warning("Database schema error in dashboard: %s", exc)
            case_row = None
            clusters = hypotheses = approved = entities = disturbances = 0
            top_clusters = []
            recent_hypotheses = []
        except HTTPException:
            raise
        except Exception as exc:
            logger.warning("Failed to load dashboard data: %s", exc)
            case_row = None
            clusters = hypotheses = approved = entities = disturbances = 0
            top_clusters = []
            recent_hypotheses = []

        active_case = get_active_case()
        return templates.TemplateResponse("index.html", {
            "request": request,
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

        return templates.TemplateResponse("clusters.html", {
            "request": request,
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

        return templates.TemplateResponse("cluster_detail.html", {
            "request": request,
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

        return templates.TemplateResponse("hypotheses.html", {
            "request": request,
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

        return templates.TemplateResponse("hypothesis_detail.html", {
            "request": request,
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

        return templates.TemplateResponse("timeline.html", {
            "request": request,
            "events": events,
        })

    @app.get("/graph", response_class=HTMLResponse)
    async def graph_page(request: Request):
        """Interactive graph visualization page."""
        try:
            case_id = _get_case_id()
            with _get_db() as conn:
                # Get entities
                entity_rows = conn.execute(
                    """
                    SELECT entity_id, entity_type, canonical_key, properties, first_seen, last_seen
                    FROM entities WHERE case_id = ?
                    LIMIT 500
                    """,
                    (case_id,),
                ).fetchall()

                # Get edges
                edge_rows = conn.execute(
                    """
                    SELECT from_entity, to_entity, edge_type, timestamp, properties
                    FROM edges WHERE case_id = ?
                    LIMIT 1000
                    """,
                    (case_id,),
                ).fetchall()

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

                # Generate Mermaid code
                mermaid_lines = ["flowchart LR"]
                # Add nodes
                for node in nodes:
                    # Escape characters for Mermaid syntax safety
                    label = node["canonical_key"].replace('"', "'").replace("]", "&#93;").replace("[", "&#91;")
                    safe_id = node["entity_id"].replace('"', "'")
                    mermaid_lines.append(f'    {safe_id}["{node["entity_type"]}: {label}"]')
                
                # Add edges
                for link in links:
                    mermaid_lines.append(f'    {link["from_entity"]} -->|{link["edge_type"]}| {link["to_entity"]}')
                
                mermaid_graph = "\n".join(mermaid_lines)

        except Exception as exc:
            logger.warning("Failed to load graph: %s", exc)
            nodes = []
            links = []
            mermaid_graph = "flowchart LR\n    Empty[No data available]"

        return templates.TemplateResponse("graph.html", {
            "request": request,
            "nodes": nodes,
            "links": links,
            "mermaid_graph": mermaid_graph,
        })

    @app.get("/disturbances", response_class=HTMLResponse)
    async def disturbances_page(request: Request):
        """Evidence disturbances page."""
        try:
            case_id = _get_case_id()
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

        return templates.TemplateResponse("disturbances.html", {
            "request": request,
            "disturbances": disturbances,
        })

    @app.get("/gaps", response_class=HTMLResponse)
    async def gaps_page(request: Request):
        """Evidence gaps page."""
        try:
            case_id = _get_case_id()
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

        return templates.TemplateResponse("gaps.html", {
            "request": request,
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
