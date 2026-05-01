"""NightEye Explainability Portal.

Provides a local web interface for human analysts to review
the AI agent's findings, hypotheses, and forensic graph.

References:
    - docs/PORTAL.md
"""

from __future__ import annotations

import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import uvicorn
from pathlib import Path

from nighteye.case import get_case_dir

logger = logging.getLogger("nighteye.portal")

# FastAPI App
app = FastAPI(title="NightEye Explainability Portal")

# Setup templates
current_dir = Path(__file__).parent
templates_dir = current_dir / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

# Mock data generation for D15-D16 stubbing
def _get_case_stats() -> dict:
    case_dir = get_case_dir()
    return {
        "case_id": case_dir.name if case_dir else "NO ACTIVE CASE",
        "hosts": 4,
        "artifact_types": 7,
        "hypotheses_approved": 5,
        "hypotheses_draft": 3,
        "insufficient": 1,
        "rejected": 1,
    }


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Case Overview Dashboard."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"stats": _get_case_stats()}
    )


@app.get("/clusters", response_class=HTMLResponse)
async def list_clusters(request: Request):
    """View all threat clusters."""
    return templates.TemplateResponse(
        request=request,
        name="clusters.html",
        context={
            "clusters": [
                {"id": "cluster-001", "type": "Lateral Movement", "tier": "STRONG", "score": 90, "host": "DC01"},
                {"id": "cluster-002", "type": "Defense Evasion", "tier": "MODERATE", "score": 65, "host": "WKSTN-02"}
            ]
        }
    )


@app.get("/cluster/{cluster_id}", response_class=HTMLResponse)
async def view_cluster(request: Request, cluster_id: str):
    """View details, timeline, and artifacts for a specific cluster."""
    # Mock data for demonstration
    mock_cluster = {
        "id": cluster_id,
        "type": "Lateral Movement",
        "tier": "STRONG",
        "score": 90,
        "host": "DC01",
        "summary": "Lateral movement pattern detected on DC01. Network logon (Type 3) by stark\\admin from 10.0.0.50 followed by PsExec service installation.",
        "timeline": [
            {"time": "2026-04-30 14:22:10 UTC", "event": "Network Logon (Type 3) from 10.0.0.50", "type": "AUTHENTICATION"},
            {"time": "2026-04-30 14:22:15 UTC", "event": "File write to C$\\ADMIN$\\PSEXESVC.exe", "type": "FILE_MODIFICATION"},
            {"time": "2026-04-30 14:22:18 UTC", "event": "Service Installed: PSEXESVC", "type": "SERVICE_INSTALLATION"},
        ],
        "artifacts": [
            {"type": "extracted_string", "pattern": "IPv4", "value": "10.0.0.50", "source": "memory.dmp"},
            {"type": "extracted_string", "pattern": "IPv4", "value": "192.168.1.100", "source": "memory.dmp"},
            {"type": "cobalt_strike_config", "pattern": "C2 Domain", "value": "update.windows-services.net", "source": "memory.dmp"}
        ]
    }
    
    return templates.TemplateResponse(
        request=request,
        name="cluster_detail.html",
        context={"cluster": mock_cluster}
    )


@app.get("/hypotheses", response_class=HTMLResponse)
async def list_hypotheses(request: Request):
    """View all hypotheses."""
    return templates.TemplateResponse(
        request=request,
        name="hypotheses.html",
        context={
            "hypotheses": [
                {"id": "hyp-001", "status": "APPROVED", "tier": "HIGH", "title": "Lateral movement via PsExec", "techniques": ["T1021.002"]}
            ]
        }
    )


@app.get("/graph", response_class=HTMLResponse)
async def view_graph(request: Request):
    """View the entity relationship graph."""
    # A simple mock mermaid graph
    mock_mermaid = """
    graph TD
        DC01[DC01] -->|authenticated_as| ADMIN[stark\\admin]
        ADMIN -->|spawned| PSEXEC[psexec.exe]
        PSEXEC -->|connected_to| WKSTN02[WKSTN-02]
    """
    return templates.TemplateResponse(
        request=request,
        name="graph.html",
        context={"mermaid_graph": mock_mermaid}
    )


def start_portal(port: int = 4510) -> None:
    """Start the FastAPI Portal server."""
    logger.info("Starting NightEye Portal on http://127.0.0.1:%d", port)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
