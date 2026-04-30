# NightEye — Explainability Portal

Localhost-served web UI for human review of the agent's investigation.
Functional, not pretty. Same Python process as the MCP server, port
4510.

## Goals

1. **Reverse traversal of every conclusion.** Cluster → canonical events
   → raw artifact docs. Hypothesis → cluster → events → artifacts.
   Causal chain → proof edges → audit IDs → tool call → query.
2. **Entity-relationship visualization.** Server-rendered Mermaid graph
   of hosts, processes, files, users, network destinations and their
   relationships.
3. **Timeline reconstruction.** Chronological view of clusters,
   hypotheses, journal entries.
4. **Confidence transparency.** For each hypothesis, show the score
   breakdown — which factors applied, which were consulted, what the
   penalties were.
5. **Audit trail review.** Every tool invocation, with parameters,
   queries run, and result summaries.

## Non-goals (v1)

- Beautiful UX
- Mobile responsiveness
- Editing findings from the browser (CLI handles that)
- Authentication beyond localhost binding
- Real-time updates (page reload is fine)

---

## Stack

| Layer | Choice | Rationale |
|---|---|---|
| Web framework | **FastAPI** | Already async Python; same process as MCP |
| Templates | **Jinja2** | Server-rendered, no JS build |
| Diagrams | **Mermaid.js via CDN** | No build, renders client-side from server-emitted markdown |
| Interactivity | **HTMX via CDN** | No SPA framework; HTML-over-the-wire |
| Styling | **TailwindCSS via CDN** | No build step |
| Tables / data | Server-rendered HTML; HTMX swaps for filtering |

Total: zero build step. `pip install -e .` and the portal is live.

---

## Routes and pages

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Case overview |
| `/clusters` | GET | All clusters, filterable by type/strength/host |
| `/clusters/{cluster_id}` | GET | Cluster detail: members, counter-evidence, contradictions, expand |
| `/clusters/{cluster_id}/expand` | GET | Canonical events that compose this cluster |
| `/canonical/{event_id}` | GET | Canonical event detail + back-references to raw artifacts |
| `/raw/{index}/{doc_id}` | GET | Raw artifact document from OpenSearch |
| `/hypotheses` | GET | All hypotheses, filterable by status |
| `/hypotheses/{hypothesis_id}` | GET | Hypothesis detail: evidence, confidence breakdown, causal links, challenge verdict |
| `/graph` | GET | Entity-relationship graph (Mermaid), filter by host/entity-type |
| `/graph/host/{host}` | GET | Per-host graph |
| `/timeline` | GET | Chronological view of clusters + hypotheses + journal |
| `/timeline.json` | GET | JSON form for external tools |
| `/journal` | GET | Investigation journal, all entries |
| `/audit` | GET | Per-tool audit log, filterable |
| `/gaps` | GET | Open evidence gaps |
| `/report` | GET | Render the generated report (Markdown) as HTML |
| `/case/capabilities` | GET | Case profile (host count, artifact types, AF observed) |

### Removable under time pressure

If we slip on D15-D16, fold these into other pages and drop standalone routes:

- `/journal` → fold into hypothesis detail (per-hypothesis timeline view)
- `/timeline` → graph + clusters list approximates it
- `/gaps` → fold into hypothesis detail and case overview

Keep at minimum: `/`, `/clusters`, `/clusters/{id}`, `/hypotheses`,
`/hypotheses/{id}`, `/graph`, `/audit`.

---

## Page layouts

### `/` — Case overview

```
┌─────────────────────────────────────────────────────────────┐
│ NightEye | Case: INC-2026-001 (FOR508 lab) | shivang        │
├─────────────────────────────────────────────────────────────┤
│ Status                       │ Counts                       │
│   Hosts: 4                   │   Hypotheses APPROVED: 5     │
│   Artifact types: 7          │   Hypotheses DRAFT:    3     │
│   AF observed: yes           │   Insufficient:        1     │
│   Time range: 2015-09-...    │   Rejected:            1     │
├─────────────────────────────────────────────────────────────┤
│ Clusters by strength × type                                 │
│   STRONG     MODERATE   WEAK    NOISE                       │
│   ─────────────────────────────────────                     │
│   LM    3 │  LM   5  │  LM  12 │  LM  47                    │
│   PE    2 │  PE   4  │  ...                                 │
│   ...                                                        │
├─────────────────────────────────────────────────────────────┤
│ Recent journal entries (10)                                  │
│   14:32 HYPOTHESIS_RECORDED H-shivang-005                    │
│   14:35 HYPOTHESIS_CHALLENGED H-005 SUPPORTED                │
│   ...                                                        │
├─────────────────────────────────────────────────────────────┤
│ Open evidence gaps (2)                                       │
│   G-001: Did actor exfiltrate? Resolved by: gateway logs     │
└─────────────────────────────────────────────────────────────┘
```

### `/clusters/{id}` — Cluster detail

Sections:
1. **Header**: cluster_type, strength badge, score, time range, primary
   host/user, MITRE T-IDs.
2. **Summary**: 1-paragraph human-readable description.
3. **Triggers fired**: list with checkmarks.
4. **Supporting signals**: list with weights.
5. **Counter-evidence**: list with whether each applied + evidence.
6. **Contradicting clusters**: links if any.
7. **Member events**: table of canonical events, click each → /canonical/{id}.
8. **Hypotheses derived**: any hypotheses suggested-by this cluster.
9. **Expand to raw**: button → /clusters/{id}/expand → /raw/.

### `/hypotheses/{id}` — Hypothesis detail

Sections:
1. **Header**: ID, status badge, tier badge, MITRE T-IDs, examiner.
2. **Title + observation + interpretation**.
3. **Confidence breakdown**:
   - Applicable factors and their weights
   - Consulted factors (highlighted)
   - Penalties triggered
   - Final score with arithmetic shown
4. **Causal links**: each link with level and proof edges.
5. **Challenge verdict** (if challenged): verdict, reasoning, timestamp.
6. **Evidence refs**: list of (audit_id, cluster_id, canonical_event_ids).
   Click → drill to cluster → canonical → raw.
7. **Audit IDs**: linked to /audit/{id}.

### `/graph` — Entity-relationship

Server-rendered Mermaid diagram. Filterable by:
- Host (default: all)
- Entity type (default: all)
- Time window (default: full case)
- Min edges per entity (default: 1; helps reduce noise)

Generated as Mermaid markdown server-side, embedded in HTML, rendered
client-side by Mermaid.js CDN.

For large graphs (>200 nodes), display only the top-N pivot entities
(those with >=3 incident edges) and their immediate neighbors. Full
graph available as JSON download.

### `/timeline` — Chronological view

Vertical timeline. Each entry is one of:
- Cluster (badge by type, link to detail)
- Hypothesis (badge by tier, link to detail)
- Journal entry (badge by entry type)
- Anti-forensic disturbance window (highlighted band)

Filterable by host and entity type. Time is the y-axis.

---

## Implementation skeleton

```python
# src/nighteye/portal/app.py
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path

from nighteye.case import get_active_case
from nighteye.graph_db import GraphDB
from nighteye.opensearch_client import OSClient

app = FastAPI(title="NightEye Portal")

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

@app.get("/", response_class=HTMLResponse)
async def overview(request: Request):
    case = get_active_case()
    db = GraphDB(case.dir / "graph.db")
    overview_data = {
        "case": case,
        "capabilities": db.get_case_capabilities(case.id),
        "cluster_counts": db.cluster_counts_by_type_and_strength(case.id),
        "hypothesis_counts": db.hypothesis_counts_by_status(case.id),
        "recent_journal": db.journal_recent(case.id, limit=10),
        "open_gaps": db.evidence_gaps_open(case.id),
    }
    return templates.TemplateResponse("overview.html",
                                      {"request": request, **overview_data})

@app.get("/clusters", response_class=HTMLResponse)
async def clusters_list(request: Request,
                        cluster_type: str | None = None,
                        strength: str | None = None,
                        host: str | None = None):
    # ...
    pass

# ... more routes
```

Templates use Jinja2 inheritance from a `base.html` that provides nav,
TailwindCSS CDN link, Mermaid CDN, HTMX CDN.

---

## Server lifecycle

The portal runs in the same Python process as the MCP server. Two
options:

**Option A: Two separate servers via `uvicorn` multi-app**
```python
# nighteye/__main__.py
import uvicorn
from nighteye.mcp_server import mcp_app
from nighteye.portal.app import app as portal_app

if __name__ == "__main__":
    # uvicorn supports multiple apps via separate processes,
    # but for simplicity we run both servers via asyncio.gather
    import asyncio
    config1 = uvicorn.Config(mcp_app, host="127.0.0.1", port=4509)
    config2 = uvicorn.Config(portal_app, host="127.0.0.1", port=4510)
    server1 = uvicorn.Server(config1)
    server2 = uvicorn.Server(config2)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.gather(server1.serve(), server2.serve()))
```

**Option B: Mount the MCP under FastAPI** if FastMCP supports
ASGI integration. Cleaner if available.

Decision deferred to D14 — depends on FastMCP capabilities.

---

## What the operator sees

```bash
$ nighteye serve
NightEye starting...
  MCP server:    http://127.0.0.1:4509/mcp
  Portal:        http://127.0.0.1:4510/
  Active case:   INC-2026-001 (FOR508 lab)
  Hosts indexed: 4
  Constructors:  ready
  
[INFO] MCP listening on 127.0.0.1:4509
[INFO] Portal listening on 127.0.0.1:4510
```

Open `http://127.0.0.1:4510/` in a browser. Done.

---

## What's deferred to v2

- Authentication (anything beyond localhost)
- Edit/approve/reject from the browser (CLI handles it)
- Real-time updates (WebSocket / SSE)
- Mobile responsive layout
- Theming
- Per-page export (currently CLI exports JSON for everything)
- Multi-case selector in nav (currently active-case only)
