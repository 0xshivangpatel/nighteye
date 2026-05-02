# NightEye on SIFT — Boot-up Checklist

This document is the operational checklist for bringing NightEye up on
a SIFT Workstation VM and exercising all 8 layers end-to-end. Follow
top-to-bottom; every step has a verification command.

## 0. Prerequisites

| Item | How to check / install |
|---|---|
| SIFT VM with sudo | `whoami` should be `sansforensics` |
| Python 3.11+ | `python3 --version` (SIFT 2024 ships 3.12) |
| Docker (for OpenSearch) | `docker --version` and `docker ps` |
| 7zip CLI | `which 7z` (install: `sudo apt install p7zip-full`) |
| Git | `git --version` |

## 1. Clone + install

```bash
git clone https://github.com/0xshivangpatel/nighteye.git
cd nighteye

# Use Python 3.11+ if not default
python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -e ".[dev]"

# Verify console script
nighteye --help
```

Expected: help text listing `init / status / ingest / normalize / graph / cluster / report / list-cases / hypotheses / clusters / entities / full-pipeline / serve`.

## 2. Run the test suite

```bash
pytest -q
```

Expected: **379 passed, 1 warning**. If anything fails, stop and report — the rest of this checklist won't work cleanly.

## 3. Bring up OpenSearch

```bash
docker compose up -d opensearch
# Wait ~30s, then:
curl -s http://localhost:9200 | python3 -m json.tool
```

Expected: JSON with `cluster_name: nighteye-cluster`, `status: green` (or yellow).

## 4. Initialize a case

```bash
nighteye init --name "SIFT bootstrap" --examiner alice
nighteye status
```

Expected: case ID printed, status output shows zero clusters / hypotheses / entities.

## 5. Verify all 8 layers exercise

The synthetic E2E test in `tests/test_e2e_pipeline.py::test_full_pipeline_e2e`
exercises Layers 1–8 with an in-memory mock OpenSearch client. Run it
in isolation to confirm:

```bash
pytest tests/test_e2e_pipeline.py -v
```

Expected: `1 passed`. The test verifies:

| Layer | What it checks |
|---|---|
| L1 Ingest | Mock client receives raw doc batches |
| L2 Canonical | `run_normalization_pass` produces canonical events with `canonical_docs_created > 0` |
| L3 Graph | `build_graph_from_canonical` writes `host` and `registry` entities to SQLite |
| L4 Clustering | `run_all_constructors` produces ≥2 clusters across the 12 constructors, including `LateralMovement` and `Persistence` |
| L5 Hypothesis lifecycle | `record_hypothesis` returns DRAFT, gates evaluate, content_hash + provenance set |
| L6 Journal | (covered separately by `tests/test_mcp_tools.py::test_journal_tools_real_persist` — round-trips checkpoint/decision/query/resume through SQLite) |
| L7 Confidence engine | `confidence_score` and `confidence_tier` populated on the recorded hypothesis |
| L8 Portal | FastAPI test client GETs `/`, expects `200` with NightEye in the body |

## 6. Real ingest on real evidence

```bash
# Mount external drive, e.g.
# sudo mount /dev/sdb1 /mnt/evidence

nighteye full-pipeline /mnt/evidence/SRL-2015/

# Or step-by-step:
nighteye ingest /mnt/evidence/SRL-2015/
nighteye normalize
nighteye graph
nighteye cluster
nighteye report --format markdown -o /tmp/report.md
```

What you should see, per stage:

| Stage | Indicator |
|---|---|
| ingest | `documents_indexed: <large number>`, `hosts_detected: [...]` |
| normalize | `canonical_docs_created: <subset of indexed>` |
| graph | `entities_created`, `edges_created` both > 0 |
| cluster | `clusters_created` > 0, mix of strengths visible via `nighteye clusters -v` |

### Idempotency check (the user-reported bug)

```bash
# First run: extracts archives
nighteye ingest /mnt/evidence/SRL-2015/

# Now delete or unmount the evidence:
rm -rf /tmp/scratch/*.zip
# (Or move external drive to a different machine)

# Run again with a different path that has nothing:
nighteye ingest /tmp/scratch/
# Expected: NightEye still surfaces the previously-extracted dirs
# from <case>/extractions/ and continues with normalize/cluster.
```

This is verified by `tests/test_extract_idempotent.py` (5 tests, all
pass). The fix is a marker file (`.nighteye_extracted`) written into
each successful extraction; on re-run the function returns every
directory under `case/extractions/` that has either the marker or any
non-marker content.

## 7. Bring up MCP + Portal

```bash
nighteye serve
```

Expected output:

```
============================================================
NIGHTEYE — Starting MCP server + Portal
============================================================
  MCP server: http://127.0.0.1:4509/mcp/
  Portal:     http://127.0.0.1:4510/
  Active case: <case-id> (<case name>)
============================================================
INFO:     Started server process
INFO:     Uvicorn running on http://127.0.0.1:4509
INFO:     Uvicorn running on http://127.0.0.1:4510
```

Open `http://127.0.0.1:4510/` in a browser → portal loads.
Connect Claude Code to `http://127.0.0.1:4509/mcp` → 42 tools exposed.

## 8. MCP smoke test (optional, before connecting Claude Code)

In a new terminal while `nighteye serve` is running:

```bash
# List tools via MCP protocol
curl -s -X POST http://127.0.0.1:4509/mcp/ \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | head -40
```

Expected: JSON-RPC response with `result.tools[]` containing tool names like `tool_search_evidence`, `tool_list_clusters`, `tool_record_hypothesis`, `tool_journal_resume`, etc.

## 9. Connect Claude Code

In your Claude Code config (`~/.config/Claude/claude_desktop_config.json`
or via the CLI), add:

```json
{
  "mcpServers": {
    "nighteye": {
      "transport": "streamable_http",
      "url": "http://127.0.0.1:4509/mcp/"
    }
  }
}
```

Restart Claude Code. The 42 NightEye tools should appear in the tool picker.

## Layer-by-Layer Quick Reference

| Layer | Module | Test file | MCP tool prefix |
|---|---|---|---|
| L1 Wide ingest | `src/nighteye/ingest/` | `tests/test_ingest.py`, `test_evtx.py`, `test_parsers.py`, `test_orchestrator.py`, `test_extract_idempotent.py` | (driven by CLI, not MCP) |
| L2 Canonical | `src/nighteye/canonical/` | `tests/test_e2e_pipeline.py` | (post-ingest, not MCP) |
| L3 Graph | `src/nighteye/graph/` | `tests/test_e2e_pipeline.py` | `query_entity`, `query_neighbors`, `find_path`, `get_entity_details`, `search_entities` |
| L4 Constructors | `src/nighteye/constructors/` | `tests/test_constructors.py`, `test_persistence_evasion.py`, `test_additional_constructors.py` | `list_clusters`, `get_cluster_details`, `get_cluster_timeline`, `get_cluster_artifacts`, `get_cluster_counter_evidence` |
| L5 Hypothesis | `src/nighteye/hypothesis_lifecycle.py` | `tests/test_causation_provenance.py`, e2e | `record_hypothesis`, `challenge_hypothesis`, `approve_hypothesis`, `reject_hypothesis`, `list_hypotheses`, `get_hypothesis_details`, `establish_causation`, `mark_insufficient_evidence` |
| L6 Journal | `src/nighteye/journal.py` | `tests/test_mcp_tools.py::test_journal_tools_real_persist` | `journal_checkpoint`, `journal_record_decision`, `journal_query`, `journal_resume` |
| L7 Confidence | `src/nighteye/confidence.py` | `tests/test_confidence.py` (~80 tests) | (gates inside `record_hypothesis`) |
| L8 Portal | `src/nighteye/portal/` | `tests/test_e2e_pipeline.py` | (HTTP, not MCP) |

## Troubleshooting

| Symptom | Cause / Fix |
|---|---|
| `ModuleNotFoundError: No module named 'fastmcp'` | `pip install -e ".[dev]"` (fastmcp is a pinned dep) |
| `7z: command not found` | `sudo apt install p7zip-full` |
| OpenSearch returns 401/403 | docker-compose disables security; ensure compose is up: `docker ps \| grep opensearch` |
| `nighteye serve` exits with port-in-use | Another process on 4509 or 4510. Override: `nighteye serve --mcp-port 4609 --portal-port 4610` |
| Portal page renders but "Static directory not found" warning | Already fixed — empty `src/nighteye/portal/static/.gitkeep` exists |
| Ingest finds no archives but I have already extracted | Idempotency fix surfaces existing extractions automatically; check `<case>/extractions/` for previously extracted dirs |
| Portal shows 0 clusters after ingest | Run `nighteye normalize` then `nighteye cluster` (or use `full-pipeline`) |
