# NightEye — Build Plan

3-week build, then 3 weeks of testing/iteration before the June 15
submission deadline. Iterative — each chunk has an explicit test point
the operator can run on a Windows VM / SIFT before the next chunk
starts.

## Approach

- **One small chunk at a time.** Build → operator tests → fix → next.
- **Every chunk has a verifiable test.** If you can't test it, it's
  not a chunk yet — break it down further.
- **No chunk depends on a yet-unbuilt chunk** (within reason).
- **Failures are caught early.** If a chunk fails operator testing,
  fix before proceeding.

## Timeline overview

| Week | Focus |
|---|---|
| 1 | Foundation + ingest pipeline (no agent yet, no portal yet) |
| 2 | Constructors + canonical events + agent loop + portal scaffold |
| 3 | Polish + demo + accuracy report + submission |

---

## Week 1 — Foundation + ingest

### D1 — Repo scaffold

**Builds:**
- `pyproject.toml` (Python 3.11+, deps: opensearch-py, sqlalchemy or
  raw sqlite3, fastmcp, fastapi, jinja2, uvicorn, pydantic, pyyaml,
  pytest, ruff)
- `LICENSE` (MIT)
- `.gitignore`
- `src/nighteye/__init__.py`, `src/nighteye/cli.py` skeleton
- `tests/__init__.py`, `tests/test_smoke.py`
- `pytest.ini`, `ruff.toml`

**Operator test:**
```bash
cd ~/NightEye/code  # or wherever
git clone <repo>
cd nighteye
pip install -e ".[dev]"
nighteye --help
pytest
```
Expected: CLI prints help, pytest passes (1 trivial smoke test).

### D2 — Schemas + SQLite layer + audit log

**Builds:**
- `src/nighteye/schema/graph.sql` — full schema from ARCHITECTURE.md § 7
- `src/nighteye/schema/__init__.py` — schema initialization functions
- `src/nighteye/db.py` — SQLite connection helper, WAL mode, retry
- `src/nighteye/audit.py` — audit_call helper, sequential ID generation
- `src/nighteye/models.py` — Python dataclasses for Hypothesis,
  EvidenceGap, JournalEntry, ConfidenceBreakdown, etc.
- Tests: schema creation, idempotent re-run, audit ID sequencing,
  dataclass round-tripping JSON

**Operator test:**
```bash
nighteye case init "test"        # creates ~/cases/test-XXX/graph.db
sqlite3 ~/cases/test-*/graph.db ".tables"
# Should list: entities, edges, evidence_disturbances, case_capabilities,
#              clusters, hypotheses, evidence_gaps, journal, audit
pytest tests/test_schema.py tests/test_audit.py
```

### D3 — Adaptive confidence engine

**Builds:**
- `src/nighteye/confidence.py` — adaptive scoring per ARCHITECTURE.md § 11
- `src/nighteye/causation.py` — causation ladder constants
- `src/nighteye/provenance.py` — provenance derivation
- Tests: every worked example from ARCHITECTURE.md § 11 passes

**Operator test:**
```bash
pytest tests/test_confidence.py -v
# All worked examples produce expected score and tier
python -c "
from nighteye.confidence import compute_adaptive_confidence
result = compute_adaptive_confidence(
    case_profile={'host_count': 1, ...},
    consulted=['provenance_tier', 'causal_lineage', ...],
    ...
)
print(result.score, result.tier, result.factor_contributions)
"
```

### D4 — Ingest pipeline scaffolding

**Builds:**
- `src/nighteye/ingest/__init__.py` — ingest orchestrator
- `src/nighteye/ingest/dispatch.py` — given a path, detect file type and
  route (E01 / KAPE zip / EVTX folder / memory dump)
- `src/nighteye/ingest/opensearch_client.py` — async OS client wrapper
  with bulk indexer + shard breaker
- `src/nighteye/ingest/ecs.py` — ECS field mapping helpers
- `src/nighteye/ingest/index_template.py` — installs OS index template

**Operator test:**
```bash
docker run -d -p 9200:9200 -e "discovery.type=single-node" \
  -e "OPENSEARCH_INITIAL_ADMIN_PASSWORD=Strong@123" \
  opensearchproject/opensearch:latest
# Wait 30s for OS to start
nighteye ingest --check-opensearch
# Expected: connects to localhost:9200, installs index template, returns OK
```

### D5 — EVTX ingest end-to-end

**Builds:**
- `src/nighteye/ingest/evtx.py` — EvtxECmd wrapper, JSON output parsing
- `src/nighteye/ingest/parsers/evtxecmd.py` — parser binding
- `src/nighteye/cli.py` `ingest` subcommand
- Test fixture: small EVTX file (~50KB, ~1000 events) in
  `tests/fixtures/evtx/`

**Operator test:**
```bash
nighteye case init "evtx-test"
nighteye ingest tests/fixtures/evtx/Security.evtx --host TEST-HOST
# Should index ~1000 docs to case-X-evtx-TEST-HOST
curl localhost:9200/case-*-evtx-TEST-HOST/_count
# Expected: count > 0
```

### D6 — Hayabusa + Chainsaw integration

**Builds:**
- `src/nighteye/ingest/hayabusa.py` — runner wrapper, JSONL output
  parsing, alert indexing
- `src/nighteye/ingest/chainsaw.py` — runner wrapper, alert indexing
- Both write to `case-X-hayabusa-{host}` and `case-X-chainsaw-{host}`

**Operator test:**
```bash
# Pre-req: Hayabusa + rules installed at /opt/hayabusa
nighteye ingest tests/fixtures/evtx/Security.evtx --host TEST-HOST
# After EVTX ingest, hayabusa should auto-run
curl localhost:9200/case-*-hayabusa-TEST-HOST/_count
# Expected: some alerts (depends on fixture content)
```

If Hayabusa not installed: clear error, skip step.

### D7 — Volatility 3 + MemProcFS + EZ Tools batch

**Builds:**
- `src/nighteye/ingest/volatility.py` — Vol3 plugin runner, output
  indexing per plugin
- `src/nighteye/ingest/memprocfs.py` — MemProcFS bulk extractor
- `src/nighteye/ingest/parsers/{amcache,mft,prefetch,registry,...}.py` —
  one parser per EZ Tool
- `src/nighteye/ingest/parsers/__init__.py` — registry of parsers

**Operator test:**
```bash
# With a small memory dump
nighteye ingest tests/fixtures/memory/tiny.mem --host TEST-HOST
curl localhost:9200/case-*-vol-pslist-TEST-HOST/_count
# Expected: some processes indexed

# With a small Amcache hive
nighteye ingest tests/fixtures/registry/Amcache.hve --host TEST-HOST
curl localhost:9200/case-*-amcache-TEST-HOST/_count
```

### Week 1 deliverable

A working `nighteye ingest` CLI that ingests EVTX, registry hives,
Amcache, MFT, Prefetch, and memory dumps into OpenSearch with proper
ECS mapping and Hayabusa alerts. **No agent yet, no portal.**

---

## Week 2 — Canonical + constructors + agent + portal scaffold

### D8 — Canonical event normalization

**Builds:**
- `src/nighteye/canonical/__init__.py`
- `src/nighteye/canonical/types.py` — all canonical event type constants
- `src/nighteye/canonical/mappers/{evtx,sysmon,vol3,zeek,...}.py` — each
  raw artifact type maps to canonical events
- Post-ingest pass that reads raw indices and writes canonical events
- Index `case-X-canonical-{host}` populated

**Operator test:**
```bash
nighteye normalize  # runs the canonical pass
curl localhost:9200/case-*-canonical-*/_count
# Expected: substantial doc count (subset of raw)
curl 'localhost:9200/case-*-canonical-*/_search?q=canonical_type:AUTHENTICATION'
# Expected: hits
```

### D9 — Constructor framework + LateralMovementConstructor

**Builds:**
- `src/nighteye/constructors/base.py` — Constructor / TriggerRule /
  SignalRule / Cluster classes
- `src/nighteye/constructors/scoring.py` — strength tiering,
  base+supporting+counter math
- `src/nighteye/constructors/lateral_movement.py` — full implementation
  per CONSTRUCTORS.md § 5.1
- Counter-evidence pre-computation for LM
- Cluster writer (SQLite + OpenSearch index)
- `tests/fixtures/canonical/lateral_movement_seeded.json`
- `tests/test_lateral_movement.py`

**Operator test:**
```bash
nighteye constructors run --type LateralMovement
sqlite3 ~/cases/test-*/graph.db "SELECT cluster_id, strength, score, summary FROM clusters WHERE cluster_type='LateralMovement'"
# Expected: rows with strengths, scores
pytest tests/test_lateral_movement.py
```

### D10 — Persistence + CredentialAccess constructors

**Builds:**
- `src/nighteye/constructors/persistence.py`
- `src/nighteye/constructors/credential_access.py`
- Fixtures + tests for both

**Operator test:** same shape as D9, for new types.

### D11 — RemoteExec + DefenseEvasion + Beaconing constructors

**Builds:** as above × 3.

### D12 — Collection + Exfiltration + Impact + 3 anti-forensic constructors

**Builds:**
- `collection.py`, `exfiltration.py`, `impact.py`
- `log_clearing.py`, `timestomp.py`, `shadow_deletion.py`
- Anti-forensic detectors register `evidence_disturbances` rows

**Operator test:**
```bash
nighteye constructors run --all
# Reports: clusters created per type, disturbances registered
sqlite3 ~/cases/test-*/graph.db "SELECT cluster_type, strength, COUNT(*) FROM clusters GROUP BY cluster_type, strength"
sqlite3 ~/cases/test-*/graph.db "SELECT * FROM evidence_disturbances"
```

### D13 — MCP server + core tools

**Builds:**
- `src/nighteye/mcp/server.py` — FastMCP setup, port 4509
- `src/nighteye/mcp/tools/triage.py`:
  - `triage_clusters`
  - `profile_host`
- `src/nighteye/mcp/tools/cluster.py`:
  - `query_clusters`
  - `expand_cluster`
- `src/nighteye/mcp/tools/canonical.py`:
  - `expand_canonical`
- `src/nighteye/mcp/tools/case.py`:
  - `case_status`, `evidence_register`
- Server instructions text

**Operator test:**
```bash
nighteye serve &
# In another terminal:
curl -X POST http://127.0.0.1:4509/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
# Expected: list of registered tools
# Connect Claude Code, point at http://127.0.0.1:4509/mcp
# Ask: "What clusters are in the case?"
# Expected: agent calls triage_clusters, returns results
```

### D14 — Hypothesis lifecycle + challenge_hypothesis + journal

**Builds:**
- `src/nighteye/mcp/tools/hypothesis.py`:
  - `record_hypothesis` with all 4 gates
  - `challenge_hypothesis` with conclusive verdict logic
  - `mark_insufficient`
  - `record_evidence_gap`
  - `establish_causation`
- `src/nighteye/mcp/tools/journal.py`:
  - `journal_resume`, `journal_decision`, `journal_checkpoint`,
    `journal_query`
- HMAC ledger writer for auto-approved hypotheses

**Operator test:**
```bash
# Via Claude Code:
# "Record a hypothesis based on cluster-001"
# "Challenge that hypothesis"
# Verify: hypothesis lands in DRAFT or APPROVED based on gates
sqlite3 ~/cases/test-*/graph.db "SELECT id, status, confidence_score, challenge_verdict FROM hypotheses"
ls /var/lib/nighteye/verification/
# Expected: HMAC ledger entries for APPROVED ones
```

### Week 2 deliverable

End-to-end: ingest → normalize → cluster → agent investigates → records
hypotheses with gates → challenges them → journal records decisions.
**Portal not yet built.**

---

## Week 3 — Portal + polish + demo + submission

### D15 — Portal scaffold + clusters/hypotheses pages

**Builds:**
- `src/nighteye/portal/app.py` — FastAPI app, port 4510
- `src/nighteye/portal/templates/base.html` — nav, CDN includes
- `src/nighteye/portal/templates/overview.html`
- `src/nighteye/portal/templates/clusters_list.html`
- `src/nighteye/portal/templates/cluster_detail.html`
- `src/nighteye/portal/templates/hypotheses_list.html`
- `src/nighteye/portal/templates/hypothesis_detail.html`
- Routes per PORTAL.md
- `nighteye serve` starts both MCP and portal

**Operator test:**
```bash
nighteye serve
# Open http://127.0.0.1:4510/ in browser
# Expected: case overview renders, clusters and hypotheses pages work,
#           drill-down to cluster detail works, hypothesis detail shows
#           confidence breakdown
```

### D16 — Portal: graph + timeline + journal + audit

**Builds:**
- `src/nighteye/portal/templates/graph.html` with Mermaid
- `src/nighteye/portal/templates/timeline.html`
- `src/nighteye/portal/templates/journal.html`
- `src/nighteye/portal/templates/audit.html`
- Server-side Mermaid generation from graph DB

**Operator test:** click through all pages, verify they render with
real case data.

### D17 — find_root_cause + end-of-case validation + report

**Builds:**
- `src/nighteye/correlation/root_cause.py`
- `src/nighteye/validation/end_of_case.py` — reconciliation pass
- `src/nighteye/report/markdown.py` — Markdown report generator
- `src/nighteye/report/json_export.py` — JSON form
- MCP tools: `find_root_cause`, `generate_report`, `save_report`

**Operator test:**
```bash
# Via Claude Code:
# "Find the root cause"
# "Generate the report"
ls ~/cases/test-*/reports/
# Open the markdown report
```

### D18 — SRL-2015 ingest + snapshot

**Activities:**
- Run full ingest on SRL-2015 (4 hosts)
- Tune any constructors that misfire on real data
- Capture OpenSearch snapshot via `_snapshot` API
- Tar + zstd the snapshot
- Document restore procedure

**Operator test:** run full Claude Code investigation against the
ingested case, see clusters, record hypotheses, challenge, generate
report. Identify any major issues.

### D19 — Synthetic test fixture + CI + accuracy report

**Builds:**
- `data/synthetic-test-case/` — 5MB seeded multi-host attack scenario
- CI workflow (`.github/workflows/test.yml`) that runs:
  - `pytest`
  - End-to-end ingest of synthetic fixture
  - Constructor expectations
  - Hypothesis lifecycle smoke test
- `docs/ACCURACY_REPORT.md` — comparison of NightEye output on SRL-2015
  vs published FOR508 walkthrough findings
  - True positives, false positives, false negatives
  - Hallucination examples (or absence thereof)
  - Coverage by MITRE tactic

### D20 — Demo video

**Activities:**
- Record 5-min screencast on SRL-2015
- Show: ingest progress → agent triages → records hypothesis →
  challenges and gets verdict (must include self-correction moment) →
  finds root cause → generates report → portal walkthrough
- Clean audio narration
- Upload to YouTube (unlisted) for Devpost link

### D21 — Submission + slippage buffer

**Activities:**
- Devpost form: project description, tech used, challenges, learnings
- Architecture diagram → polished version (export from Mermaid live editor)
- Try-It-Out instructions: 3 paths (Quick / BYO / Full)
- Final README pass
- Verify all submission deliverables present
- Submit

If slipping by D21: cut whichever Week 3 polish item is smallest, keep
demo and submission solid.

---

## Cuts under pressure (priority order, least essential first)

1. Linux artifact ingestion (only matters if judges pick Linux data)
2. capa (YARA covers most malware indicators)
3. Network/PCAP if no PCAP in demo dataset
4. Chainsaw (Hayabusa covers most of the same)
5. Portal `/timeline` page (graph + clusters list approximates)
6. Portal `/journal` page (fold into hypothesis detail)
7. Portal `/audit` page (CLI exposes `nighteye audit log`)
8. ImpactConstructor + ExfiltrationConstructor (lower-priority TTPs)
9. Branching investigation infrastructure (already deferred to v2)

## Cuts forbidden under any pressure

- Memory analysis (Vol3 + MemProcFS) — half the value of the platform
- All EZ Tools — these are the parsers, not optional
- KAPE-equivalent collection from E01 — required for raw-image input
- Hayabusa L1 detection
- Constructor framework with permissive triggers
- `challenge_hypothesis` with conclusive verdict
- Adaptive confidence engine
- Causation ladder enforcement
- HMAC ledger
- Portal pages: `/`, `/clusters`, `/clusters/{id}`, `/hypotheses`,
  `/hypotheses/{id}`, `/graph`

---

## Iterative test gates

After each week, the operator runs an end-to-end test on a Windows VM /
SIFT to verify the platform works as a whole, not just the latest piece:

| End of week | Test |
|---|---|
| W1 | `nighteye ingest <SRL-2015 single host>` produces indices in OS, hayabusa alerts present, no errors |
| W2 | Constructors run on canonical events, clusters table populated, agent via Claude Code can list and investigate clusters, hypotheses recorded with gates working |
| W3 | Full end-to-end demo run completes: ingest → cluster → investigate → challenge → root cause → report → portal walkthrough |

If a weekly gate fails, the next week's plan defers in favor of fixing
the regression.

---

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| EZ Tools .NET runtime issues on Linux | Fallback to running them inside a Wine container or .NET self-contained runtime; verified on D5 |
| OpenSearch performance at scale | Single-node Docker is sufficient up to ~100M docs; defer cluster setup to v2 |
| Constructor false positive rate too high | Counter-evidence weights tunable; CI fixtures catch regressions |
| LLM agent context exhaustion mid-investigation | Journal + checkpoint protocol; agent prompted to checkpoint at >75% context |
| Hayabusa rule update breaks reproducibility | Pin to specific commit at install, record version in audit |
| 3 weeks too tight | Cuts list above; W3 has slippage buffer |
