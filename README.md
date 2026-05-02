# NightEye

> Autonomous AI-driven Digital Forensics & Incident Response agent for the
> [SANS FindEvil! Hackathon 2026](https://findevil.devpost.com/). Triages
> incidents at the speed adversaries operate, with architectural constraints
> that block hallucinated findings and pre-computed clusters that let the
> agent reason over reduced evidence rather than raw event streams.

**Status:** all 8 layers scaffolded; full ingest → cluster → hypothesis → report
pipeline runs end-to-end on mock data.
**Test suite:** 368/374 passing (98.4%). 6 pre-existing trigger-name drift
failures in `test_additional_constructors.py`, `test_constructors.py`,
`test_persistence_evasion.py` — tests assert different trigger names/scores
than implementations expose. Tracked but non-blocking.
**Target submission:** June 15, 2026.
**Reference to exceed:** [Valhuntir](https://github.com/AppliedIR/Valhuntir).

## Recent audit + fixes (2026-05-02)

A deep architecture audit identified and resolved several red flags. Each
change preserves the contracts in `docs/ARCHITECTURE.md`:

| Red flag | Resolution |
|---|---|
| Test collection broken: `test_confidence.py` expected `FACTOR_MAX_WEIGHTS`, `HypothesisFactors`, `score_to_tier`; `test_mcp_tools.py` pulled in `fastmcp` via stub files | Refactored `confidence.py` to expose the cleaner `(profile, factors)` API; preserved old call sites via `compute_adaptive_confidence_from_db`. Deleted stub MCP tool files (`case.py`/`cluster.py`/`hypothesis.py`/`report.py`/`triage.py`/`canonical.py`/`journal.py`) and rewrote `test_mcp_tools.py` to test the real `*_tools.py` production modules. |
| Layer 6 (Persistent Investigation State) not wired into MCP server. `journal.py` stub returned hardcoded fake data. | New `src/nighteye/journal.py` does real CRUD against the SQLite `journal` table — `append_entry`, `query_entries`, `build_resume_digest`, `checkpoint`, `record_decision`. New `mcp/tools/journal_tools.py` exposes the four MCP tools (`journal_checkpoint`, `journal_record_decision`, `journal_query`, `journal_resume`). All four are now registered on the MCP server. |
| `correlation/root_cause.py` returned hardcoded "WKSTN-02 / T1078.002" mock data | Replaced with real implementation that walks APPROVED hypotheses backward via `causal_links`, picks strongest precursor at each step (CHAIN > WRITE > NET > TIGHT_TIME > CO_OCCUR > TEMPORAL_ONLY), and emits a MITRE-tagged kill chain. Notes the gap when no precursor link exists rather than fabricating one. |
| `validation/end_of_case.py` returned hardcoded "GAP-001 Missing VPN logs" mock | Replaced with real reconciliation: counts hypotheses by status, validates MITRE technique IDs, detects A→B/B→A causal contradictions, finds APPROVED-but-contradicted pairs, checks HMAC ledger coverage, surfaces unresolved blocking gaps. |
| Constructors created **one cluster per trigger event** instead of aggregating by host + time-window per `CONSTRUCTORS.md` § 1 | Rewrote `run_all_constructors`: events are bucketed by `(constructor, host, floor(timestamp/window))`. Multiple triggers within a bucket fold into a single cluster recording every trigger fired. Cluster ID keyed on bucket so re-runs are idempotent. |
| Cluster rows had empty `mitre_tactic` / `technique_ids` even though Constructor classes declare them | Cluster constructor now accepts these from the runner; `run_all_constructors` populates them from `Constructor.mitre_tactic` and `Constructor.mitre_techniques`. Anti-forensic counter check now matches actual constructor names (`LogClearing`/`Timestomp`/`ShadowDeletion`). |
| `mapper.py` used dotted strings as nested-dict keys (`doc.get("registry.value_data", "")`, `doc.get("rule.name", "")`) — never matched real ECS docs | Switched to nested object access with fallback to flattened-key form. |
| `_eval_target_not_previously_accessed` was hardcoded `return True` — every cluster got the +10 supporting bonus regardless of actual evidence | Replaced with a real check against same-user authentication history in the supplied context window. Conservative: returns False when in doubt rather than biasing the score upward. |

---

## What NightEye does

NightEye is a single-process MCP server that:

1. **Ingests broadly** — runs every relevant Eric Zimmerman parser, Hayabusa,
   Chainsaw, Volatility 3, MemProcFS, YARA, capa, and Zeek over a forensic
   case at ingest time, indexing everything into OpenSearch with ECS field
   mappings.
2. **Normalizes to canonical events** — a fixed event-type taxonomy
   (`PROCESS_EXECUTION`, `AUTHENTICATION`, `FILE_WRITE`, etc.) that
   constructors consume independent of source artifact.
3. **Builds behavior clusters at ingest** — 12 deterministic
   constructors (LateralMovement, Persistence, CredentialAccess,
   RemoteExecution, DefenseEvasion, Beaconing, Collection, Exfiltration,
   Impact, plus 6 anti-forensic) with permissive triggers and graded
   confidence. Hayabusa Sigma matches feed constructors as inputs, not as a
   parallel detection layer.
4. **Pre-computes counter-evidence per cluster** — every cluster carries
   refuting signals alongside supporting ones, so the agent's
   self-correction is a single read, not a parallel investigation.
5. **Drives a recursive AI investigation loop** — agent reads clusters,
   forms hypotheses, calls `challenge_hypothesis` for conclusive verdicts,
   builds a MITRE ATT&CK-aligned kill chain.
6. **Persists investigation state** — journal entries survive across
   Claude Code sessions; investigations resume after context exhaustion.
7. **Validates with adaptive deterministic confidence** — same factors
   evaluated everywhere, weights conditional on what's actually applicable
   to the case (single-host vs enterprise, anti-forensic observed vs not,
   intel sources configured vs not).
8. **Renders an explainability portal at localhost** — clusters,
   hypotheses, entity-relationship graph, timeline, journal. Functional,
   not pretty.

---

## Architecture at a glance

### Eight-layer stack

```mermaid
flowchart TB
    L1[Layer 1 - Wide Evidence Ingestion<br/>EZ Tools / KAPE-equivalent / Hayabusa /<br/>Chainsaw / Volatility 3 / MemProcFS / YARA /<br/>capa / Zeek]
    L2[Layer 2 - Canonical Evidence Store<br/>OpenSearch raw + canonical event indices<br/>Reversible reduction preserved]
    L3[Layer 3 - Entity & Relationship Graph<br/>SQLite / WAL mode<br/>Hosts, processes, files, users, network,<br/>registry, services, tasks]
    L4[Layer 4 - Deterministic Behavioral Clustering<br/>12 constructors with permissive triggers<br/>Counter-evidence pre-computed per cluster]
    L5[Layer 5 - Recursive AI Investigation<br/>Hypothesis ledger / challenge with verdict /<br/>causation ladder / evidence gap registry]
    L6[Layer 6 - Persistent Investigation State<br/>Journal / resume / no branching in v1]
    L7[Layer 7 - Validation and Confidence<br/>Adaptive deterministic scoring /<br/>per-hypothesis + end-of-case]
    L8[Layer 8 - Human Explainability Portal<br/>FastAPI + Jinja2 + Mermaid + HTMX<br/>localhost only]

    L1 --> L2 --> L3 --> L4 --> L5
    L5 --> L6
    L5 --> L7
    L5 --> L8
    L4 --> L8
    L3 --> L8
```

### Single MCP server, internal grouping

```mermaid
flowchart LR
    subgraph SIFT[SIFT Workstation - one VM]
        CC[Claude Code]
        NE[nighteye-mcp<br/>port 4509]
        PT[nighteye-portal<br/>port 4510]
        OS[(OpenSearch<br/>Docker / 9200)]
        SQ[(SQLite<br/>per case)]
        TOOLS[EZ Tools / Hayabusa /<br/>Chainsaw / Vol3 / MemProcFS /<br/>YARA / capa / Zeek]

        CC -->|MCP / HTTP| NE
        Browser -->|HTTP| PT
        NE --> OS
        NE --> SQ
        PT --> OS
        PT --> SQ
        NE --> TOOLS
    end
```

### Investigation flow

```mermaid
sequenceDiagram
    participant U as Operator
    participant N as nighteye-mcp
    participant OS as OpenSearch
    participant G as Evidence Graph
    participant J as Journal

    Note over N: ====== INGEST PHASE (no LLM) ======
    U->>N: nighteye ingest /evidence
    N->>N: parse with EZ Tools / Vol3 / etc.
    N->>OS: bulk index raw artifacts
    N->>N: run Hayabusa + Chainsaw
    N->>OS: index Sigma alerts
    N->>OS: write canonical events
    N->>N: run 12 constructors over canonical events
    N->>OS: write clusters + counter-evidence
    N->>G: write entities + edges

    Note over N: ====== INVESTIGATION PHASE ======
    participant A as Claude Code
    A->>N: triage_clusters()
    N->>OS: query clusters by strength
    N-->>A: top STRONG and MODERATE clusters

    loop Per cluster
        A->>N: expand_cluster(id)
        N-->>A: members + counter-evidence + contradicting clusters
        A->>N: record_hypothesis(...)
        N->>N: confidence + provenance + causation gates
        alt all gates pass
            N->>J: journal entry
            N-->>A: H-001 staged DRAFT
        else gates reject
            N-->>A: ERROR or INSUFFICIENT_EVIDENCE
        end
        A->>N: challenge_hypothesis(H-001)
        N-->>A: SUPPORTED | SUPPORTED_WITH_CAVEATS | REFUTED | DOWNGRADED
    end

    A->>N: find_root_cause()
    N->>G: walk graph backwards
    N-->>A: MITRE ATT&CK kill chain

    A->>N: generate_report()
    N-->>U: Markdown report + JSON + portal link
```

---

## Core design principles

1. **Ingest broadly, normalize, then reduce.** Cast a wide net at ingest
   (every relevant parser, every memory plugin). Normalize to canonical
   events. Cluster constructors run over canonical events. Reversible at
   every step.
2. **Architectural constraints, not prompt constraints.** Confidence
   scoring, causation verification, provenance tiers, anti-forensic
   propagation, and verdict requirements are enforced in code. The LLM
   cannot smuggle weak claims through.
3. **Permissive triggers, graded confidence.** Constructors fire on ANY
   recognized primitive of an attack class; cluster strength reflects the
   totality of supporting and counter signals. Single-trigger novel
   variants surface (with low strength); flooded-with-noise patterns are
   suppressed automatically.
4. **Counter-evidence pre-computed.** Self-correction is not a parallel
   investigation — every cluster carries refuting evidence already.
   `challenge_hypothesis` is a single-pass tool that returns a conclusive
   verdict.
5. **Adaptive deterministic confidence.** Same factors, weights
   conditional on what applies to the case. Single-host case with full
   corroboration can score HIGH; enterprise case that only checked one
   host gets penalized appropriately.
6. **Persistent investigation state.** Investigations survive context
   exhaustion. Journal records decisions, verdicts, and resume points.
7. **Reversible reduction.** Cluster → canonical events → raw artifact
   docs. Every layer expandable. No conclusion is opaque.
8. **The agent must commit.** `INSUFFICIENT_EVIDENCE` is allowed only
   when an evidence_gap is explicitly registered. The agent cannot
   indefinitely defer; it must reach a conclusion or document why it
   can't.

---

## Decision log

| Decision | Choice |
|---|---|
| Project name | NightEye |
| License | MIT |
| Language | Python 3.11+ |
| MCP framework | FastMCP |
| Server count | 1 MCP + 1 Portal (same process, different ports) |
| MCP port | 4509 |
| Portal port | 4510 |
| Transport | Streamable HTTP |
| VMs required | 1 (SIFT). Optional Windows helper deferred to v2 |
| Storage | OpenSearch (Docker) for events; SQLite (WAL) for graph + state |
| Field mapping | ECS v8.x |
| Index naming | `case-{id}-{artifact}-{host}` |
| Detection: L1 | Hayabusa + Chainsaw at ingest, fed into constructors |
| Detection: L4 | 12 behavior constructors (6 TTP + 6 anti-forensic) |
| Detection: L5 | Agent investigation with hypothesis ledger |
| Cluster matching | Permissive triggers (ANY one fires), graded confidence |
| Counter-evidence | Pre-computed at ingest per cluster |
| Self-correction | Single-pass `challenge_hypothesis` returning conclusive verdict |
| Confidence | Adaptive deterministic — factors fixed, weights conditional on case profile |
| Approval default | Auto-approve at strongest tier (HIGH + MCP provenance + clean + proven causation); else DRAFT |
| Causation ladder | 6 levels: CHAIN > WRITE > NET > TIGHT_TIME > CO_OCCUR > TEMPORAL_ONLY |
| Branching investigations | Deferred to v2 |
| Journal | Per-case, shared across sessions |
| Validation timing | Per-hypothesis (gates) + end-of-case (reconciliation) |
| Demo dataset | SRL-2015 primary; SRL-2018 scale benchmark |
| Snapshot delivery | OpenSearch snapshot tarball + 5MB synthetic test fixture |
| Install paths | Quick (snapshot) / BYO (judge data) / Full (raw E01 reingest) |
| KAPE | Replicate target list ourselves (Option 2, license-free path) |

---

## Documentation map

| Document | Purpose |
|---|---|
| **`README.md`** | Project overview, decisions, navigation (this file) |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Full architecture: 8-layer model, schemas, confidence engine, causation, OpenSearch design |
| [`docs/CONSTRUCTORS.md`](docs/CONSTRUCTORS.md) | All 12 constructor specs with permissive triggers, supporting/counter signals, scoring |
| [`docs/JOURNAL.md`](docs/JOURNAL.md) | Investigation journal schema and resume protocol |
| [`docs/PORTAL.md`](docs/PORTAL.md) | Localhost portal: pages, routes, stack |
| [`docs/BUILD_PLAN.md`](docs/BUILD_PLAN.md) | 3-week build schedule with iterative test points |

---
## Current build status

**Updated:** 2026-04-30

### ✅ Built (D1–D9)

| Module | File | Tests | Description |
|---|---|---|---|
| Package scaffold | `pyproject.toml`, `__init__.py` | `test_smoke.py` (7) | CLI entry point, version, dependencies |
| Data models | `models.py` (407 lines) | `test_models.py` (22) | Hypothesis, EvidenceGap, JournalEntry, ConfidenceBreakdown, all enums |
| SQLite layer | `db.py` (98 lines) | `test_db.py` (6) | WAL mode, foreign keys, transaction helper, retry logic |
| Schema | `schema/graph.sql` (252 lines) | `test_schema.py` (7) | 10 tables, 18 indexes, CHECK constraints |
| Audit log | `audit.py` (152 lines) | `test_audit.py` (16) | Sequential ID generation, record/query helpers |
| Identity | `identity.py` (102 lines) | `test_identity.py` (11) | Examiner resolution: flag → env → config → OS user |
| Case management | `case.py` (379 lines) | `test_case.py` (42) | Init, list, status, activate, close, reopen, delete |
| CLI | `cli.py` (315 lines) | `test_smoke.py` | Case subcommands live; ingest/normalize live |
| Confidence engine | `confidence.py` (290 lines) | `test_confidence.py` (35) | Adaptive scoring: 10 factors, 2 penalties, 4 tiers |
| Causation ladder | `causation.py` (115 lines) | `test_causation_provenance.py` (38) | 7-level causation weights, language detection |
| Provenance | `provenance.py` (120 lines) | `test_causation_provenance.py` | Weakest-link derivation from audit IDs |
| Evidence dispatch | `ingest/dispatch.py` (180 lines) | `test_ingest.py` (48) | 13 evidence types, directory scanning |
| ECS mapping | `ingest/ecs.py` (270 lines) | `test_ingest.py` | Index naming, doc IDs, timestamp normalization, doc builder |
| Index template | `ingest/index_template.py` (170 lines) | `test_ingest.py` | case-* template with ECS + NightEye fields |
| OpenSearch client | `ingest/opensearch_client.py` (530 lines) | — (integration) | Bulk indexer, shard breaker, scroll API, refresh mgmt, 50+ host scale |
| Orchestrator | `ingest/orchestrator.py` | `test_orchestrator.py` | Recursive discovery, KAPE host resolution, Ingest plans |
| EVTX Parser | `ingest/evtx.py` | `test_evtx.py` | EvtxECmd wrapper + python-evtx fallback, ECS mapping |
| EZ Tools Parsers | `ingest/parsers/*.py` | `test_parsers.py` | Registry, MFT, Prefetch, Amcache, Shimcache, SRUM to ECS |
| Ingest Executor | `ingest/executor.py` | `test_smoke.py` | Bulk streaming execution, auto-discovery routing |
| Hunt Automation | `ingest/hayabusa.py`, `chainsaw.py` | `test_hunt_parsers.py`| Native Sigma execution, JSON parsing to ECS alerts |
| Memory Ingestion| `ingest/volatility.py`, `memprocfs.py` | `test_memory_parsers.py` | Volatility 3 plugins & MemProcFS bulk extractions |
| Canonical Core | `canonical/types.py`, `mapper.py` | `test_smoke.py` | Post-ingest normalization of all raw ECS into CanonicalEvents |
| Constructor Base| `constructors/base.py`, `scoring.py` | `test_constructors.py` | Trigger, signal, counter-evidence framework + bounded tier math |
| Lateral Movement| `constructors/lateral_movement.py` | `test_constructors.py` | Complete T1021 TA0008 implementation with baseline checks |

**Total: 319 tests passing, 0 failures.**

### 🔲 Remaining (D10–D21)

| Day | Module | Status |
|---|---|---|
| D10-D12 | 11 remaining behavior constructors | 🔲 Next up |
| D13 | MCP server + core tools | 🔲 |
| D14 | Hypothesis lifecycle + journal | 🔲 |
| D15-D16 | Explainability portal | 🔲 |
| D17 | Root cause + report generation | 🔲 |
| D18 | SRL-2015 full ingest + snapshot | 🔲 |
| D19 | Synthetic test fixture + CI + accuracy report | 🔲 |
| D20-D21 | Demo video + submission | 🔲 |

---

## Data ingestion: SRL-2015 and SRL-2018

The primary demonstration dataset is the **SANS SRL APT 2015** (4 hosts)
with **SRL-2018** (13 hosts) as the scale benchmark.

### For the developer (you)

1. **Download the E01 images** from the SANS course materials or the
   publicly available links to your **external hard disk** or local
   storage. Each host produces 1-2 E01 files (split images), totaling
   ~15-50 GB per host.
2. **Mount the external disk** to your SIFT VM (USB passthrough in
   VirtualBox/VMware, or shared folder).
3. **Run ingest** pointing NightEye at the mounted evidence:
   ```bash
   nighteye case init "SRL-2015 Investigation"
   nighteye ingest /mnt/evidence/SRL-2015/ --host DC01
   nighteye ingest /mnt/evidence/SRL-2015/ --host RD-01
   # ... per host
   ```
4. NightEye mounts E01s via `ewfmount`, extracts artifacts via its
   KAPE-equivalent script, parses with EZ Tools, runs Hayabusa, and
   indexes everything into OpenSearch. First-time ingest: **4-8 hours**
   for SRL-2015 (4 hosts).
5. After ingest, capture an **OpenSearch snapshot** for reuse:
   ```bash
   nighteye snapshot create --output /mnt/evidence/snapshots/srl-2015.tar.zst
   ```

### For the judges (three install paths)

NightEye provides three ways for judges to evaluate:

| Path | Time | What's needed |
|---|---|---|
| **Quick (recommended)** | ~10 min | Restore the pre-built OpenSearch snapshot. No E01s, no external disk. Just `nighteye snapshot restore srl-2015.tar.zst` and the case is ready. |
| **BYO (bring your own data)** | ~1 hour | Judges point NightEye at their own triage data (KAPE zips, EVTX folders, memory dumps). Works from local disk or USB. |
| **Full (raw E01 reingest)** | ~4-8 hours | Judges download SRL-2015 E01s to their disk (external or internal), mount in SIFT VM, run `nighteye ingest`. Full reproducibility. |

**Key points:**
- The **Quick path** does NOT require an external hard disk. The
  snapshot tarball (~2-5 GB compressed) ships with the submission or is
  downloaded from a release URL.
- The **Full path** requires ~50-100 GB of disk space for the raw
  images. An external hard disk is convenient but not mandatory — any
  accessible storage works (internal SSD, NFS mount, shared folder).
- All three paths produce identical investigation-ready cases. The
  agent's investigation is deterministic regardless of ingest method.

---

## Hackathon submission deliverables

| Deliverable | Status |
|---|---|
| Public repo (MIT) | ✅ initialized |
| Demo video (5 min, with self-correction) | 🔲 post-build |
| Architecture diagram | ✅ this README + ARCHITECTURE.md |
| Project description (Devpost) | 🔲 post-build |
| Dataset documentation | 🔲 post-build |
| Accuracy report | 🔲 post-build (FOR508 ground-truth comparison on SRL-2015) |
| Try-It-Out instructions (3 paths) | ✅ documented above |
| Agent execution logs | 🔲 auto-captured by audit subsystem |

---

## Quick start (will fill in as build progresses)

```bash
# Install (after D1 of build plan)
git clone https://github.com/<user>/nighteye.git
cd nighteye
pip install -e ".[dev]"

# Initialize a case
nighteye case init "FOR508 lab investigation"

# Ingest evidence (E01s, KAPE-extracted triage zips, raw EVTX folders)
nighteye ingest /path/to/evidence

# Start MCP server + portal
nighteye serve

# Connect Claude Code to http://127.0.0.1:4509/mcp
# Open http://127.0.0.1:4510/ for the portal
```

---

## Handoff to next agent

If you're an LLM or human picking this up cold, read in order:

1. **`README.md`** (this file) — overview and decisions.
2. **`docs/ARCHITECTURE.md`** — full technical architecture.
3. **`docs/CONSTRUCTORS.md`** — cluster specifications.
4. **`docs/JOURNAL.md`** — persistent state design.
5. **`docs/PORTAL.md`** — explainability output.
6. **`docs/BUILD_PLAN.md`** — what to build, in what order, with test points.
7. **The hackathon brief** — https://findevil.devpost.com/ (read Rules tab and Resources tab).
8. **Reference codebase** — Valhuntir at `C:/Users/shivang/OneDrive/Desktop/Valhuntir/`. Read its `README.md` and `docs/architecture.md` to understand what NightEye improves over.

### Critical context for the next agent

- **The brief rewards autonomous execution, architectural constraints, audit traceability, and depth.**
  Do not pad with shallow coverage. 12 well-implemented constructors beat 30 stubs.
- **Permissive triggers, graded confidence.** A single trigger fires a
  cluster with low confidence. Multiple triggers + supporting signals
  raise confidence. Counter signals lower it. This is non-negotiable.
- **Single-pass verdict on `challenge_hypothesis`.** The agent cannot use
  INSUFFICIENT_EVIDENCE as a cop-out — it must register an evidence_gap
  to use that status.
- **Reversible reduction at every layer.** Cluster expands to canonical
  events; canonical events expand to raw artifact docs. No black boxes.
- **All decisions have rationale documented.** If you change a decision,
  update `docs/ARCHITECTURE.md` § "Decision log" in the same commit.
- **Iterative build.** Each chunk of `BUILD_PLAN.md` should be testable
  by the operator on a Windows VM / SIFT before the next chunk starts.

---

## Troubleshooting & Bug Log

Below are common issues encountered during the NightEye build and deployment, along with their solutions.

| Issue | Symptom | Solution |
|---|---|---|
| **OpenSearch Missing** | `systemctl start opensearch` fails with `Unit not found` | Run `sudo docker compose up -d`. NightEye now includes a `docker-compose.yml` for easy infrastructure setup. |
| **Docker Permissions** | `permission denied` connecting to `docker.sock` | Run docker commands with `sudo` (e.g., `sudo docker compose up -d`). |
| **Scanning Slowness** | `nighteye ingest` hangs at "Scanning..." on external HDDs | Use the new `--no-recurse` flag. We also implemented "Smart Recursion" which automatically ignores the flag for extracted ZIP data so it still finds the evidence inside. |
| **No Evidence Found** | `No supported evidence files found` after unzipping | Fixed via "Smart Recursion": The system now knows to always look deep into internal extraction folders even if `--no-recurse` is set for the main drive. |
| **Index Not Found** | `execute_ingest_plan` fails with `404 index_not_found_exception` | We updated the OpenSearch client to gracefully ignore refresh-interval optimizations if the index hasn't been created yet. |
| **Missing EZ Tools** | `Required EZ Tool not found` on SIFT | Updated tool discovery to support SIFT-style shell scripts and `/usr/local/bin` paths. Added fallback to Python-native parsers. |
| **Incorrect Client Args** | `TypeError: NightEyeOSClient.__init__() got unexpected keyword argument 'host'` | Always instantiate the client using the `OSConfig` object: `client = NightEyeOSClient(OSConfig(url="..."))`. |

---

## License

MIT. See `LICENSE` once repo is initialized.

## Contact

Solo build by Shivang Patel (<shivang092003@gmail.com>) for the SANS FindEvil! Hackathon 2026.
