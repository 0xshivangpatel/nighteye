# NightEye — Investigation Journal

The journal solves three problems:

1. **Context window exhaustion.** Long enterprise investigations exceed
   the LLM's context window. Without external memory, the agent forgets
   what it did. The journal is the externalized memory.
2. **Session resumption.** Operator closes Claude Code. Re-opens it
   tomorrow. Agent needs to know where to pick up.
3. **Audit traceability.** Every significant decision the agent made,
   recorded with reasoning, queryable by the portal.

The journal is not a chat history. It is a structured record of
**decisions** — moments where the agent committed to something
(a hypothesis, a verdict, a path of investigation, a checkpoint
summary).

---

## Schema

Stored in SQLite `journal` table (defined in `ARCHITECTURE.md` § 7).

```python
@dataclass
class JournalEntry:
    entry_id:          str                 # J-{examiner}-{nnn}
    case_id:           str
    investigation_id:  str = "main"        # branching reserved for v2
    timestamp:         datetime
    entry_type:        EntryType
    summary:           str                 # 1-line for resume digest
    details:           dict                # entry-type-specific JSON
    agent_session_id:  Optional[str]       # session that wrote it
    supersedes:        Optional[str]       # entry_id this overrides
```

### EntryType enum

| Type | When written | `details` contents |
|---|---|---|
| `SESSION_START` | Agent begins a session | start time, prior session digest read |
| `SESSION_END` | Agent declares stopping point | summary of what was done, what's next |
| `CLUSTER_INVESTIGATED` | Agent reads + acts on a cluster | cluster_id, action taken |
| `HYPOTHESIS_RECORDED` | `record_hypothesis` succeeded | hypothesis_id, score, tier |
| `HYPOTHESIS_CHALLENGED` | `challenge_hypothesis` returned a verdict | hypothesis_id, verdict, reasoning |
| `EVIDENCE_GAP_REGISTERED` | `record_evidence_gap` called | gap_id, blocks_hypothesis, what_resolves |
| `CAUSATION_ESTABLISHED` | `establish_causation` proved a link | from_id, to_id, level, proof_edges |
| `ROOT_CAUSE_ATTEMPTED` | `find_root_cause` ran | found, chain, gaps |
| `INVESTIGATION_DECISION` | Agent's free-form reasoning at a checkpoint | text, hypotheses_considered |
| `CHECKPOINT_SUMMARY` | Agent emits state digest | hypotheses by status, open gaps, next steps |
| `RESUME_DIGEST_READ` | Agent reads journal at session start | last_entry_id, entries_read |

### Why this granularity

- `SESSION_START` and `RESUME_DIGEST_READ` make resumption explicit.
- `CHECKPOINT_SUMMARY` is the agent's own state compaction — when a
  cluster is fully investigated, the agent writes a 1-paragraph summary
  the next session can read instead of replaying every tool call.
- `INVESTIGATION_DECISION` captures reasoning that doesn't fit other
  types (e.g., "I'm pivoting from credential access to lateral movement
  because the kerberoasting hits suggest service-account abuse").

---

## Resume protocol

### Session start

```python
# Agent calls this as its first tool in any session
def journal_resume(case_id: str, since: Optional[str] = None) -> ResumeDigest:
    """
    Returns a compact digest the agent can fit in its context to
    re-orient.

    If `since` not provided, defaults to last SESSION_END entry's
    timestamp (or case start if no prior session).
    """
```

`ResumeDigest` shape:

```python
{
    "case": {"id": "INC-2026-001", "name": "FOR508 lab", "examiner": "shivang"},
    "prior_sessions": 3,
    "last_session_end": {
        "timestamp": "2026-04-29T18:00:00Z",
        "summary": "Investigated lateral movement clusters on RD-01 and DC01. Recorded H-shivang-005 (lateral via PsExec). Open: credential access on DC01."
    },
    "current_state": {
        "hypotheses": {
            "DRAFT": 3,
            "INSUFFICIENT_EVIDENCE": 1,
            "APPROVED": 5,
            "REJECTED": 1
        },
        "evidence_gaps_open": 2,
        "clusters_investigated": 8,
        "clusters_remaining_strong": 4,
        "clusters_remaining_moderate": 11
    },
    "key_recent_findings": [
        {"id": "H-shivang-005", "title": "Lateral movement WKSTN-01 -> RD-01 via PsExec",
         "tier": "HIGH", "approved_at": "2026-04-29T17:42:00Z"},
        # ... up to 5 most recent APPROVED
    ],
    "open_gaps": [
        {"id": "G-shivang-002", "question": "Did the actor exfiltrate data?",
         "what_would_resolve": "Network telemetry from gateway between 14:00-18:00"}
    ],
    "next_suggested_actions": [
        # Pulled from last SESSION_END.details.next_steps if present
        "Investigate credential access cluster CA-003 on DC01",
        "Run find_c2_beacons on full case window"
    ]
}
```

### Session end

```python
def journal_checkpoint(case_id: str, summary: str, next_steps: list[str]) -> None:
    """
    Agent should call this before a session ends or before context
    becomes exhausted (>75% full). Writes a CHECKPOINT_SUMMARY entry.
    """
```

This is the agent's own self-managed state compaction.

---

## How tools write to the journal

Most journal writes are automatic — every successful `record_hypothesis`,
`challenge_hypothesis`, `record_evidence_gap`, `establish_causation`,
`find_root_cause` writes its own journal entry as a side effect.

Two are agent-explicit:

- `journal_decision(text, hypotheses_considered)` — agent records its
  free-form reasoning at decision points
- `journal_checkpoint(summary, next_steps)` — agent compacts state

The agent should be prompted (via server instructions at session init)
to call `journal_checkpoint` before its context runs out.

---

## Querying the journal

```python
def journal_query(
    case_id: str,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    entry_types: Optional[list[EntryType]] = None,
    limit: int = 100
) -> list[JournalEntry]
```

Used by:

- `journal_resume` — internally builds digest
- Portal `/journal` page — full chronological view
- `generate_report` — pulls `INVESTIGATION_DECISION` entries for
  the "analyst reasoning" section of the final report

---

## Branching investigations (v2, deferred)

The schema supports `investigation_id` for branching but v1 always uses
`"main"`. Branching adds:

- Fork a new investigation from a cluster or hypothesis
- Run parallel hypothesis chains
- Merge or discard branches at end
- Resolve hypothesis conflicts across branches

Useful for "what if X happened first vs Y" analysis. Not in v1 scope.

---

## What journal does NOT replace

- **Audit log** — every tool invocation is logged to `audit` table
  regardless. Journal is for *significant decisions*; audit is for
  *every action*.
- **Hypothesis ledger** — hypotheses live in their own table with
  full state machine.
- **HMAC ledger** — cryptographic integrity is separate.

The journal is **narrative state**: what the agent decided and why,
fit for resume and report generation.
