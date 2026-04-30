-- NightEye Evidence Graph + investigation state schema.
--
-- Per-case SQLite database. WAL mode enabled by the connection helper.
-- All schema mutations must come through schema_version bumps.
--
-- See docs/ARCHITECTURE.md sec 7 for the design rationale and
-- canonical_key rules per entity type.

PRAGMA foreign_keys = ON;

-- ============================================================
-- schema_version: tracks migrations
-- ============================================================
CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL
);

-- ============================================================
-- entities: graph nodes (host / process / file / user / ...)
-- ============================================================
CREATE TABLE IF NOT EXISTS entities (
    entity_id          TEXT PRIMARY KEY,
    entity_type        TEXT NOT NULL,
    case_id            TEXT NOT NULL,
    canonical_key      TEXT NOT NULL,
    properties         TEXT NOT NULL,            -- JSON, type-specific
    first_seen         TEXT NOT NULL,            -- ISO 8601 UTC
    last_seen          TEXT NOT NULL,
    seen_count         INTEGER NOT NULL DEFAULT 1,
    evidence_disturbed INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL,
    CHECK (entity_type IN (
        'host', 'process', 'file', 'user',
        'network', 'registry', 'service', 'task'
    ))
);
CREATE INDEX IF NOT EXISTS idx_entities_case_type
    ON entities(case_id, entity_type);
CREATE INDEX IF NOT EXISTS idx_entities_canonical
    ON entities(case_id, canonical_key);
CREATE INDEX IF NOT EXISTS idx_entities_lastseen
    ON entities(last_seen);

-- ============================================================
-- edges: typed relationships between entities
-- ============================================================
CREATE TABLE IF NOT EXISTS edges (
    edge_id          TEXT PRIMARY KEY,
    from_entity      TEXT NOT NULL,
    to_entity        TEXT NOT NULL,
    edge_type        TEXT NOT NULL,
    case_id          TEXT NOT NULL,
    timestamp        TEXT NOT NULL,
    properties       TEXT,                       -- JSON, edge-specific
    source_audit_id  TEXT NOT NULL,
    confidence_basis TEXT NOT NULL,              -- mcp|hook|shell|parsed_artifact
    created_at       TEXT NOT NULL,
    CHECK (edge_type IN (
        'spawned_by', 'wrote', 'connected_to', 'authenticated_as',
        'persists_via', 'modified', 'loaded', 'accessed', 'signed_by'
    )),
    FOREIGN KEY (from_entity) REFERENCES entities(entity_id),
    FOREIGN KEY (to_entity)   REFERENCES entities(entity_id)
);
CREATE INDEX IF NOT EXISTS idx_edges_from
    ON edges(from_entity, edge_type);
CREATE INDEX IF NOT EXISTS idx_edges_to
    ON edges(to_entity, edge_type);
CREATE INDEX IF NOT EXISTS idx_edges_timestamp
    ON edges(timestamp);
CREATE INDEX IF NOT EXISTS idx_edges_case_type
    ON edges(case_id, edge_type);

-- ============================================================
-- evidence_disturbances: anti-forensic windows
-- ============================================================
CREATE TABLE IF NOT EXISTS evidence_disturbances (
    disturbance_id    TEXT PRIMARY KEY,
    case_id           TEXT NOT NULL,
    host              TEXT NOT NULL,
    window_start      TEXT NOT NULL,
    window_end        TEXT NOT NULL,
    disturbance_type  TEXT NOT NULL,
    detected_by       TEXT NOT NULL,
    source_audit_id   TEXT NOT NULL,
    details           TEXT,                      -- JSON
    created_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_disturbances_host_time
    ON evidence_disturbances(host, window_start, window_end);

-- ============================================================
-- case_capabilities: case profile, set at ingest completion
-- ============================================================
CREATE TABLE IF NOT EXISTS case_capabilities (
    case_id                 TEXT PRIMARY KEY,
    host_count              INTEGER NOT NULL,
    artifact_types          TEXT NOT NULL,        -- JSON array
    has_memory              INTEGER NOT NULL,
    has_network             INTEGER NOT NULL,
    has_intel_source        INTEGER NOT NULL,
    anti_forensic_observed  INTEGER NOT NULL DEFAULT 0,
    time_window_hours       INTEGER,
    profiled_at             TEXT NOT NULL
);

-- ============================================================
-- clusters: behavioral neighborhoods produced by constructors
-- ============================================================
CREATE TABLE IF NOT EXISTS clusters (
    cluster_id              TEXT PRIMARY KEY,
    case_id                 TEXT NOT NULL,
    cluster_type            TEXT NOT NULL,
    strength                TEXT NOT NULL,        -- STRONG|MODERATE|WEAK|NOISE
    score                   INTEGER NOT NULL,
    triggers_fired          TEXT NOT NULL,        -- JSON
    supporting_signals      TEXT NOT NULL,        -- JSON
    counter_signals         TEXT NOT NULL,        -- JSON
    counter_evidence_details TEXT,                -- JSON
    contradicting_clusters  TEXT,                 -- JSON
    member_canonical_ids    TEXT NOT NULL,        -- JSON
    primary_host            TEXT,
    primary_user            TEXT,
    secondary_hosts         TEXT,                 -- JSON
    time_start              TEXT NOT NULL,
    time_end                TEXT NOT NULL,
    technique_ids           TEXT,                 -- JSON
    mitre_tactic            TEXT,
    summary                 TEXT NOT NULL,
    created_at              TEXT NOT NULL,
    CHECK (strength IN ('STRONG', 'MODERATE', 'WEAK', 'NOISE'))
);
CREATE INDEX IF NOT EXISTS idx_clusters_case_strength
    ON clusters(case_id, strength);
CREATE INDEX IF NOT EXISTS idx_clusters_type
    ON clusters(case_id, cluster_type);
CREATE INDEX IF NOT EXISTS idx_clusters_time
    ON clusters(time_start, time_end);

-- ============================================================
-- hypotheses: agent-staged investigative claims
-- ============================================================
CREATE TABLE IF NOT EXISTS hypotheses (
    hypothesis_id          TEXT PRIMARY KEY,
    case_id                TEXT NOT NULL,
    examiner               TEXT NOT NULL,
    title                  TEXT NOT NULL,
    observation            TEXT NOT NULL,
    interpretation         TEXT NOT NULL,
    technique_ids          TEXT NOT NULL,        -- JSON
    status                 TEXT NOT NULL,
    staged_at              TEXT NOT NULL,
    modified_at            TEXT NOT NULL,
    approved_at            TEXT,
    approved_by            TEXT,
    rejected_at            TEXT,
    rejected_by            TEXT,
    rejection_reason       TEXT,
    contradicted_by        TEXT,
    evidence_refs          TEXT NOT NULL,        -- JSON
    audit_ids              TEXT NOT NULL,        -- JSON
    confidence_score       INTEGER NOT NULL,
    confidence_tier        TEXT NOT NULL,
    confidence_breakdown   TEXT NOT NULL,        -- JSON
    provenance_tier        TEXT NOT NULL,
    causal_links           TEXT,                 -- JSON
    suggested_by_cluster   TEXT,
    content_hash           TEXT NOT NULL,
    hmac_signature         TEXT,
    challenged_at          TEXT,
    challenge_verdict      TEXT,
    challenge_reasoning    TEXT,
    CHECK (status IN (
        'DRAFT', 'INSUFFICIENT_EVIDENCE', 'APPROVED',
        'REJECTED', 'CONTRADICTED', 'DOWNGRADED'
    )),
    CHECK (confidence_tier IN ('HIGH', 'MEDIUM', 'LOW', 'SPECULATIVE')),
    CHECK (provenance_tier IN ('MCP', 'HOOK', 'SHELL', 'NONE'))
);
CREATE INDEX IF NOT EXISTS idx_hypotheses_case_status
    ON hypotheses(case_id, status);
CREATE INDEX IF NOT EXISTS idx_hypotheses_cluster
    ON hypotheses(suggested_by_cluster);

-- ============================================================
-- evidence_gaps: registered unknowns
-- ============================================================
CREATE TABLE IF NOT EXISTS evidence_gaps (
    gap_id              TEXT PRIMARY KEY,
    case_id             TEXT NOT NULL,
    question            TEXT NOT NULL,
    what_would_resolve  TEXT NOT NULL,
    blocks_hypothesis   TEXT,
    blocks_report       INTEGER NOT NULL DEFAULT 0,
    registered_at       TEXT NOT NULL,
    registered_by       TEXT NOT NULL,
    resolved_at         TEXT,
    resolution          TEXT
);
CREATE INDEX IF NOT EXISTS idx_gaps_case_blocks
    ON evidence_gaps(case_id, blocks_hypothesis);

-- ============================================================
-- journal: persistent investigation state, see docs/JOURNAL.md
-- ============================================================
CREATE TABLE IF NOT EXISTS journal (
    entry_id          TEXT PRIMARY KEY,
    case_id           TEXT NOT NULL,
    investigation_id  TEXT NOT NULL DEFAULT 'main',
    timestamp         TEXT NOT NULL,
    entry_type        TEXT NOT NULL,
    summary           TEXT NOT NULL,
    details           TEXT,                       -- JSON
    agent_session_id  TEXT,
    supersedes        TEXT,
    CHECK (entry_type IN (
        'SESSION_START', 'SESSION_END',
        'CLUSTER_INVESTIGATED', 'HYPOTHESIS_RECORDED',
        'HYPOTHESIS_CHALLENGED', 'EVIDENCE_GAP_REGISTERED',
        'CAUSATION_ESTABLISHED', 'ROOT_CAUSE_ATTEMPTED',
        'INVESTIGATION_DECISION', 'CHECKPOINT_SUMMARY',
        'RESUME_DIGEST_READ'
    ))
);
CREATE INDEX IF NOT EXISTS idx_journal_case_time
    ON journal(case_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_journal_type
    ON journal(case_id, entry_type);

-- ============================================================
-- audit: per-tool execution log
-- ============================================================
CREATE TABLE IF NOT EXISTS audit (
    audit_id        TEXT PRIMARY KEY,
    case_id         TEXT NOT NULL,
    tool_group      TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    parameters      TEXT NOT NULL,                -- JSON
    result_summary  TEXT NOT NULL,                -- JSON
    duration_ms     INTEGER NOT NULL,
    queries_run     TEXT,                         -- JSON
    examiner        TEXT NOT NULL,
    timestamp       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_case_tool
    ON audit(case_id, tool_name);
CREATE INDEX IF NOT EXISTS idx_audit_time
    ON audit(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_examiner_date
    ON audit(examiner, timestamp);
