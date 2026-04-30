"""Tests for the SQLite schema initialization."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from nighteye.schema import (
    CURRENT_SCHEMA_VERSION,
    init_schema,
    init_schema_at_path,
    schema_version,
)

EXPECTED_TABLES = {
    "schema_version",
    "entities",
    "edges",
    "evidence_disturbances",
    "case_capabilities",
    "clusters",
    "hypotheses",
    "evidence_gaps",
    "journal",
    "audit",
}

EXPECTED_INDEXES = {
    "idx_entities_case_type",
    "idx_entities_canonical",
    "idx_entities_lastseen",
    "idx_edges_from",
    "idx_edges_to",
    "idx_edges_timestamp",
    "idx_edges_case_type",
    "idx_disturbances_host_time",
    "idx_clusters_case_strength",
    "idx_clusters_type",
    "idx_clusters_time",
    "idx_hypotheses_case_status",
    "idx_hypotheses_cluster",
    "idx_gaps_case_blocks",
    "idx_journal_case_time",
    "idx_journal_type",
    "idx_audit_case_tool",
    "idx_audit_time",
    "idx_audit_examiner_date",
}


def _list_tables(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    return {r[0] for r in rows}


def _list_indexes(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return {r[0] for r in rows}


def test_init_schema_creates_all_tables(tmp_path: Path) -> None:
    db = tmp_path / "graph.db"
    conn = sqlite3.connect(str(db))
    try:
        version = init_schema(conn)
        assert version == CURRENT_SCHEMA_VERSION
        tables = _list_tables(conn)
        assert EXPECTED_TABLES.issubset(tables), (
            f"missing tables: {EXPECTED_TABLES - tables}"
        )
    finally:
        conn.close()


def test_init_schema_creates_all_indexes(tmp_path: Path) -> None:
    db = tmp_path / "graph.db"
    conn = sqlite3.connect(str(db))
    try:
        init_schema(conn)
        indexes = _list_indexes(conn)
        assert EXPECTED_INDEXES.issubset(indexes), (
            f"missing indexes: {EXPECTED_INDEXES - indexes}"
        )
    finally:
        conn.close()


def test_init_schema_is_idempotent(tmp_path: Path) -> None:
    """Running init_schema twice must not raise or duplicate version rows."""
    db = tmp_path / "graph.db"
    conn = sqlite3.connect(str(db))
    try:
        v1 = init_schema(conn)
        v2 = init_schema(conn)
        assert v1 == v2 == CURRENT_SCHEMA_VERSION
        rows = conn.execute(
            "SELECT COUNT(*) FROM schema_version"
        ).fetchone()
        assert rows[0] == 1
    finally:
        conn.close()


def test_schema_version_returns_none_for_uninitialized_db(tmp_path: Path) -> None:
    db = tmp_path / "empty.db"
    conn = sqlite3.connect(str(db))
    try:
        assert schema_version(conn) is None
    finally:
        conn.close()


def test_init_schema_at_path_creates_parent_dirs(tmp_path: Path) -> None:
    db = tmp_path / "nested" / "dir" / "graph.db"
    version = init_schema_at_path(db)
    assert db.exists()
    assert version == CURRENT_SCHEMA_VERSION


def test_check_constraint_entity_type(tmp_path: Path) -> None:
    """The entities.entity_type CHECK constraint must reject unknown types."""
    db = tmp_path / "graph.db"
    conn = sqlite3.connect(str(db))
    try:
        init_schema(conn)
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO entities (
                    entity_id, entity_type, case_id, canonical_key,
                    properties, first_seen, last_seen, created_at
                ) VALUES (?, 'NOT_A_TYPE', ?, ?, '{}', '2026-01-01', '2026-01-01', '2026-01-01')
                """,
                ("test-id", "case-1", "key"),
            )
    finally:
        conn.close()


def test_check_constraint_hypothesis_status(tmp_path: Path) -> None:
    db = tmp_path / "graph.db"
    conn = sqlite3.connect(str(db))
    try:
        init_schema(conn)
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO hypotheses (
                    hypothesis_id, case_id, examiner, title, observation,
                    interpretation, technique_ids, status, staged_at,
                    modified_at, evidence_refs, audit_ids,
                    confidence_score, confidence_tier, confidence_breakdown,
                    provenance_tier, content_hash
                ) VALUES (?, ?, ?, ?, ?, ?, '[]', 'BOGUS', ?, ?, '[]', '[]',
                          0, 'HIGH', '{}', 'MCP', 'h')
                """,
                (
                    "H-1", "case-1", "examiner", "title",
                    "obs", "interp", "2026-01-01", "2026-01-01",
                ),
            )
    finally:
        conn.close()
