"""Tests for the audit log helper (nighteye.audit)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from nighteye.audit import (
    is_valid_audit_id,
    next_audit_id,
    query_audit,
    record_audit,
    utc_now_iso,
    utc_now_yyyymmdd,
)
from nighteye.db import connect
from nighteye.schema import init_schema


@pytest.fixture
def audit_db(tmp_path: Path) -> sqlite3.Connection:
    """Create a fresh in-memory-like DB with schema for audit tests."""
    db = tmp_path / "graph.db"
    conn = connect(db)
    init_schema(conn)
    return conn


# ============================================================
# ID format validation
# ============================================================


def test_is_valid_audit_id_accepts_canonical() -> None:
    assert is_valid_audit_id("nighteye-alice-20260429-001")
    assert is_valid_audit_id("nighteye-alice-20260429-999")
    assert is_valid_audit_id("ne-bob-20260101-1234")  # >3 digit seq


def test_is_valid_audit_id_rejects_bad_format() -> None:
    assert not is_valid_audit_id("")
    assert not is_valid_audit_id("NIGHTEYE-alice-20260429-001")  # uppercase
    assert not is_valid_audit_id("nighteye-alice-20260429")      # missing seq
    assert not is_valid_audit_id("nighteye_alice_20260429_001")  # underscores
    assert not is_valid_audit_id("nighteye-alice-2026042-001")   # short date


# ============================================================
# Timestamp helpers
# ============================================================


def test_utc_now_iso_returns_iso_format() -> None:
    ts = utc_now_iso()
    assert "T" in ts
    assert "+" in ts or "Z" in ts  # timezone info present


def test_utc_now_yyyymmdd_returns_date_string() -> None:
    d = utc_now_yyyymmdd()
    assert len(d) == 8
    assert d.isdigit()


# ============================================================
# next_audit_id
# ============================================================


def test_next_audit_id_starts_at_001(audit_db: sqlite3.Connection) -> None:
    aid = next_audit_id(audit_db, "alice", date="20260429")
    assert aid == "nighteye-alice-20260429-001"


def test_next_audit_id_increments(audit_db: sqlite3.Connection) -> None:
    # Seed an existing audit row
    record_audit(
        audit_db,
        case_id="case-1",
        tool_group="test",
        tool_name="test_tool",
        parameters={},
        result_summary={},
        duration_ms=10,
        examiner="alice",
        audit_id="nighteye-alice-20260429-003",
        timestamp="2026-04-29T12:00:00+00:00",
    )
    audit_db.commit()
    aid = next_audit_id(audit_db, "alice", date="20260429")
    assert aid == "nighteye-alice-20260429-004"


def test_next_audit_id_per_examiner(audit_db: sqlite3.Connection) -> None:
    """Different examiners have independent sequences."""
    record_audit(
        audit_db,
        case_id="case-1",
        tool_group="test",
        tool_name="t",
        parameters={},
        result_summary={},
        duration_ms=10,
        examiner="alice",
        audit_id="nighteye-alice-20260429-005",
        timestamp="2026-04-29T12:00:00+00:00",
    )
    audit_db.commit()
    bob_id = next_audit_id(audit_db, "bob", date="20260429")
    assert bob_id == "nighteye-bob-20260429-001"


def test_next_audit_id_per_date(audit_db: sqlite3.Connection) -> None:
    """New date resets the sequence."""
    record_audit(
        audit_db,
        case_id="case-1",
        tool_group="test",
        tool_name="t",
        parameters={},
        result_summary={},
        duration_ms=10,
        examiner="alice",
        audit_id="nighteye-alice-20260429-010",
        timestamp="2026-04-29T12:00:00+00:00",
    )
    audit_db.commit()
    new_day = next_audit_id(audit_db, "alice", date="20260430")
    assert new_day == "nighteye-alice-20260430-001"


# ============================================================
# record_audit
# ============================================================


def test_record_audit_writes_row(audit_db: sqlite3.Connection) -> None:
    aid = record_audit(
        audit_db,
        case_id="INC-001",
        tool_group="triage",
        tool_name="triage_clusters",
        parameters={"min_strength": "MODERATE"},
        result_summary={"cluster_count": 5},
        duration_ms=123,
        examiner="alice",
    )
    audit_db.commit()
    assert is_valid_audit_id(aid)

    rows = audit_db.execute(
        "SELECT * FROM audit WHERE audit_id = ?", (aid,)
    ).fetchall()
    assert len(rows) == 1
    row = dict(rows[0])
    assert row["case_id"] == "INC-001"
    assert row["tool_group"] == "triage"
    assert row["tool_name"] == "triage_clusters"
    assert json.loads(row["parameters"]) == {"min_strength": "MODERATE"}
    assert json.loads(row["result_summary"]) == {"cluster_count": 5}
    assert row["duration_ms"] == 123
    assert row["examiner"] == "alice"


def test_record_audit_rejects_empty_examiner(audit_db: sqlite3.Connection) -> None:
    with pytest.raises(ValueError, match="examiner"):
        record_audit(
            audit_db,
            case_id="INC-001",
            tool_group="test",
            tool_name="t",
            parameters={},
            result_summary={},
            duration_ms=10,
            examiner="",
        )


def test_record_audit_rejects_empty_case_id(audit_db: sqlite3.Connection) -> None:
    with pytest.raises(ValueError, match="case_id"):
        record_audit(
            audit_db,
            case_id="",
            tool_group="test",
            tool_name="t",
            parameters={},
            result_summary={},
            duration_ms=10,
            examiner="alice",
        )


def test_record_audit_rejects_malformed_audit_id(
    audit_db: sqlite3.Connection,
) -> None:
    with pytest.raises(ValueError, match="Malformed"):
        record_audit(
            audit_db,
            case_id="INC-001",
            tool_group="test",
            tool_name="t",
            parameters={},
            result_summary={},
            duration_ms=10,
            examiner="alice",
            audit_id="BAD_FORMAT",
        )


def test_record_audit_with_queries_run(audit_db: sqlite3.Connection) -> None:
    queries = [
        {"dsl": "match_all", "ms": 50, "hits": 10},
        {"dsl": "terms host.name", "ms": 30, "hits": 3},
    ]
    aid = record_audit(
        audit_db,
        case_id="INC-001",
        tool_group="query",
        tool_name="query_clusters",
        parameters={},
        result_summary={},
        duration_ms=80,
        examiner="alice",
        queries_run=queries,
    )
    audit_db.commit()
    row = dict(
        audit_db.execute("SELECT * FROM audit WHERE audit_id = ?", (aid,)).fetchone()
    )
    assert json.loads(row["queries_run"]) == queries


# ============================================================
# query_audit
# ============================================================


def test_query_audit_filters_by_case(audit_db: sqlite3.Connection) -> None:
    for case_id in ("INC-A", "INC-B"):
        record_audit(
            audit_db,
            case_id=case_id,
            tool_group="test",
            tool_name="t",
            parameters={},
            result_summary={},
            duration_ms=10,
            examiner="alice",
        )
    audit_db.commit()

    results = query_audit(audit_db, case_id="INC-A")
    assert all(r["case_id"] == "INC-A" for r in results)
    assert len(results) == 1


def test_query_audit_filters_by_tool_name(audit_db: sqlite3.Connection) -> None:
    for tool in ("triage_clusters", "expand_cluster"):
        record_audit(
            audit_db,
            case_id="INC-A",
            tool_group="test",
            tool_name=tool,
            parameters={},
            result_summary={},
            duration_ms=10,
            examiner="alice",
        )
    audit_db.commit()

    results = query_audit(audit_db, tool_name="expand_cluster")
    assert len(results) == 1
    assert results[0]["tool_name"] == "expand_cluster"


def test_query_audit_returns_parsed_json(audit_db: sqlite3.Connection) -> None:
    record_audit(
        audit_db,
        case_id="INC-A",
        tool_group="test",
        tool_name="t",
        parameters={"key": "value"},
        result_summary={"count": 42},
        duration_ms=10,
        examiner="alice",
    )
    audit_db.commit()

    results = query_audit(audit_db)
    assert results[0]["parameters"] == {"key": "value"}
    assert results[0]["result_summary"] == {"count": 42}


def test_query_audit_respects_limit(audit_db: sqlite3.Connection) -> None:
    for i in range(5):
        record_audit(
            audit_db,
            case_id="INC-A",
            tool_group="test",
            tool_name=f"t{i}",
            parameters={},
            result_summary={},
            duration_ms=10,
            examiner="alice",
        )
    audit_db.commit()

    results = query_audit(audit_db, limit=3)
    assert len(results) == 3


def test_query_audit_newest_first(audit_db: sqlite3.Connection) -> None:
    record_audit(
        audit_db,
        case_id="INC-A",
        tool_group="test",
        tool_name="first",
        parameters={},
        result_summary={},
        duration_ms=10,
        examiner="alice",
        timestamp="2026-04-29T10:00:00+00:00",
    )
    record_audit(
        audit_db,
        case_id="INC-A",
        tool_group="test",
        tool_name="second",
        parameters={},
        result_summary={},
        duration_ms=10,
        examiner="alice",
        timestamp="2026-04-29T12:00:00+00:00",
    )
    audit_db.commit()

    results = query_audit(audit_db)
    assert results[0]["tool_name"] == "second"
    assert results[1]["tool_name"] == "first"
