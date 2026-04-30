"""Tests for the SQLite connection helper."""

from __future__ import annotations

from pathlib import Path

from nighteye.db import connect, execute_with_retry, get_pragma, transaction
from nighteye.schema import init_schema


def test_connect_enables_wal_and_foreign_keys(tmp_path: Path) -> None:
    db = tmp_path / "graph.db"
    conn = connect(db)
    try:
        assert get_pragma(conn, "journal_mode") == "wal"
        assert get_pragma(conn, "foreign_keys") == 1
    finally:
        conn.close()


def test_connect_creates_parent_dirs(tmp_path: Path) -> None:
    db = tmp_path / "deep" / "nested" / "graph.db"
    conn = connect(db)
    try:
        assert db.exists()
    finally:
        conn.close()


def test_connect_read_only_mode(tmp_path: Path) -> None:
    db = tmp_path / "graph.db"
    rw = connect(db)
    try:
        init_schema(rw)
        rw.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
            (99, "2026-01-01"),
        )
        rw.commit()
    finally:
        rw.close()

    ro = connect(db, read_only=True)
    try:
        rows = ro.execute("SELECT version FROM schema_version").fetchall()
        assert any(r[0] == 99 for r in rows)
    finally:
        ro.close()


def test_transaction_commits_on_success(tmp_path: Path) -> None:
    db = tmp_path / "graph.db"
    conn = connect(db)
    try:
        init_schema(conn)
        with transaction(conn):
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (42, "2026-01-01"),
            )
        rows = conn.execute(
            "SELECT version FROM schema_version WHERE version = 42"
        ).fetchall()
        assert len(rows) == 1
    finally:
        conn.close()


def test_transaction_rolls_back_on_exception(tmp_path: Path) -> None:
    db = tmp_path / "graph.db"
    conn = connect(db)
    try:
        init_schema(conn)

        class _BoomError(RuntimeError):
            pass

        try:
            with transaction(conn):
                conn.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                    (77, "2026-01-01"),
                )
                raise _BoomError("simulated failure")
        except _BoomError:
            pass

        rows = conn.execute(
            "SELECT version FROM schema_version WHERE version = 77"
        ).fetchall()
        assert rows == []
    finally:
        conn.close()


def test_execute_with_retry_passes_through_normal_calls(tmp_path: Path) -> None:
    db = tmp_path / "graph.db"
    conn = connect(db)
    try:
        init_schema(conn)
        cur = execute_with_retry(
            conn,
            "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
            (55, "2026-01-01"),
        )
        assert cur.rowcount == 1
    finally:
        conn.close()
