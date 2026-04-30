"""Schema management for NightEye Evidence Graph SQLite databases."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path

CURRENT_SCHEMA_VERSION = 1


def init_schema(conn: sqlite3.Connection) -> int:
    """Initialize schema on a connection. Idempotent.

    Returns the schema version after initialization.
    """
    sql = files("nighteye.schema").joinpath("graph.sql").read_text(encoding="utf-8")
    conn.executescript(sql)
    cur = conn.execute("SELECT MAX(version) FROM schema_version")
    row = cur.fetchone()
    current = row[0] if row else None
    if current is None:
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
            (CURRENT_SCHEMA_VERSION, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        current = CURRENT_SCHEMA_VERSION
    return current


def schema_version(conn: sqlite3.Connection) -> int | None:
    """Return current schema version, or None if not initialized."""
    try:
        cur = conn.execute("SELECT MAX(version) FROM schema_version")
        row = cur.fetchone()
        return row[0] if row and row[0] is not None else None
    except sqlite3.OperationalError:
        return None


def init_schema_at_path(db_path: Path) -> int:
    """Initialize schema at the given DB path, creating parents if needed."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        return init_schema(conn)
    finally:
        conn.close()
