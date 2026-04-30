"""SQLite connection helper for NightEye case databases.

Centralizes connection setup so every caller gets the same PRAGMAs:
WAL journal mode, foreign keys enforced, sane busy timeout.

Sync API in v1; D13 will add `asyncio.to_thread` wrappers when MCP
tools need DB access from async contexts.
"""

from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

# Default busy timeout (ms). SQLite blocks for up to this long if another
# writer holds the lock before raising sqlite3.OperationalError.
_DEFAULT_BUSY_TIMEOUT_MS = 5000

# Number of automatic retries on OperationalError("database is locked").
_LOCK_RETRY_ATTEMPTS = 3
_LOCK_RETRY_BACKOFF_S = 0.1


def connect(db_path: str | Path, *, read_only: bool = False) -> sqlite3.Connection:
    """Open a SQLite connection with NightEye's standard PRAGMAs.

    - WAL journaling (concurrent readers + one writer)
    - Foreign keys enforced
    - 5-second busy timeout
    - Row factory set to sqlite3.Row for column-name access

    `read_only=True` opens in URI mode with mode=ro for immutable read paths.
    """
    db_path = Path(db_path)
    if read_only:
        uri = f"file:{db_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=_DEFAULT_BUSY_TIMEOUT_MS / 1000)
    else:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path), timeout=_DEFAULT_BUSY_TIMEOUT_MS / 1000)

    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(f"PRAGMA busy_timeout = {_DEFAULT_BUSY_TIMEOUT_MS}")
    if not read_only:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Context manager: BEGIN IMMEDIATE / COMMIT / ROLLBACK on exception."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.rollback()
        raise
    else:
        conn.commit()


def execute_with_retry(
    conn: sqlite3.Connection,
    sql: str,
    params: tuple | dict = (),
) -> sqlite3.Cursor:
    """Execute a write with automatic retry on 'database is locked'.

    SQLite WAL mode is robust under concurrent reads; writes still need
    serialization. Brief retries handle the rare contention case.
    """
    last_err: sqlite3.OperationalError | None = None
    for attempt in range(_LOCK_RETRY_ATTEMPTS):
        try:
            return conn.execute(sql, params)
        except sqlite3.OperationalError as err:
            if "locked" not in str(err).lower():
                raise
            last_err = err
            if attempt < _LOCK_RETRY_ATTEMPTS - 1:
                time.sleep(_LOCK_RETRY_BACKOFF_S * (2**attempt))
    assert last_err is not None
    raise last_err


def get_pragma(conn: sqlite3.Connection, pragma: str) -> object:
    """Return the value of a SQLite PRAGMA."""
    cur = conn.execute(f"PRAGMA {pragma}")
    row = cur.fetchone()
    if row is None:
        return None
    return row[0]
