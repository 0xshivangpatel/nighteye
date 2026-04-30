"""Case directory management.

A case is a directory under `cases_dir/` (default `~/cases/`) containing:
- CASE.yaml          metadata
- graph.db           SQLite Evidence Graph
- evidence/          original evidence files
- extractions/       parsed artifacts ready for ingest
- reports/           generated reports
- audit_export/      JSONL backup of audit table

The active-case pointer at `~/.nighteye/active_case` holds the absolute
path to the currently-selected case directory. Most commands resolve the
active case implicitly; `--case` overrides per-invocation.
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

from nighteye.db import connect, transaction
from nighteye.schema import init_schema

_CASE_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$")
_NIGHTEYE_DIR = Path.home() / ".nighteye"
_ACTIVE_CASE_FILE = _NIGHTEYE_DIR / "active_case"


class CaseError(Exception):
    """Raised when a case operation fails."""


@dataclass
class CaseInfo:
    """Lightweight case summary."""

    case_id: str
    name: str
    status: str
    examiner: str
    case_dir: Path
    created_at: str
    active: bool = False


def default_cases_dir() -> Path:
    """Return the default cases root directory."""
    return Path(os.environ.get("NIGHTEYE_CASES_DIR", str(Path.home() / "cases")))


def _validate_case_id(case_id: str) -> None:
    if not case_id or not _CASE_ID_RE.match(case_id):
        raise CaseError(
            f"Invalid case_id {case_id!r}: must be alphanumeric with hyphens/"
            f"underscores, 2-64 chars, starting with letter or digit."
        )
    if ".." in case_id or "/" in case_id or "\\" in case_id:
        raise CaseError(f"Invalid case_id {case_id!r}: path-traversal characters")


def _generate_case_id() -> str:
    ts = datetime.now(timezone.utc)
    return f"INC-{ts.strftime('%Y')}-{ts.strftime('%m%d%H%M%S')}"


def _atomic_write(path: Path, content: str) -> None:
    """Write atomically via temp file + os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def init_case(
    name: str,
    examiner: str,
    *,
    case_id: str | None = None,
    description: str = "",
    cases_dir: Path | None = None,
    set_active: bool = True,
) -> CaseInfo:
    """Initialize a new case directory and SQLite database.

    Returns CaseInfo with absolute paths. Raises CaseError if the case
    already exists or examiner/case_id are invalid.
    """
    if not name or not name.strip():
        raise CaseError("Case name cannot be empty")
    if not examiner:
        raise CaseError("Examiner cannot be empty")

    cases_dir = Path(cases_dir) if cases_dir else default_cases_dir()
    case_id = case_id or _generate_case_id()
    _validate_case_id(case_id)

    case_dir = cases_dir / case_id
    if case_dir.exists():
        raise CaseError(f"Case directory already exists: {case_dir}")

    # Layout
    case_dir.mkdir(parents=True)
    for sub in ("evidence", "extractions", "reports", "audit_export"):
        (case_dir / sub).mkdir()

    created_at = datetime.now(timezone.utc).isoformat()
    meta = {
        "case_id": case_id,
        "name": name.strip(),
        "description": description,
        "status": "open",
        "examiner": examiner,
        "created_at": created_at,
    }
    _atomic_write(case_dir / "CASE.yaml", yaml.safe_dump(meta, sort_keys=False))

    # Initialize SQLite schema
    db_path = case_dir / "graph.db"
    conn = connect(db_path)
    try:
        init_schema(conn)
    finally:
        conn.close()

    if set_active:
        set_active_case(case_dir)

    return CaseInfo(
        case_id=case_id,
        name=meta["name"],
        status=meta["status"],
        examiner=examiner,
        case_dir=case_dir.resolve(),
        created_at=created_at,
        active=set_active,
    )


def load_case_meta(case_dir: Path) -> dict:
    """Load CASE.yaml as a dict. Raises CaseError if missing or malformed."""
    meta_path = Path(case_dir) / "CASE.yaml"
    if not meta_path.exists():
        raise CaseError(f"Not a NightEye case directory (missing CASE.yaml): {case_dir}")
    try:
        with open(meta_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as err:
        raise CaseError(f"Failed to read {meta_path}: {err}") from err
    if not isinstance(data, dict):
        raise CaseError(f"Malformed CASE.yaml: {meta_path}")
    return data


def save_case_meta(case_dir: Path, meta: dict) -> None:
    """Atomically write CASE.yaml."""
    _atomic_write(case_dir / "CASE.yaml", yaml.safe_dump(meta, sort_keys=False))


def set_active_case(case_dir: Path) -> None:
    """Write the active-case pointer to ~/.nighteye/active_case."""
    case_dir = Path(case_dir).resolve()
    if not (case_dir / "CASE.yaml").exists():
        raise CaseError(f"Cannot activate non-case directory: {case_dir}")
    _NIGHTEYE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    _atomic_write(_ACTIVE_CASE_FILE, str(case_dir))


def clear_active_case() -> None:
    """Remove the active-case pointer."""
    if _ACTIVE_CASE_FILE.exists():
        _ACTIVE_CASE_FILE.unlink()


def get_active_case_dir() -> Path | None:
    """Return absolute path to active case, or None if none set."""
    if not _ACTIVE_CASE_FILE.exists():
        return None
    try:
        content = _ACTIVE_CASE_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not content:
        return None
    p = Path(content)
    if not p.exists() or not (p / "CASE.yaml").exists():
        return None
    return p


def get_case_dir(
    case_id: str | None = None, *, cases_dir: Path | None = None
) -> Path:
    """Resolve a case directory.

    Resolution order:
      1. `case_id` argument (fails if not found)
      2. `NIGHTEYE_CASE_DIR` env var (fails if invalid)
      3. Active case pointer
    """
    if case_id:
        _validate_case_id(case_id)
        cases_dir = Path(cases_dir) if cases_dir else default_cases_dir()
        case_dir = cases_dir / case_id
        if not (case_dir / "CASE.yaml").exists():
            raise CaseError(f"Case not found: {case_id}")
        return case_dir.resolve()

    env_dir = os.environ.get("NIGHTEYE_CASE_DIR")
    if env_dir:
        case_dir = Path(env_dir)
        if not (case_dir / "CASE.yaml").exists():
            raise CaseError(f"NIGHTEYE_CASE_DIR is not a case dir: {case_dir}")
        return case_dir.resolve()

    active = get_active_case_dir()
    if active:
        return active

    raise CaseError(
        "No active case. Use `nighteye case init` or `nighteye case activate <id>`, "
        "or pass --case <id>."
    )


def list_cases(cases_dir: Path | None = None) -> list[CaseInfo]:
    """List all cases under cases_dir, sorted by case_id."""
    cases_dir = Path(cases_dir) if cases_dir else default_cases_dir()
    if not cases_dir.is_dir():
        return []
    active_dir = get_active_case_dir()
    out: list[CaseInfo] = []
    for entry in sorted(cases_dir.iterdir()):
        if not entry.is_dir():
            continue
        meta_path = entry / "CASE.yaml"
        if not meta_path.exists():
            continue
        try:
            meta = load_case_meta(entry)
        except CaseError:
            continue
        out.append(
            CaseInfo(
                case_id=meta.get("case_id", entry.name),
                name=meta.get("name", ""),
                status=meta.get("status", "unknown"),
                examiner=meta.get("examiner", ""),
                case_dir=entry.resolve(),
                created_at=meta.get("created_at", ""),
                active=(active_dir == entry.resolve() if active_dir else False),
            )
        )
    return out


def case_status(case_dir: Path) -> dict:
    """Return a status dict for a case: meta + counts from graph.db."""
    meta = load_case_meta(case_dir)
    db_path = case_dir / "graph.db"
    counts: dict[str, int] = {
        "entities": 0,
        "edges": 0,
        "clusters": 0,
        "hypotheses_total": 0,
        "hypotheses_draft": 0,
        "hypotheses_approved": 0,
        "hypotheses_rejected": 0,
        "hypotheses_insufficient": 0,
        "evidence_gaps_open": 0,
        "audit_entries": 0,
        "journal_entries": 0,
    }
    if db_path.exists():
        conn = connect(db_path, read_only=True)
        try:
            counts["entities"] = conn.execute(
                "SELECT COUNT(*) FROM entities"
            ).fetchone()[0]
            counts["edges"] = conn.execute(
                "SELECT COUNT(*) FROM edges"
            ).fetchone()[0]
            counts["clusters"] = conn.execute(
                "SELECT COUNT(*) FROM clusters"
            ).fetchone()[0]
            counts["hypotheses_total"] = conn.execute(
                "SELECT COUNT(*) FROM hypotheses"
            ).fetchone()[0]
            for status_name, key in (
                ("DRAFT", "hypotheses_draft"),
                ("APPROVED", "hypotheses_approved"),
                ("REJECTED", "hypotheses_rejected"),
                ("INSUFFICIENT_EVIDENCE", "hypotheses_insufficient"),
            ):
                counts[key] = conn.execute(
                    "SELECT COUNT(*) FROM hypotheses WHERE status = ?",
                    (status_name,),
                ).fetchone()[0]
            counts["evidence_gaps_open"] = conn.execute(
                "SELECT COUNT(*) FROM evidence_gaps WHERE resolved_at IS NULL"
            ).fetchone()[0]
            counts["audit_entries"] = conn.execute(
                "SELECT COUNT(*) FROM audit"
            ).fetchone()[0]
            counts["journal_entries"] = conn.execute(
                "SELECT COUNT(*) FROM journal"
            ).fetchone()[0]
        finally:
            conn.close()
    return {"meta": meta, "case_dir": str(case_dir.resolve()), "counts": counts}


def close_case(case_dir: Path, summary: str = "") -> None:
    """Mark a case as closed in CASE.yaml and clear active pointer if matching."""
    meta = load_case_meta(case_dir)
    if meta.get("status") == "closed":
        raise CaseError(f"Case {meta.get('case_id')} is already closed")
    meta["status"] = "closed"
    meta["closed_at"] = datetime.now(timezone.utc).isoformat()
    if summary:
        meta["close_summary"] = summary
    save_case_meta(case_dir, meta)
    active = get_active_case_dir()
    if active and active == case_dir.resolve():
        clear_active_case()


def reopen_case(case_dir: Path) -> None:
    """Reopen a closed case."""
    meta = load_case_meta(case_dir)
    if meta.get("status") != "closed":
        raise CaseError(
            f"Case {meta.get('case_id')} is not closed (status: {meta.get('status')})"
        )
    meta["status"] = "open"
    meta.pop("closed_at", None)
    meta.pop("close_summary", None)
    save_case_meta(case_dir, meta)


def delete_case(case_dir: Path, *, force: bool = False) -> None:
    """Delete a case directory and its database. Test-helper; not on the CLI."""
    case_dir = Path(case_dir)
    if not (case_dir / "CASE.yaml").exists() and not force:
        raise CaseError(f"Refusing to delete non-case directory: {case_dir}")
    shutil.rmtree(case_dir)
    active = get_active_case_dir()
    if active and active == case_dir.resolve():
        clear_active_case()


# Re-export transaction for convenience in CLI / tools
__all__ = [
    "CaseError",
    "CaseInfo",
    "case_status",
    "clear_active_case",
    "close_case",
    "default_cases_dir",
    "delete_case",
    "get_active_case_dir",
    "get_case_dir",
    "init_case",
    "list_cases",
    "load_case_meta",
    "reopen_case",
    "save_case_meta",
    "set_active_case",
    "transaction",
]
