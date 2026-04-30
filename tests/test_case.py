"""Tests for case lifecycle: init, list, status, activate, close, reopen, delete.

Covers: directory layout, CASE.yaml format, schema init, case ID validation,
active-case pointer, status counts, close/reopen semantics, edge cases,
env var resolution, metadata persistence, and concurrent multi-case management.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest
import yaml

from nighteye.case import (
    CaseError,
    CaseInfo,
    case_status,
    clear_active_case,
    close_case,
    default_cases_dir,
    delete_case,
    get_active_case_dir,
    get_case_dir,
    init_case,
    list_cases,
    load_case_meta,
    reopen_case,
    save_case_meta,
    set_active_case,
)


# ============================================================
# init_case — directory layout
# ============================================================


def test_init_case_creates_directory_layout(
    nighteye_home: Path, cases_dir: Path
) -> None:
    info = init_case(name="My Investigation", examiner="alice", cases_dir=cases_dir)
    case_root = cases_dir / info.case_id
    assert case_root.exists()
    assert (case_root / "CASE.yaml").exists()
    assert (case_root / "graph.db").exists()
    assert (case_root / "evidence").is_dir()
    assert (case_root / "extractions").is_dir()
    assert (case_root / "reports").is_dir()
    assert (case_root / "audit_export").is_dir()


def test_init_case_returns_case_info(
    nighteye_home: Path, cases_dir: Path
) -> None:
    info = init_case(
        name="Test Case",
        examiner="alice",
        case_id="INC-2026-TEST",
        cases_dir=cases_dir,
    )
    assert isinstance(info, CaseInfo)
    assert info.case_id == "INC-2026-TEST"
    assert info.name == "Test Case"
    assert info.examiner == "alice"
    assert info.status == "open"
    assert info.case_dir.is_absolute()
    assert info.created_at  # non-empty ISO string
    assert info.active is True  # default


# ============================================================
# init_case — metadata
# ============================================================


def test_init_case_writes_valid_metadata(
    nighteye_home: Path, cases_dir: Path
) -> None:
    info = init_case(
        name="Test Case",
        examiner="alice",
        description="A description",
        cases_dir=cases_dir,
    )
    meta = load_case_meta(cases_dir / info.case_id)
    assert meta["name"] == "Test Case"
    assert meta["examiner"] == "alice"
    assert meta["status"] == "open"
    assert meta["description"] == "A description"
    assert meta["case_id"] == info.case_id
    assert meta["created_at"]


def test_init_case_name_is_trimmed(
    nighteye_home: Path, cases_dir: Path
) -> None:
    info = init_case(name="  Padded Name  ", examiner="alice", cases_dir=cases_dir)
    meta = load_case_meta(info.case_dir)
    assert meta["name"] == "Padded Name"


def test_init_case_default_description_is_empty(
    nighteye_home: Path, cases_dir: Path
) -> None:
    info = init_case(name="t", examiner="alice", cases_dir=cases_dir)
    meta = load_case_meta(info.case_dir)
    assert meta["description"] == ""


def test_case_yaml_format_is_correct(nighteye_home: Path, cases_dir: Path) -> None:
    info = init_case(name="My Case", examiner="alice", cases_dir=cases_dir)
    text = (info.case_dir / "CASE.yaml").read_text()
    parsed = yaml.safe_load(text)
    # Verify expected keys
    for key in ("case_id", "name", "description", "status", "examiner", "created_at"):
        assert key in parsed, f"missing key {key}"


# ============================================================
# init_case — schema initialization
# ============================================================


def test_init_case_initializes_schema(
    nighteye_home: Path, cases_dir: Path
) -> None:
    info = init_case(name="t", examiner="alice", cases_dir=cases_dir)
    db = cases_dir / info.case_id / "graph.db"
    conn = sqlite3.connect(str(db))
    try:
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        expected = {
            "entities", "edges", "evidence_disturbances",
            "case_capabilities", "clusters", "hypotheses",
            "evidence_gaps", "journal", "audit", "schema_version",
        }
        assert expected.issubset(tables), f"missing: {expected - tables}"
    finally:
        conn.close()


# ============================================================
# init_case — case ID handling
# ============================================================


def test_init_case_with_explicit_id(
    nighteye_home: Path, cases_dir: Path
) -> None:
    info = init_case(
        name="t", examiner="alice", case_id="INC-2026-001", cases_dir=cases_dir
    )
    assert info.case_id == "INC-2026-001"
    assert (cases_dir / "INC-2026-001" / "CASE.yaml").exists()


def test_init_case_generates_id_when_omitted(
    nighteye_home: Path, cases_dir: Path
) -> None:
    info = init_case(name="t", examiner="alice", cases_dir=cases_dir)
    assert info.case_id.startswith("INC-")
    assert len(info.case_id) > 6  # INC-YYYY-XXXXXXXXXX


def test_init_case_rejects_invalid_case_ids(
    nighteye_home: Path, cases_dir: Path
) -> None:
    bad_ids = [
        "bad/id",       # slash
        "..",            # traversal
        "a",            # too short (min 2 chars)
        "bad\\id",      # backslash
    ]
    for bad_id in bad_ids:
        with pytest.raises(CaseError, match="Invalid case_id"):
            init_case(name="t", examiner="alice", case_id=bad_id, cases_dir=cases_dir)


def test_init_case_accepts_valid_case_ids(
    nighteye_home: Path, cases_dir: Path
) -> None:
    valid_ids = ["INC-A", "ab", "case-123", "MY_CASE_01", "A1-B2-C3"]
    for i, cid in enumerate(valid_ids):
        info = init_case(
            name=f"t{i}", examiner="alice", case_id=cid, cases_dir=cases_dir
        )
        assert info.case_id == cid


# ============================================================
# init_case — error handling
# ============================================================


def test_init_case_rejects_empty_name(
    nighteye_home: Path, cases_dir: Path
) -> None:
    with pytest.raises(CaseError, match="[Nn]ame"):
        init_case(name="", examiner="alice", cases_dir=cases_dir)
    with pytest.raises(CaseError, match="[Nn]ame"):
        init_case(name="   ", examiner="alice", cases_dir=cases_dir)


def test_init_case_rejects_empty_examiner(
    nighteye_home: Path, cases_dir: Path
) -> None:
    with pytest.raises(CaseError, match="[Ee]xaminer"):
        init_case(name="t", examiner="", cases_dir=cases_dir)


def test_init_case_refuses_existing_directory(
    nighteye_home: Path, cases_dir: Path
) -> None:
    init_case(name="t", examiner="alice", case_id="DUPE", cases_dir=cases_dir)
    with pytest.raises(CaseError, match="already exists"):
        init_case(name="t", examiner="alice", case_id="DUPE", cases_dir=cases_dir)


# ============================================================
# Active case pointer
# ============================================================


def test_init_case_sets_active_by_default(
    nighteye_home: Path, cases_dir: Path
) -> None:
    info = init_case(name="t", examiner="alice", cases_dir=cases_dir)
    active = get_active_case_dir()
    assert active is not None
    assert active.resolve() == info.case_dir.resolve()


def test_init_case_no_activate_flag(
    nighteye_home: Path, cases_dir: Path
) -> None:
    init_case(name="t", examiner="alice", cases_dir=cases_dir, set_active=False)
    assert get_active_case_dir() is None


def test_set_active_case_writes_pointer(
    nighteye_home: Path, cases_dir: Path
) -> None:
    info = init_case(name="t", examiner="alice", cases_dir=cases_dir, set_active=False)
    set_active_case(info.case_dir)
    active = get_active_case_dir()
    assert active is not None
    assert active.resolve() == info.case_dir.resolve()


def test_clear_active_case(nighteye_home: Path, cases_dir: Path) -> None:
    init_case(name="t", examiner="alice", cases_dir=cases_dir)
    assert get_active_case_dir() is not None
    clear_active_case()
    assert get_active_case_dir() is None


def test_clear_active_case_is_idempotent(nighteye_home: Path) -> None:
    """Clearing when nothing is active shouldn't raise."""
    clear_active_case()
    clear_active_case()  # no error


def test_set_active_case_rejects_non_case_dir(
    nighteye_home: Path, tmp_path: Path
) -> None:
    bogus = tmp_path / "not-a-case"
    bogus.mkdir()
    with pytest.raises(CaseError, match="Cannot activate"):
        set_active_case(bogus)


def test_active_case_switches_on_second_init(
    nighteye_home: Path, cases_dir: Path
) -> None:
    """Last init_case with set_active=True wins."""
    info_a = init_case(name="A", examiner="alice", case_id="INC-A", cases_dir=cases_dir)
    info_b = init_case(name="B", examiner="alice", case_id="INC-B", cases_dir=cases_dir)
    active = get_active_case_dir()
    assert active is not None
    assert active.resolve() == info_b.case_dir.resolve()


def test_get_active_case_dir_returns_none_when_target_deleted(
    nighteye_home: Path, cases_dir: Path
) -> None:
    """If the active case directory is deleted, get_active_case_dir returns None."""
    import shutil
    info = init_case(name="t", examiner="alice", cases_dir=cases_dir)
    assert get_active_case_dir() is not None
    shutil.rmtree(info.case_dir)
    assert get_active_case_dir() is None


# ============================================================
# list_cases
# ============================================================


def test_list_cases_returns_all(nighteye_home: Path, cases_dir: Path) -> None:
    init_case(name="A", examiner="alice", case_id="INC-A", cases_dir=cases_dir)
    init_case(name="B", examiner="bob", case_id="INC-B", cases_dir=cases_dir)
    cases = list_cases(cases_dir)
    ids = [c.case_id for c in cases]
    assert "INC-A" in ids
    assert "INC-B" in ids


def test_list_cases_sorted_by_case_id(nighteye_home: Path, cases_dir: Path) -> None:
    init_case(name="Z", examiner="alice", case_id="INC-Z", cases_dir=cases_dir)
    init_case(name="A", examiner="alice", case_id="INC-A", cases_dir=cases_dir)
    init_case(name="M", examiner="alice", case_id="INC-M", cases_dir=cases_dir)
    cases = list_cases(cases_dir)
    ids = [c.case_id for c in cases]
    assert ids == sorted(ids)


def test_list_cases_marks_active(nighteye_home: Path, cases_dir: Path) -> None:
    init_case(name="A", examiner="alice", case_id="INC-A", cases_dir=cases_dir)
    init_case(name="B", examiner="alice", case_id="INC-B", cases_dir=cases_dir)
    cases = list_cases(cases_dir)
    active = [c for c in cases if c.active]
    assert len(active) == 1
    assert active[0].case_id == "INC-B"  # last initialized became active


def test_list_cases_empty_dir(nighteye_home: Path, cases_dir: Path) -> None:
    assert list_cases(cases_dir) == []


def test_list_cases_nonexistent_dir(nighteye_home: Path, tmp_path: Path) -> None:
    assert list_cases(tmp_path / "nonexistent") == []


def test_list_cases_ignores_non_case_dirs(
    nighteye_home: Path, cases_dir: Path
) -> None:
    """Non-case subdirectories (no CASE.yaml) are silently skipped."""
    init_case(name="A", examiner="alice", case_id="INC-A", cases_dir=cases_dir)
    (cases_dir / "random-dir").mkdir()
    (cases_dir / "some-file.txt").write_text("not a case")
    cases = list_cases(cases_dir)
    assert len(cases) == 1
    assert cases[0].case_id == "INC-A"


# ============================================================
# get_case_dir
# ============================================================


def test_get_case_dir_uses_active(nighteye_home: Path, cases_dir: Path) -> None:
    info = init_case(name="t", examiner="alice", cases_dir=cases_dir)
    resolved = get_case_dir()
    assert resolved.resolve() == info.case_dir.resolve()


def test_get_case_dir_by_id(nighteye_home: Path, cases_dir: Path) -> None:
    init_case(name="t", examiner="alice", case_id="INC-X", cases_dir=cases_dir)
    resolved = get_case_dir("INC-X", cases_dir=cases_dir)
    assert resolved.name == "INC-X"


def test_get_case_dir_raises_when_no_active_no_id(
    nighteye_home: Path, cases_dir: Path
) -> None:
    with pytest.raises(CaseError, match="No active case"):
        get_case_dir()


def test_get_case_dir_raises_for_unknown_id(
    nighteye_home: Path, cases_dir: Path
) -> None:
    with pytest.raises(CaseError, match="Case not found"):
        get_case_dir("INC-NOPE", cases_dir=cases_dir)


def test_get_case_dir_env_var_override(
    nighteye_home: Path, cases_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """NIGHTEYE_CASE_DIR environment variable should be used when set."""
    info = init_case(name="t", examiner="alice", cases_dir=cases_dir, set_active=False)
    monkeypatch.setenv("NIGHTEYE_CASE_DIR", str(info.case_dir))
    resolved = get_case_dir()
    assert resolved.resolve() == info.case_dir.resolve()


def test_get_case_dir_env_var_invalid_raises(
    nighteye_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """NIGHTEYE_CASE_DIR pointing to non-case dir should raise."""
    bogus = tmp_path / "not-a-case"
    bogus.mkdir()
    monkeypatch.setenv("NIGHTEYE_CASE_DIR", str(bogus))
    with pytest.raises(CaseError, match="NIGHTEYE_CASE_DIR"):
        get_case_dir()


def test_get_case_dir_explicit_id_beats_active(
    nighteye_home: Path, cases_dir: Path
) -> None:
    """Explicit case_id argument takes priority over active case."""
    init_case(name="active", examiner="alice", case_id="INC-ACTIVE", cases_dir=cases_dir)
    init_case(
        name="target", examiner="alice", case_id="INC-TARGET",
        cases_dir=cases_dir, set_active=False,
    )
    resolved = get_case_dir("INC-TARGET", cases_dir=cases_dir)
    assert resolved.name == "INC-TARGET"


# ============================================================
# case_status
# ============================================================


def test_case_status_returns_zero_counts_on_fresh_case(
    nighteye_home: Path, cases_dir: Path
) -> None:
    info = init_case(name="t", examiner="alice", cases_dir=cases_dir)
    status = case_status(info.case_dir)
    assert status["meta"]["case_id"] == info.case_id
    counts = status["counts"]
    assert counts["entities"] == 0
    assert counts["edges"] == 0
    assert counts["clusters"] == 0
    assert counts["hypotheses_total"] == 0
    assert counts["hypotheses_draft"] == 0
    assert counts["hypotheses_approved"] == 0
    assert counts["hypotheses_rejected"] == 0
    assert counts["hypotheses_insufficient"] == 0
    assert counts["evidence_gaps_open"] == 0
    assert counts["audit_entries"] == 0
    assert counts["journal_entries"] == 0


def test_case_status_includes_case_dir_path(
    nighteye_home: Path, cases_dir: Path
) -> None:
    info = init_case(name="t", examiner="alice", cases_dir=cases_dir)
    status = case_status(info.case_dir)
    assert "case_dir" in status
    assert Path(status["case_dir"]).exists()


def test_case_status_meta_matches_yaml(
    nighteye_home: Path, cases_dir: Path
) -> None:
    info = init_case(name="My Case", examiner="bob", cases_dir=cases_dir)
    status = case_status(info.case_dir)
    meta = status["meta"]
    assert meta["name"] == "My Case"
    assert meta["examiner"] == "bob"
    assert meta["status"] == "open"


# ============================================================
# close_case
# ============================================================


def test_close_case_marks_status_and_clears_active(
    nighteye_home: Path, cases_dir: Path
) -> None:
    info = init_case(name="t", examiner="alice", cases_dir=cases_dir)
    close_case(info.case_dir, summary="all done")
    meta = load_case_meta(info.case_dir)
    assert meta["status"] == "closed"
    assert meta["close_summary"] == "all done"
    assert "closed_at" in meta
    assert get_active_case_dir() is None


def test_close_case_without_summary(
    nighteye_home: Path, cases_dir: Path
) -> None:
    info = init_case(name="t", examiner="alice", cases_dir=cases_dir)
    close_case(info.case_dir)
    meta = load_case_meta(info.case_dir)
    assert meta["status"] == "closed"
    assert "close_summary" not in meta  # no summary → no key


def test_close_case_already_closed_raises(
    nighteye_home: Path, cases_dir: Path
) -> None:
    info = init_case(name="t", examiner="alice", cases_dir=cases_dir)
    close_case(info.case_dir)
    with pytest.raises(CaseError, match="already closed"):
        close_case(info.case_dir)


def test_close_case_doesnt_clear_other_active(
    nighteye_home: Path, cases_dir: Path
) -> None:
    """Closing a non-active case shouldn't affect the active pointer."""
    info_a = init_case(name="A", examiner="alice", case_id="INC-A", cases_dir=cases_dir)
    info_b = init_case(name="B", examiner="alice", case_id="INC-B", cases_dir=cases_dir)
    # B is active. Close A.
    close_case(info_a.case_dir)
    active = get_active_case_dir()
    assert active is not None
    assert active.resolve() == info_b.case_dir.resolve()


# ============================================================
# reopen_case
# ============================================================


def test_reopen_case(nighteye_home: Path, cases_dir: Path) -> None:
    info = init_case(name="t", examiner="alice", cases_dir=cases_dir)
    close_case(info.case_dir)
    reopen_case(info.case_dir)
    meta = load_case_meta(info.case_dir)
    assert meta["status"] == "open"
    assert "closed_at" not in meta
    assert "close_summary" not in meta


def test_reopen_already_open_raises(
    nighteye_home: Path, cases_dir: Path
) -> None:
    info = init_case(name="t", examiner="alice", cases_dir=cases_dir)
    with pytest.raises(CaseError, match="not closed"):
        reopen_case(info.case_dir)


# ============================================================
# save_case_meta
# ============================================================


def test_save_case_meta_persists(
    nighteye_home: Path, cases_dir: Path
) -> None:
    info = init_case(name="t", examiner="alice", cases_dir=cases_dir)
    meta = load_case_meta(info.case_dir)
    meta["custom_field"] = "custom_value"
    save_case_meta(info.case_dir, meta)

    reloaded = load_case_meta(info.case_dir)
    assert reloaded["custom_field"] == "custom_value"
    assert reloaded["name"] == "t"  # original fields preserved


def test_save_case_meta_is_atomic(
    nighteye_home: Path, cases_dir: Path
) -> None:
    """After save, no .tmp file should linger."""
    info = init_case(name="t", examiner="alice", cases_dir=cases_dir)
    meta = load_case_meta(info.case_dir)
    save_case_meta(info.case_dir, meta)
    assert not (info.case_dir / "CASE.yaml.tmp").exists()


# ============================================================
# load_case_meta — error handling
# ============================================================


def test_load_case_meta_raises_on_missing(
    nighteye_home: Path, tmp_path: Path
) -> None:
    with pytest.raises(CaseError, match="missing CASE.yaml"):
        load_case_meta(tmp_path / "no-such-dir")


def test_load_case_meta_raises_on_malformed_yaml(
    nighteye_home: Path, tmp_path: Path
) -> None:
    case_dir = tmp_path / "bad-case"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("not_a_dict", encoding="utf-8")
    with pytest.raises(CaseError, match="[Mm]alformed"):
        load_case_meta(case_dir)


# ============================================================
# delete_case
# ============================================================


def test_delete_case_removes_directory(
    nighteye_home: Path, cases_dir: Path
) -> None:
    info = init_case(name="t", examiner="alice", cases_dir=cases_dir)
    delete_case(info.case_dir)
    assert not info.case_dir.exists()


def test_delete_active_case_clears_pointer(
    nighteye_home: Path, cases_dir: Path
) -> None:
    info = init_case(name="t", examiner="alice", cases_dir=cases_dir)
    assert get_active_case_dir() is not None
    delete_case(info.case_dir)
    assert get_active_case_dir() is None


def test_delete_non_case_dir_raises_without_force(
    nighteye_home: Path, tmp_path: Path
) -> None:
    bogus = tmp_path / "not-a-case"
    bogus.mkdir()
    with pytest.raises(CaseError, match="Refusing"):
        delete_case(bogus)


def test_delete_non_case_dir_succeeds_with_force(
    nighteye_home: Path, tmp_path: Path
) -> None:
    bogus = tmp_path / "force-delete"
    bogus.mkdir()
    (bogus / "file.txt").write_text("data")
    delete_case(bogus, force=True)
    assert not bogus.exists()


# ============================================================
# default_cases_dir
# ============================================================


def test_default_cases_dir_uses_env_var(
    nighteye_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NIGHTEYE_CASES_DIR", "/custom/path")
    assert default_cases_dir() == Path("/custom/path")


def test_default_cases_dir_falls_back_to_home(
    nighteye_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("NIGHTEYE_CASES_DIR", raising=False)
    result = default_cases_dir()
    assert result == Path.home() / "cases"


# ============================================================
# Multi-case workflows
# ============================================================


def test_multiple_cases_independent(
    nighteye_home: Path, cases_dir: Path
) -> None:
    """Creating multiple cases doesn't corrupt each other's metadata."""
    info_a = init_case(
        name="Case A", examiner="alice", case_id="INC-A", cases_dir=cases_dir
    )
    info_b = init_case(
        name="Case B", examiner="bob", case_id="INC-B", cases_dir=cases_dir
    )

    meta_a = load_case_meta(info_a.case_dir)
    meta_b = load_case_meta(info_b.case_dir)
    assert meta_a["name"] == "Case A"
    assert meta_a["examiner"] == "alice"
    assert meta_b["name"] == "Case B"
    assert meta_b["examiner"] == "bob"


def test_close_and_reopen_preserves_metadata(
    nighteye_home: Path, cases_dir: Path
) -> None:
    """Close then reopen should preserve original metadata fields."""
    info = init_case(
        name="Persistent", examiner="alice", case_id="INC-P",
        description="important", cases_dir=cases_dir,
    )
    close_case(info.case_dir, summary="done")
    reopen_case(info.case_dir)
    meta = load_case_meta(info.case_dir)
    assert meta["name"] == "Persistent"
    assert meta["examiner"] == "alice"
    assert meta["description"] == "important"
    assert meta["status"] == "open"


def test_full_lifecycle(
    nighteye_home: Path, cases_dir: Path
) -> None:
    """End-to-end: init → status → close → reopen → delete."""
    # Init
    info = init_case(
        name="Lifecycle", examiner="alice", case_id="INC-LC", cases_dir=cases_dir
    )
    assert info.status == "open"

    # Status
    status = case_status(info.case_dir)
    assert status["meta"]["status"] == "open"

    # Close
    close_case(info.case_dir, summary="investigation complete")
    meta = load_case_meta(info.case_dir)
    assert meta["status"] == "closed"

    # Reopen
    reopen_case(info.case_dir)
    meta = load_case_meta(info.case_dir)
    assert meta["status"] == "open"

    # Delete
    delete_case(info.case_dir)
    assert not info.case_dir.exists()
