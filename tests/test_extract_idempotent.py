"""Tests for extract.py idempotency.

The user-reported bug: running ingest a second time after deleting the
source zip caused the system to lose track of the previously-extracted
contents. The fix surfaces all directories under case/extractions/
regardless of whether the source archives are still on disk.
"""

from __future__ import annotations

from pathlib import Path

from nighteye.case import init_case
from nighteye.ingest.extract import extract_archives


def _seed_extracted_dir(extractions_root: Path, name: str, content: str) -> Path:
    """Pretend an archive was extracted previously by creating the dir + marker."""
    out = extractions_root / name
    out.mkdir(parents=True, exist_ok=True)
    (out / "evidence.txt").write_text(content)
    (out / ".nighteye_extracted").write_text(f"source: {name}.zip\n")
    return out


def test_extract_returns_existing_extractions_when_source_zip_missing(
    nighteye_home: Path, cases_dir: Path, tmp_path: Path
) -> None:
    """User-reported bug: re-run with no zip should still surface
    previously-extracted dirs. Previously returned [] which broke ingest."""
    case = init_case(name="idempotency-test", examiner="alice", cases_dir=cases_dir)
    extractions = case.case_dir / "extractions"

    seeded = _seed_extracted_dir(extractions, "win7-64-nfury", "fake evtx data")

    # The evidence drive (target_dir) is empty — no archives.
    empty_drive = tmp_path / "empty_drive"
    empty_drive.mkdir()

    result = extract_archives(empty_drive, recursive=True)

    # The previously-extracted dir must still appear in the result.
    assert seeded.resolve() in {p.resolve() for p in result}
    assert len(result) >= 1


def test_extract_skips_re_extraction_when_dir_already_exists(
    nighteye_home: Path, cases_dir: Path, tmp_path: Path
) -> None:
    """If a zip is still on disk AND its extraction dir is populated,
    we must NOT re-extract (and must include the existing dir)."""
    case = init_case(name="re-extract", examiner="alice", cases_dir=cases_dir)
    extractions = case.case_dir / "extractions"

    seeded = _seed_extracted_dir(extractions, "host01", "preserved content")
    original_marker = (seeded / ".nighteye_extracted").read_text()
    original_evidence = (seeded / "evidence.txt").read_text()

    # Place a fake zip on the drive — extraction should be skipped because
    # the target dir is already populated.
    drive = tmp_path / "drive"
    drive.mkdir()
    (drive / "host01.zip").write_text("fake zip body, not actually a zip")

    result = extract_archives(drive, recursive=True)

    assert seeded.resolve() in {p.resolve() for p in result}
    # Existing content not clobbered.
    assert (seeded / ".nighteye_extracted").read_text() == original_marker
    assert (seeded / "evidence.txt").read_text() == original_evidence


def test_extract_returns_multiple_existing_extractions(
    nighteye_home: Path, cases_dir: Path, tmp_path: Path
) -> None:
    """Multiple previously-extracted dirs must all surface."""
    case = init_case(name="many", examiner="alice", cases_dir=cases_dir)
    extractions = case.case_dir / "extractions"

    h1 = _seed_extracted_dir(extractions, "WKSTN-01", "data1")
    h2 = _seed_extracted_dir(extractions, "WKSTN-02", "data2")
    h3 = _seed_extracted_dir(extractions, "DC01", "data3")

    empty = tmp_path / "empty"
    empty.mkdir()

    result = extract_archives(empty, recursive=True)
    resolved = {p.resolve() for p in result}
    assert h1.resolve() in resolved
    assert h2.resolve() in resolved
    assert h3.resolve() in resolved


def test_extract_ignores_empty_extraction_dirs(
    nighteye_home: Path, cases_dir: Path, tmp_path: Path
) -> None:
    """An empty extractions/<name>/ (no marker, no content) should NOT be
    treated as 'previously extracted' — that would mask aborted runs."""
    case = init_case(name="aborted", examiner="alice", cases_dir=cases_dir)
    extractions = case.case_dir / "extractions"
    aborted = extractions / "aborted-host"
    aborted.mkdir(parents=True, exist_ok=True)
    # Leave it empty — simulates a previous extraction that crashed
    # before any content was written.

    empty = tmp_path / "empty"
    empty.mkdir()

    result = extract_archives(empty, recursive=True)
    resolved = {p.resolve() for p in result}
    assert aborted.resolve() not in resolved


def test_extract_marker_only_counts_as_extracted(
    nighteye_home: Path, cases_dir: Path, tmp_path: Path
) -> None:
    """A dir with only the marker file (e.g., empty archive) still
    counts as a completed extraction."""
    case = init_case(name="marker-only", examiner="alice", cases_dir=cases_dir)
    extractions = case.case_dir / "extractions"
    d = extractions / "empty-archive-host"
    d.mkdir(parents=True, exist_ok=True)
    (d / ".nighteye_extracted").write_text("source: empty.zip\n")

    empty = tmp_path / "empty"
    empty.mkdir()

    result = extract_archives(empty, recursive=True)
    assert d.resolve() in {p.resolve() for p in result}
