"""Regression tests for the SIFT pipeline failures observed on 2026-05-02.

The full-pipeline run on SIFT produced four classes of bug:

  1. NameError ``name 'detect_evidence_type' is not defined`` raised on
     every IngestGroup, leading to 0 documents indexed.
  2. ``EvidenceType.KAPE_ZIP`` was sent to ``run_ez_tool`` which has no
     mapping and emitted ``No EZ Tool mapped`` for every file.
  3. ``MEMORY_DUMP`` was inferred for non-memory files (timeliner.body,
     *-apihooks.txt, *-apihooks.json) co-located with real memory dumps,
     causing Volatility 3 to fail noisily for each one.
  4. Recognized-but-unsupported types (LNK, JUMPLIST, WIN_TIMELINE,
     PCAP, AUTH_LOG, ...) emitted WARNING-level "Required EZ Tool not
     found" log lines per file.

These tests exercise the executor branches in isolation so that future
regressions are caught.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nighteye.ingest import executor as executor_mod
from nighteye.ingest.dispatch import EvidenceType
from nighteye.ingest.executor import (
    _REAL_MEMORY_EXTENSIONS,
    _is_real_memory_dump,
    _stream_directory,
    _stream_group_docs,
)
from nighteye.ingest.orchestrator import IngestGroup


# ============================================================
# Bug #1: detect_evidence_type must be importable + defined
# ============================================================


def test_detect_evidence_type_is_imported_in_executor() -> None:
    """The previous bug crashed on a NameError for every IngestGroup."""
    assert hasattr(executor_mod, "detect_evidence_type"), (
        "detect_evidence_type must be imported into executor module"
    )
    assert hasattr(executor_mod, "Path"), "Path must be imported into executor module"


# ============================================================
# Bug #2: KAPE_ZIP must NOT be sent to run_ez_tool
# ============================================================


def test_kape_zip_directory_fans_out_via_stream_directory(tmp_path: Path) -> None:
    """A KAPE_ZIP IngestGroup whose evidence is a directory should fan
    out via ``_stream_directory`` rather than calling ``run_ez_tool``.

    We seed a directory with no recognized files; the iterator must
    therefore yield nothing AND must not raise.
    """
    triage_dir = tmp_path / "kape_triage"
    triage_dir.mkdir()
    (triage_dir / "junk.txt").write_text("ignored")

    from nighteye.ingest.dispatch import DetectedEvidence

    group = IngestGroup(
        host="WKSTN-01",
        artifact_type=EvidenceType.KAPE_ZIP,
        index_name="case-test-kape_zip-WKSTN-01",
    )
    group.files.append(
        DetectedEvidence(path=triage_dir, evidence_type=EvidenceType.KAPE_ZIP)
    )

    docs = list(_stream_group_docs(group, case_id="test"))
    # No real artifacts in the dir → empty stream is correct.
    assert docs == []


def test_kape_zip_file_does_not_call_run_ez_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A KAPE_ZIP that's a regular *file* (not a directory) must skip
    cleanly without invoking run_ez_tool, which has no mapping for it."""
    fake_zip = tmp_path / "triage.kape"
    fake_zip.write_bytes(b"PK")

    calls: list[tuple[EvidenceType, Path]] = []

    def fake_run_ez_tool(et: EvidenceType, path: Path):
        calls.append((et, path))
        return iter([])

    monkeypatch.setattr(executor_mod, "run_ez_tool", fake_run_ez_tool)

    from nighteye.ingest.dispatch import DetectedEvidence

    group = IngestGroup(
        host="HOST",
        artifact_type=EvidenceType.KAPE_ZIP,
        index_name="case-test-kape_zip-HOST",
    )
    group.files.append(
        DetectedEvidence(path=fake_zip, evidence_type=EvidenceType.KAPE_ZIP)
    )

    docs = list(_stream_group_docs(group, case_id="test"))
    assert docs == []
    assert calls == [], "run_ez_tool must not be called for KAPE_ZIP"


# ============================================================
# Bug #3: only real memory file extensions trigger Volatility
# ============================================================


@pytest.mark.parametrize(
    "name,is_memory",
    [
        ("dump.mem", True),
        ("dump.raw", True),
        ("DUMP.RAW", True),
        ("snapshot.vmem", True),
        ("crash.dmp", True),
        ("dump.lime", True),
        ("Win7SP1x86-baseline.img", False),     # disk image, not memory
        ("timeliner.body", False),              # Vol2 output, not memory
        ("zeus-apihooks.txt", False),           # text artifact
        ("xp-tdungan-apihooks.json", False),    # JSON artifact
        ("readme.md", False),
        ("evidence.csv", False),
    ],
)
def test_real_memory_dump_filter(name: str, is_memory: bool) -> None:
    assert _is_real_memory_dump(Path(name)) is is_memory


def test_real_memory_extensions_set_is_locked() -> None:
    """The set is small and explicit. Adding new extensions requires
    a code change + a new test row above. Anything else routed through
    MEMORY_DUMP is treated as a false positive."""
    assert ".mem" in _REAL_MEMORY_EXTENSIONS
    assert ".raw" in _REAL_MEMORY_EXTENSIONS
    assert ".dmp" in _REAL_MEMORY_EXTENSIONS
    # Sanity: things that LOOK like memory but aren't.
    assert ".body" not in _REAL_MEMORY_EXTENSIONS
    assert ".txt" not in _REAL_MEMORY_EXTENSIONS
    assert ".json" not in _REAL_MEMORY_EXTENSIONS
    assert ".img" not in _REAL_MEMORY_EXTENSIONS


def test_memory_group_with_text_files_does_not_call_volatility(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When a MEMORY_DUMP group contains non-memory files (.body, .txt),
    Volatility must NOT be invoked on them."""
    body = tmp_path / "timeliner.body"
    body.write_text("not a memory dump")
    apihooks = tmp_path / "zeus-apihooks.txt"
    apihooks.write_text("not a memory dump")

    vol_calls: list[Path] = []

    def fake_run_volatility(path, **kwargs):
        vol_calls.append(path)
        return iter([])

    # Patch the symbols imported lazily inside _run_memory_pipeline.
    import nighteye.ingest.volatility as vol_mod
    monkeypatch.setattr(vol_mod, "is_volatility_available", lambda: True)
    monkeypatch.setattr(vol_mod, "run_volatility", fake_run_volatility)
    import nighteye.ingest.carvers as carvers_mod
    monkeypatch.setattr(carvers_mod, "run_bstrings", lambda *a, **k: iter([]))
    monkeypatch.setattr(carvers_mod, "run_1768", lambda *a, **k: iter([]))
    import nighteye.ingest.memprocfs as mpfs_mod
    monkeypatch.setattr(mpfs_mod, "is_memprocfs_available", lambda: False)

    from nighteye.ingest.dispatch import DetectedEvidence

    group = IngestGroup(
        host="HOST",
        artifact_type=EvidenceType.MEMORY_DUMP,
        index_name="case-test-memory-HOST",
    )
    for p in (body, apihooks):
        group.files.append(DetectedEvidence(path=p, evidence_type=EvidenceType.MEMORY_DUMP))

    docs = list(_stream_group_docs(group, case_id="test"))
    assert docs == []
    assert vol_calls == [], (
        f"Volatility was invoked on non-memory files: {vol_calls}"
    )


def test_memory_group_with_real_dump_runs_volatility(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real .mem file should invoke Volatility."""
    mem = tmp_path / "snapshot.mem"
    mem.write_bytes(b"\x00" * 1024)

    vol_calls: list[Path] = []

    def fake_run_volatility(path, **kwargs):
        vol_calls.append(path)
        return iter([{"event": {"action": "process_listed"}}])

    import nighteye.ingest.volatility as vol_mod
    monkeypatch.setattr(vol_mod, "is_volatility_available", lambda: True)
    monkeypatch.setattr(vol_mod, "run_volatility", fake_run_volatility)
    import nighteye.ingest.carvers as carvers_mod
    monkeypatch.setattr(carvers_mod, "run_bstrings", lambda *a, **k: iter([]))
    monkeypatch.setattr(carvers_mod, "run_1768", lambda *a, **k: iter([]))
    import nighteye.ingest.memprocfs as mpfs_mod
    monkeypatch.setattr(mpfs_mod, "is_memprocfs_available", lambda: False)

    from nighteye.ingest.dispatch import DetectedEvidence

    group = IngestGroup(
        host="HOST",
        artifact_type=EvidenceType.MEMORY_DUMP,
        index_name="case-test-memory-HOST",
    )
    group.files.append(DetectedEvidence(path=mem, evidence_type=EvidenceType.MEMORY_DUMP))

    docs = list(_stream_group_docs(group, case_id="test"))
    assert vol_calls == [mem]
    assert len(docs) == 1


# ============================================================
# Bug #4: noisy "EZ Tool not found" warnings for known-unsupported types
# ============================================================


@pytest.mark.parametrize(
    "etype",
    [
        EvidenceType.LNK,
        EvidenceType.JUMPLIST,
        EvidenceType.WIN_TIMELINE,
        EvidenceType.PCAP,
        EvidenceType.AUTH_LOG,
        EvidenceType.SYSLOG,
        EvidenceType.APACHE_LOG,
        EvidenceType.IIS_LOG,
        EvidenceType.RECYCLEBIN,
        EvidenceType.OUTLOOK,
    ],
)
def test_unsupported_types_skip_silently(
    etype: EvidenceType,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Unsupported types must skip silently (debug-level), not warn."""
    f = tmp_path / "artifact.bin"
    f.write_bytes(b"\x00")

    from nighteye.ingest.dispatch import DetectedEvidence

    group = IngestGroup(
        host="HOST",
        artifact_type=etype,
        index_name=f"case-test-{etype.value}-HOST",
    )
    group.files.append(DetectedEvidence(path=f, evidence_type=etype))

    import logging
    caplog.set_level(logging.WARNING, logger="nighteye.ingest.executor")
    docs = list(_stream_group_docs(group, case_id="test"))
    # Unsupported types now emit a metadata doc for provenance tracking
    assert len(docs) == 1, f"Expected 1 metadata doc for {etype}, got {len(docs)}"
    assert docs[0].get("event", {}).get("action") == "evidence-indexed"
    # Remaining assertion about warnings
    warnings = [
        r for r in caplog.records
        if r.levelno >= logging.WARNING
        and r.name == "nighteye.ingest.executor"
    ]
    assert warnings == [], (
        f"Got unexpected warnings for {etype.value}: {[r.message for r in warnings]}"
    )


# ============================================================
# _stream_directory: marker file + unknown types must be skipped
# ============================================================


def test_stream_directory_skips_marker_and_unknown(tmp_path: Path) -> None:
    """The .nighteye_extracted marker and unknown extensions are skipped."""
    d = tmp_path / "extracted"
    d.mkdir()
    (d / ".nighteye_extracted").write_text("source: foo.zip\n")
    (d / "garbage.xyz").write_text("nope")
    docs = list(
        _stream_directory(
            d,
            artifact_type=EvidenceType.KAPE_ZIP,
            case_id="test",
            host_name="HOST",
            source_file=str(d),
            audit_id="audit-1",
        )
    )
    assert docs == []
