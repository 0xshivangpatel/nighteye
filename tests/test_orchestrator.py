"""Tests for the ingest orchestrator (plug-and-play ingestion).

Covers:
- Host name resolution from various forensic directory structures
- Evidence grouping by host + artifact type
- Ingest plan building (single file, mixed dirs, KAPE output, SRL layout)
- Explicit host override
- Edge cases (empty dirs, nonexistent paths, unknown types)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nighteye.ingest.dispatch import EvidenceType
from nighteye.ingest.orchestrator import (
    IngestPlan,
    build_ingest_plan,
    resolve_host_name,
)


# ============================================================
# Host name resolution
# ============================================================


class TestResolveHostName:

    def test_explicit_host_wins(self, tmp_path: Path) -> None:
        f = tmp_path / "DC01" / "Security.evtx"
        f.parent.mkdir()
        f.write_bytes(b"\x00")
        assert resolve_host_name(f, tmp_path, explicit_host="MY-HOST") == "my-host"

    def test_srl_style_dc01(self, tmp_path: Path) -> None:
        """SRL-2015 layout: /evidence/DC01/C/Windows/.../Security.evtx"""
        evtx = tmp_path / "DC01" / "C" / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx"
        evtx.parent.mkdir(parents=True)
        evtx.write_bytes(b"\x00")
        host = resolve_host_name(evtx, tmp_path)
        assert host == "dc01"

    def test_srl_style_wkstn(self, tmp_path: Path) -> None:
        evtx = tmp_path / "WKSTN-01" / "C" / "Windows" / "System32" / "Security.evtx"
        evtx.parent.mkdir(parents=True)
        evtx.write_bytes(b"\x00")
        host = resolve_host_name(evtx, tmp_path)
        assert host == "wkstn-01"

    def test_kape_output_structure(self, tmp_path: Path) -> None:
        """KAPE output: /output/DC01/filesystem/C/Windows/.../Security.evtx"""
        evtx = tmp_path / "DC01" / "filesystem" / "C" / "Windows" / "Security.evtx"
        evtx.parent.mkdir(parents=True)
        evtx.write_bytes(b"\x00")
        host = resolve_host_name(evtx, tmp_path)
        assert host == "dc01"

    def test_ip_based_directory(self, tmp_path: Path) -> None:
        evtx = tmp_path / "10.0.0.5" / "logs" / "Security.evtx"
        evtx.parent.mkdir(parents=True)
        evtx.write_bytes(b"\x00")
        host = resolve_host_name(evtx, tmp_path)
        assert host == "10-0-0-5"

    def test_server_style_name(self, tmp_path: Path) -> None:
        evtx = tmp_path / "SRV-003" / "C" / "Security.evtx"
        evtx.parent.mkdir(parents=True)
        evtx.write_bytes(b"\x00")
        host = resolve_host_name(evtx, tmp_path)
        assert host == "srv-003"

    def test_desktop_style_name(self, tmp_path: Path) -> None:
        evtx = tmp_path / "DESKTOP-ABC123" / "evtx" / "Security.evtx"
        evtx.parent.mkdir(parents=True)
        evtx.write_bytes(b"\x00")
        host = resolve_host_name(evtx, tmp_path)
        assert host == "desktop-abc123"

    def test_fallback_to_first_dir(self, tmp_path: Path) -> None:
        """When no host-like dir found, use first non-system directory."""
        evtx = tmp_path / "mycasedir" / "Security.evtx"
        evtx.parent.mkdir(parents=True)
        evtx.write_bytes(b"\x00")
        host = resolve_host_name(evtx, tmp_path)
        assert host == "mycasedir"

    def test_sanitizes_special_chars(self, tmp_path: Path) -> None:
        evtx = tmp_path / "DC 01 (copy)" / "Security.evtx"
        evtx.parent.mkdir(parents=True)
        evtx.write_bytes(b"\x00")
        host = resolve_host_name(evtx, tmp_path, explicit_host="DC 01 (copy)")
        assert " " not in host
        assert "(" not in host

    def test_skips_system_dirs(self, tmp_path: Path) -> None:
        """Windows, System32, etc. are not hosts."""
        evtx = tmp_path / "Windows" / "System32" / "winevt" / "Security.evtx"
        evtx.parent.mkdir(parents=True)
        evtx.write_bytes(b"\x00")
        host = resolve_host_name(evtx, tmp_path)
        # Should NOT return "windows" or "system32"
        assert host not in ("windows", "system32", "winevt")


# ============================================================
# Ingest plan building
# ============================================================


class TestBuildIngestPlan:

    def test_single_evtx_file(self, tmp_path: Path) -> None:
        f = tmp_path / "Security.evtx"
        f.write_bytes(b"\x00" * 1000)
        plan = build_ingest_plan(f, case_id="INC-001")
        assert len(plan.groups) == 1
        assert plan.groups[0].artifact_type == EvidenceType.EVTX_FILE

    def test_srl_style_multi_host(self, tmp_path: Path) -> None:
        """Simulate SRL-2015: 4 hosts with EVTX + registry."""
        for host in ("DC01", "RD-01", "WKSTN-01", "WKSTN-02"):
            evtx_dir = tmp_path / host / "C" / "Windows" / "System32" / "winevt" / "Logs"
            evtx_dir.mkdir(parents=True)
            (evtx_dir / "Security.evtx").write_bytes(b"\x00" * 500)
            (evtx_dir / "System.evtx").write_bytes(b"\x00" * 300)

            reg_dir = tmp_path / host / "C" / "Windows" / "System32" / "config"
            reg_dir.mkdir(parents=True)
            (reg_dir / "SAM").write_bytes(b"\x00" * 100)
            (reg_dir / "SYSTEM").write_bytes(b"\x00" * 200)

        plan = build_ingest_plan(tmp_path, case_id="SRL-2015")
        summary = plan.summary()

        assert summary["host_count"] == 4
        assert summary["total_files"] >= 16  # 4 hosts × 4 files

    def test_explicit_host_overrides_detection(self, tmp_path: Path) -> None:
        for subdir in ("some", "nested", "dir"):
            d = tmp_path / subdir
            d.mkdir(exist_ok=True)
            tmp_path = d
        f = tmp_path / "Security.evtx"
        f.write_bytes(b"\x00" * 100)

        plan = build_ingest_plan(
            f.parent.parent.parent.parent,
            case_id="INC-001",
            explicit_host="MYHOST",
        )
        for group in plan.groups:
            assert group.host == "myhost"

    def test_index_naming_follows_convention(self, tmp_path: Path) -> None:
        f = tmp_path / "DC01" / "Security.evtx"
        f.parent.mkdir()
        f.write_bytes(b"\x00" * 100)
        plan = build_ingest_plan(tmp_path, case_id="INC-2026-001")

        for group in plan.groups:
            assert group.index_name.startswith("case-")
            assert "inc-2026-001" in group.index_name

    def test_skips_unknown_types(self, tmp_path: Path) -> None:
        (tmp_path / "readme.txt").write_text("hello")
        (tmp_path / "notes.pdf").write_bytes(b"\x00" * 50)
        (tmp_path / "Security.evtx").write_bytes(b"\x00" * 100)

        plan = build_ingest_plan(tmp_path, case_id="INC-001")
        types = [g.artifact_type for g in plan.groups]
        assert EvidenceType.UNKNOWN not in types
        assert len(plan.skipped) >= 2

    def test_empty_directory(self, tmp_path: Path) -> None:
        d = tmp_path / "empty"
        d.mkdir()
        plan = build_ingest_plan(d, case_id="INC-001")
        assert len(plan.groups) == 0

    def test_nonexistent_path(self, tmp_path: Path) -> None:
        plan = build_ingest_plan(tmp_path / "nope", case_id="INC-001")
        assert len(plan.groups) == 0

    def test_summary_includes_human_readable_size(self, tmp_path: Path) -> None:
        f = tmp_path / "big.evtx"
        f.write_bytes(b"\x00" * 1_048_576)  # 1MB
        plan = build_ingest_plan(f, case_id="INC-001")
        summary = plan.summary()
        assert "MB" in summary["total_bytes_human"] or "KB" in summary["total_bytes_human"]

    def test_mixed_evidence_types_grouped(self, tmp_path: Path) -> None:
        """Different artifact types for the same host create separate groups."""
        host_dir = tmp_path / "DC01"
        host_dir.mkdir()
        (host_dir / "Security.evtx").write_bytes(b"\x00" * 100)
        (host_dir / "memory.mem").write_bytes(b"\x00" * 200)
        (host_dir / "SAM").write_bytes(b"\x00" * 50)

        plan = build_ingest_plan(tmp_path, case_id="INC-001")
        types = sorted(g.artifact_type.value for g in plan.groups)
        assert len(types) >= 2  # at least EVTX + memory or registry

    def test_exclude_types(self, tmp_path: Path) -> None:
        (tmp_path / "disk.E01").write_bytes(b"\x00" * 100)
        (tmp_path / "Security.evtx").write_bytes(b"\x00" * 100)

        plan = build_ingest_plan(
            tmp_path,
            case_id="INC-001",
            exclude_types={EvidenceType.UNKNOWN, EvidenceType.E01_IMAGE},
        )
        types = [g.artifact_type for g in plan.groups]
        assert EvidenceType.E01_IMAGE not in types

    def test_groups_sorted_by_host_then_type(self, tmp_path: Path) -> None:
        for host in ("WKSTN-02", "DC01", "WKSTN-01"):
            d = tmp_path / host
            d.mkdir()
            (d / "Security.evtx").write_bytes(b"\x00" * 100)

        plan = build_ingest_plan(tmp_path, case_id="INC-001")
        hosts = [g.host for g in plan.groups]
        assert hosts == sorted(hosts)

    def test_plan_auto_detected_flag(self, tmp_path: Path) -> None:
        f = tmp_path / "test.evtx"
        f.write_bytes(b"\x00" * 100)

        plan_auto = build_ingest_plan(tmp_path, case_id="INC-001")
        assert plan_auto.auto_detected is True

        plan_explicit = build_ingest_plan(
            tmp_path, case_id="INC-001", explicit_host="HOST"
        )
        assert plan_explicit.auto_detected is False

    def test_large_scale_50_hosts(self, tmp_path: Path) -> None:
        """Simulate 50-host environment — plan builds quickly."""
        for i in range(50):
            host_dir = tmp_path / f"HOST-{i:03d}"
            host_dir.mkdir()
            (host_dir / "Security.evtx").write_bytes(b"\x00" * 10)

        plan = build_ingest_plan(tmp_path, case_id="SCALE-TEST")
        assert plan.host_count == 50
        assert len(plan.groups) == 50


# ============================================================
# IngestGroup properties
# ============================================================


class TestIngestGroup:

    def test_total_bytes(self, tmp_path: Path) -> None:
        f1 = tmp_path / "a.evtx"
        f1.write_bytes(b"\x00" * 500)
        f2 = tmp_path / "b.evtx"
        f2.write_bytes(b"\x00" * 300)

        plan = build_ingest_plan(tmp_path, case_id="INC-001")
        for group in plan.groups:
            if group.artifact_type == EvidenceType.EVTX_FILE:
                assert group.total_bytes == 800
