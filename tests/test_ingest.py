"""Tests for the ingest pipeline scaffold (D4).

Covers dispatch (file type detection), ECS helpers (index naming,
doc IDs, timestamps, document builder), and index template structure.

These tests are pure-Python and don't require OpenSearch.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from nighteye.ingest.dispatch import (
    DetectedEvidence,
    EvidenceType,
    detect_evidence_type,
    scan_evidence_directory,
)
from nighteye.ingest.ecs import (
    build_ecs_doc,
    compute_doc_id,
    make_index_name,
    normalize_timestamp,
)
from nighteye.ingest.index_template import TEMPLATE_NAME, build_index_template


# ============================================================
# Evidence dispatch
# ============================================================


class TestDetectEvidenceType:

    def test_evtx_file(self, tmp_path: Path) -> None:
        f = tmp_path / "Security.evtx"
        f.write_bytes(b"\x00" * 100)
        result = detect_evidence_type(f)
        assert result.evidence_type == EvidenceType.EVTX_FILE
        assert result.size_bytes == 100

    def test_e01_image(self, tmp_path: Path) -> None:
        f = tmp_path / "disk.E01"
        f.write_bytes(b"\x00" * 50)
        result = detect_evidence_type(f)
        assert result.evidence_type == EvidenceType.E01_IMAGE

    def test_memory_dump_mem(self, tmp_path: Path) -> None:
        f = tmp_path / "memory.mem"
        f.write_bytes(b"\x00" * 50)
        result = detect_evidence_type(f)
        assert result.evidence_type == EvidenceType.MEMORY_DUMP

    def test_memory_dump_dmp(self, tmp_path: Path) -> None:
        f = tmp_path / "lsass.dmp"
        f.write_bytes(b"\x00" * 50)
        result = detect_evidence_type(f)
        assert result.evidence_type == EvidenceType.MEMORY_DUMP

    def test_memory_dump_vmem(self, tmp_path: Path) -> None:
        f = tmp_path / "snapshot.vmem"
        f.write_bytes(b"\x00" * 50)
        result = detect_evidence_type(f)
        assert result.evidence_type == EvidenceType.MEMORY_DUMP

    def test_prefetch_file(self, tmp_path: Path) -> None:
        f = tmp_path / "CMD.EXE-ABC123.pf"
        f.write_bytes(b"\x00" * 50)
        result = detect_evidence_type(f)
        assert result.evidence_type == EvidenceType.PREFETCH

    def test_pcap_file(self, tmp_path: Path) -> None:
        f = tmp_path / "capture.pcap"
        f.write_bytes(b"\x00" * 50)
        result = detect_evidence_type(f)
        assert result.evidence_type == EvidenceType.PCAP

    def test_pcapng_file(self, tmp_path: Path) -> None:
        f = tmp_path / "capture.pcapng"
        f.write_bytes(b"\x00" * 50)
        result = detect_evidence_type(f)
        assert result.evidence_type == EvidenceType.PCAP

    def test_registry_hive_sam(self, tmp_path: Path) -> None:
        f = tmp_path / "SAM"
        f.write_bytes(b"\x00" * 50)
        result = detect_evidence_type(f)
        assert result.evidence_type == EvidenceType.REGISTRY_HIVE

    def test_registry_hive_ntuser(self, tmp_path: Path) -> None:
        f = tmp_path / "NTUSER.DAT"
        f.write_bytes(b"\x00" * 50)
        result = detect_evidence_type(f)
        assert result.evidence_type == EvidenceType.REGISTRY_HIVE

    def test_registry_hive_hve_extension(self, tmp_path: Path) -> None:
        f = tmp_path / "SomeHive.hve"
        f.write_bytes(b"\x00" * 50)
        result = detect_evidence_type(f)
        assert result.evidence_type == EvidenceType.REGISTRY_HIVE

    def test_amcache(self, tmp_path: Path) -> None:
        f = tmp_path / "Amcache.hve"
        f.write_bytes(b"\x00" * 50)
        result = detect_evidence_type(f)
        assert result.evidence_type == EvidenceType.AMCACHE

    def test_mft(self, tmp_path: Path) -> None:
        f = tmp_path / "$MFT"
        f.write_bytes(b"\x00" * 50)
        result = detect_evidence_type(f)
        assert result.evidence_type == EvidenceType.MFT

    def test_srum(self, tmp_path: Path) -> None:
        f = tmp_path / "SRUDB.dat"
        f.write_bytes(b"\x00" * 50)
        result = detect_evidence_type(f)
        assert result.evidence_type == EvidenceType.SRUM

    def test_zip_treated_as_kape(self, tmp_path: Path) -> None:
        f = tmp_path / "triage.zip"
        f.write_bytes(b"\x00" * 50)
        result = detect_evidence_type(f)
        assert result.evidence_type == EvidenceType.KAPE_ZIP

    def test_evtx_folder(self, tmp_path: Path) -> None:
        evtx_dir = tmp_path / "evtx_logs"
        evtx_dir.mkdir()
        (evtx_dir / "Security.evtx").write_bytes(b"\x00" * 100)
        (evtx_dir / "System.evtx").write_bytes(b"\x00" * 200)
        result = detect_evidence_type(evtx_dir)
        assert result.evidence_type == EvidenceType.EVTX_FOLDER
        assert result.size_bytes == 300
        assert "2 EVTX files" in result.note

    def test_empty_dir_is_unknown(self, tmp_path: Path) -> None:
        d = tmp_path / "empty"
        d.mkdir()
        result = detect_evidence_type(d)
        assert result.evidence_type == EvidenceType.UNKNOWN

    def test_unknown_file_type(self, tmp_path: Path) -> None:
        f = tmp_path / "readme.txt"
        f.write_text("hello")
        result = detect_evidence_type(f)
        assert result.evidence_type == EvidenceType.UNKNOWN

    def test_nonexistent_path(self, tmp_path: Path) -> None:
        f = tmp_path / "does_not_exist.evtx"
        result = detect_evidence_type(f)
        assert result.evidence_type == EvidenceType.UNKNOWN
        assert "does not exist" in result.note


class TestScanEvidenceDirectory:

    def test_single_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.evtx"
        f.write_bytes(b"\x00" * 50)
        results = scan_evidence_directory(f)
        assert len(results) == 1
        assert results[0].evidence_type == EvidenceType.EVTX_FILE

    def test_mixed_directory(self, tmp_path: Path) -> None:
        (tmp_path / "logs").mkdir()
        (tmp_path / "logs" / "Security.evtx").write_bytes(b"\x00" * 100)
        results = scan_evidence_directory(tmp_path)
        assert len(results) >= 1
        types = [r.evidence_type for r in results]
        assert EvidenceType.EVTX_FOLDER in types


# ============================================================
# ECS helpers
# ============================================================


class TestMakeIndexName:

    def test_basic_format(self) -> None:
        name = make_index_name("INC-2026-001", "evtx", "DC01")
        assert name == "case-inc-2026-001-evtx-dc01"

    def test_lowercases_everything(self) -> None:
        name = make_index_name("INC-2026-001", "EVTX", "DC01")
        assert name == "case-inc-2026-001-evtx-dc01"

    def test_sanitizes_slashes(self) -> None:
        name = make_index_name("INC/001", "vol-pslist", "host\\01")
        assert "/" not in name
        assert "\\" not in name

    def test_spaces_become_dashes(self) -> None:
        name = make_index_name("My Case", "evtx", "My Host")
        assert " " not in name


class TestComputeDocId:

    def test_deterministic(self) -> None:
        id1 = compute_doc_id("case-1", "evtx", "host", "field1=val1,field2=val2")
        id2 = compute_doc_id("case-1", "evtx", "host", "field1=val1,field2=val2")
        assert id1 == id2

    def test_different_input_different_id(self) -> None:
        id1 = compute_doc_id("case-1", "evtx", "host1", "data")
        id2 = compute_doc_id("case-1", "evtx", "host2", "data")
        assert id1 != id2

    def test_returns_sha256_hex(self) -> None:
        doc_id = compute_doc_id("c", "t", "h", "f")
        assert len(doc_id) == 64
        assert all(c in "0123456789abcdef" for c in doc_id)


class TestNormalizeTimestamp:

    def test_none_returns_none(self) -> None:
        assert normalize_timestamp(None) is None

    def test_empty_string_returns_none(self) -> None:
        assert normalize_timestamp("") is None
        assert normalize_timestamp("  ") is None

    def test_iso_with_z(self) -> None:
        result = normalize_timestamp("2026-04-29T14:23:07.412Z")
        assert result is not None
        assert result.endswith("Z")
        assert "2026-04-29" in result

    def test_iso_with_offset(self) -> None:
        result = normalize_timestamp("2026-04-29T14:23:07+05:30")
        assert result is not None
        assert result.endswith("Z")  # normalized to UTC

    def test_datetime_object(self) -> None:
        dt = datetime(2026, 4, 29, 14, 23, 7, tzinfo=timezone.utc)
        result = normalize_timestamp(dt)
        assert result is not None
        assert "2026-04-29T14:23:07" in result

    def test_naive_datetime_assumed_utc(self) -> None:
        dt = datetime(2026, 4, 29, 14, 23, 7)
        result = normalize_timestamp(dt)
        assert result is not None
        assert result.endswith("Z")

    def test_invalid_string_returns_none(self) -> None:
        assert normalize_timestamp("not-a-date") is None


class TestBuildEcsDoc:

    def test_minimal_doc(self) -> None:
        doc = build_ecs_doc(timestamp="2026-04-29T14:23:07Z", host_name="DC01")
        assert "@timestamp" in doc
        assert doc["host"]["name"] == "DC01"

    def test_empty_fields_excluded(self) -> None:
        doc = build_ecs_doc(host_name="DC01")
        assert "user" not in doc
        assert "process" not in doc
        assert "file" not in doc
        assert "source" not in doc

    def test_full_doc(self) -> None:
        doc = build_ecs_doc(
            timestamp="2026-04-29T14:23:07Z",
            host_name="DC01",
            event_code="4624",
            event_action="logon-success",
            event_category=["authentication"],
            event_outcome="success",
            user_name="admin",
            user_domain="CORP",
            user_id="S-1-5-21-...",
            process_pid=1234,
            process_parent_pid=4,
            process_name="lsass.exe",
            source_ip="10.0.0.5",
            source_port=49152,
            destination_ip="10.0.0.1",
            destination_port=445,
            network_protocol="tcp",
            nighteye_parser="evtxecmd",
            nighteye_audit_id="nighteye-alice-20260429-001",
        )
        assert doc["event"]["code"] == "4624"
        assert doc["user"]["name"] == "admin"
        assert doc["process"]["pid"] == 1234
        assert doc["process"]["parent"]["pid"] == 4
        assert doc["source"]["ip"] == "10.0.0.5"
        assert doc["destination"]["port"] == 445
        assert doc["network"]["protocol"] == "tcp"
        assert doc["nighteye"]["parser"] == "evtxecmd"

    def test_nighteye_extension_fields(self) -> None:
        doc = build_ecs_doc(
            host_name="DC01",
            nighteye_ingest_id="ingest-001",
            nighteye_source_file="/evidence/Security.evtx",
            nighteye_canonical_type="AUTHENTICATION",
            nighteye_verdict="SUSPICIOUS",
            nighteye_evidence_disturbed=True,
        )
        ne = doc["nighteye"]
        assert ne["ingest_id"] == "ingest-001"
        assert ne["source_file"] == "/evidence/Security.evtx"
        assert ne["canonical_type"] == "AUTHENTICATION"
        assert ne["verdict"] == "SUSPICIOUS"
        assert ne["evidence_disturbed"] is True

    def test_extra_fields_merged(self) -> None:
        doc = build_ecs_doc(
            host_name="DC01",
            extra={"custom.field": "value"},
        )
        assert doc["custom.field"] == "value"

    def test_winlog_event_data(self) -> None:
        doc = build_ecs_doc(
            host_name="DC01",
            winlog_event_data={"TargetUserName": "admin", "LogonType": "3"},
        )
        assert doc["winlog"]["event_data"]["LogonType"] == "3"

    def test_process_hash(self) -> None:
        doc = build_ecs_doc(
            host_name="DC01",
            process_hash_sha256="abcdef1234567890",
        )
        assert doc["process"]["hash"]["sha256"] == "abcdef1234567890"

    def test_file_hash(self) -> None:
        doc = build_ecs_doc(
            host_name="DC01",
            file_path="C:\\Windows\\System32\\cmd.exe",
            file_hash_sha256="abc123",
        )
        assert doc["file"]["path"] == "C:\\Windows\\System32\\cmd.exe"
        assert doc["file"]["hash"]["sha256"] == "abc123"


# ============================================================
# Index template
# ============================================================


class TestIndexTemplate:

    def test_template_name(self) -> None:
        assert TEMPLATE_NAME == "nighteye-case"

    def test_template_structure(self) -> None:
        tmpl = build_index_template()
        assert tmpl["index_patterns"] == ["case-*"]
        assert tmpl["priority"] == 100
        settings = tmpl["template"]["settings"]
        assert settings["number_of_shards"] == 1
        assert settings["number_of_replicas"] == 0

    def test_template_has_ecs_mappings(self) -> None:
        tmpl = build_index_template()
        props = tmpl["template"]["mappings"]["properties"]
        assert "@timestamp" in props
        assert props["@timestamp"]["type"] == "date"
        assert "host" in props
        assert "event" in props
        assert "user" in props
        assert "process" in props
        assert "file" in props
        assert "source" in props
        assert "destination" in props

    def test_template_has_nighteye_fields(self) -> None:
        tmpl = build_index_template()
        ne_props = tmpl["template"]["mappings"]["properties"]["nighteye"]["properties"]
        assert "ingest_id" in ne_props
        assert "audit_id" in ne_props
        assert "canonical_type" in ne_props
        assert "verdict" in ne_props
        assert "evidence_disturbed" in ne_props
        assert ne_props["evidence_disturbed"]["type"] == "boolean"

    def test_template_allows_dynamic(self) -> None:
        tmpl = build_index_template()
        assert tmpl["template"]["mappings"]["dynamic"] is True
