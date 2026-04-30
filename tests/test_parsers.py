"""Tests for the EZ Tool parsers (D5 part 2).

Verifies that the parsers correctly map CSV/JSON output from EZ Tools
(RECmd, MFTECmd, PECmd, AmcacheParser, AppCompatCacheParser, SrumECmd)
into standardized ECS documents.
"""

from __future__ import annotations

import pytest

from nighteye.ingest.parsers.amcache import parse_amcache_record
from nighteye.ingest.parsers.mft import parse_mft_record
from nighteye.ingest.parsers.prefetch import parse_prefetch_record
from nighteye.ingest.parsers.registry import parse_registry_record
from nighteye.ingest.parsers.shimcache import parse_shimcache_record
from nighteye.ingest.parsers.srum import parse_srum_record


# ============================================================
# Registry parser
# ============================================================


class TestRegistryParser:
    def test_parse_run_key(self) -> None:
        record = {
            "HivePath": "C:\\Windows\\System32\\config\\SOFTWARE",
            "ValueName": "MaliciousUpdater",
            "ValueData": "C:\\temp\\bad.exe",
            "ValueType": "REG_SZ",
            "LastWriteTimestamp": "2026-04-29T14:23:07.000Z",
            "Category": "Autostart",
        }
        doc = parse_registry_record(record, host_name="DC01")
        assert doc is not None
        assert doc["@timestamp"] == "2026-04-29T14:23:07.000Z"
        assert doc["event"]["action"] == "registry-key-modified"
        assert doc["nighteye"]["canonical_type"] == "REGISTRY"
        assert doc["registry.value_data"] == "C:\\temp\\bad.exe"
        assert doc["registry.category"] == "Autostart"

    def test_missing_key_path_returns_none(self) -> None:
        doc = parse_registry_record({"ValueName": "Test"})
        assert doc is None


# ============================================================
# MFT parser
# ============================================================


class TestMftParser:
    def test_parse_mft_entry(self) -> None:
        record = {
            "EntryNumber": "12345",
            "ParentPath": "C:\\Windows\\System32",
            "FileName": "cmd.exe",
            "Extension": ".exe",
            "FileSize": "289792",
            "IsDirectory": "False",
            "Created0x10": "2026-04-01T10:00:00.000Z",
            "LastModified0x10": "2026-04-02T10:00:00.000Z",
        }
        doc = parse_mft_record(record, host_name="DC01")
        assert doc is not None
        assert doc["@timestamp"] == "2026-04-02T10:00:00.000Z"  # Uses modified
        assert doc["file"]["path"] == "C:\\Windows\\System32\\cmd.exe"
        assert doc["nighteye"]["canonical_type"] == "MFT_ENTRY"
        assert doc["mft.file_size"] == 289792
        assert doc["mft.timestomped"] == ""

    def test_timestomp_detection(self) -> None:
        record = {
            "FileName": "bad.exe",
            "Created0x10": "2018-01-01T00:00:00.000Z",  # Fake old date
            "Created0x30": "2026-04-29T14:00:00.000Z",  # Real new date
        }
        doc = parse_mft_record(record)
        assert doc is not None
        assert doc["mft.timestomped"] == "possible"


# ============================================================
# Prefetch parser
# ============================================================


class TestPrefetchParser:
    def test_parse_prefetch_entry(self) -> None:
        record = {
            "ExecutableName": "CMD.EXE",
            "RunCount": "42",
            "LastRun": "2026-04-29T14:23:07.000Z",
            "PreviousRun0": "2026-04-28T10:00:00.000Z",
            "Hash": "1A2B3C4D",
        }
        doc = parse_prefetch_record(record, host_name="DC01")
        assert doc is not None
        assert doc["@timestamp"] == "2026-04-29T14:23:07.000Z"
        assert doc["process"]["name"] == "CMD.EXE"
        assert doc["nighteye"]["canonical_type"] == "PREFETCH"
        assert doc["prefetch.run_count"] == 42
        assert "2026-04-28T10:00:00.000Z" in doc["prefetch.previous_runs"]


# ============================================================
# Amcache parser
# ============================================================


class TestAmcacheParser:
    def test_parse_amcache_entry(self) -> None:
        record = {
            "FullPath": "C:\\temp\\malware.exe",
            "SHA1": "abcdef1234567890",
            "Publisher": "Evil Corp",
            "IsPeFile": "True",
            "FileKeyLastWriteTimestamp": "2026-04-29T14:23:07.000Z",
        }
        doc = parse_amcache_record(record, host_name="DC01")
        assert doc is not None
        assert doc["@timestamp"] == "2026-04-29T14:23:07.000Z"
        assert doc["process"]["name"] == "malware.exe"
        assert doc["process"]["executable"] == "C:\\temp\\malware.exe"
        assert doc["nighteye"]["canonical_type"] == "AMCACHE"
        assert doc["amcache.sha1"] == "abcdef1234567890"


# ============================================================
# Shimcache parser
# ============================================================


class TestShimcacheParser:
    def test_parse_shimcache_entry(self) -> None:
        record = {
            "Path": "C:\\temp\\bad.exe",
            "LastModifiedTimeUTC": "2026-04-29T14:23:07.000Z",
            "Executed": "True",
            "CacheEntryPosition": "1",
        }
        doc = parse_shimcache_record(record, host_name="DC01")
        assert doc is not None
        assert doc["@timestamp"] == "2026-04-29T14:23:07.000Z"
        assert doc["process"]["name"] == "bad.exe"
        assert doc["file"]["path"] == "C:\\temp\\bad.exe"
        assert doc["nighteye"]["canonical_type"] == "SHIMCACHE"
        assert doc["shimcache.executed"] == "True"


# ============================================================
# SRUM parser
# ============================================================


class TestSrumParser:
    def test_parse_srum_entry(self) -> None:
        record = {
            "Timestamp": "2026-04-29T14:23:07.000Z",
            "ExeInfo": "C:\\Windows\\System32\\svchost.exe",
            "BytesSent": "1048576",
            "BytesRecvd": "2048",
            "UserSid": "S-1-5-18",
        }
        doc = parse_srum_record(record, host_name="DC01")
        assert doc is not None
        assert doc["@timestamp"] == "2026-04-29T14:23:07.000Z"
        assert doc["process"]["name"] == "svchost.exe"
        assert doc["user"]["id"] == "S-1-5-18"
        assert doc["nighteye"]["canonical_type"] == "SRUM"
        assert doc["srum.bytes_sent"] == 1048576
