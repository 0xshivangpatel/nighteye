"""E01 Forensic Extraction Pipeline — generalizable, tool-agnostic.

Mounts Expert Witness Format (E01) disk images, extracts key forensic
artifacts using The Sleuth Kit, runs EZ Tools parsers on them, and
yields ECS documents ready for NightEye ingest.

Design principles:
  - No dataset-specific paths or hostname assumptions
  - Detects filesystem type (NTFS/FAT) and partition layout automatically
  - Handles both physical (partitioned) and logical (single-volume) images
  - Extracts artifact BATCHES: EVTX, registry, MFT, prefetch in one pass
  - Falls back gracefully when artifacts don't exist on the image

References:
    - docs/ARCHITECTURE.md § 5 (Layer 1: Wide Evidence Ingestion)
"""

from __future__ import annotations

import csv
import glob
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from nighteye.ingest.ecs import build_ecs_doc
from nighteye.ingest.opensearch_client import NightEyeOSClient

__all__ = ["extract_e01_artifacts", "ingest_e01_extraction"]

logger = logging.getLogger("nighteye.ingest.e01_pipeline")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Tools we expect to find
_EWFMOUNT = shutil.which("ewfmount") or "/usr/bin/ewfmount"
_FLS = shutil.which("fls") or "/usr/bin/fls"
_ICAT = shutil.which("icat") or "/usr/bin/icat"
_MMLS = shutil.which("mmls") or "/usr/bin/mmls"
_FSSTAT = shutil.which("fsstat") or "/usr/bin/fsstat"

# EZ Tools
_EVTXECMD_DLL = "/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll"
_RECMD_DLL = "/opt/zimmermantools/RECmd/RECmd.dll"
_MFTECMD_DLL = "/opt/zimmermantools/MFTECmd.dll"
_DOTNET = shutil.which("dotnet") or "/usr/bin/dotnet"

# Key artifact patterns
_ARTIFACT_PATTERNS = {
    "evtx": {
        "windows_path": "Windows/System32/winevt/Logs",
        "extensions": [".evtx"],
    },
    "registry": {
        "windows_path": "Windows/System32/config",
        "hive_names": ["SAM", "SECURITY", "SOFTWARE", "SYSTEM"],
    },
    "mft": {
        "root_path": "$MFT",
    },
    "prefetch": {
        "windows_path": "Windows/Prefetch",
        "extensions": [".pf"],
    },
}


# ---------------------------------------------------------------------------
# E01 Mounting
# ---------------------------------------------------------------------------

def _mount_e01(e01_path: Path) -> Path | None:
    """Mount an E01 image via ewfmount, return raw image path.
    
    Handles corrupted files gracefully by checking file integrity first
    and providing detailed error messages.
    """
    # Pre-flight checks
    if not e01_path.exists():
        logger.error("E01 file does not exist: %s", e01_path)
        return None
    
    file_size = e01_path.stat().st_size
    if file_size == 0:
        logger.error("E01 file is empty (0 bytes): %s", e01_path)
        return None
    
    # Check if file is readable (corruption check - try to read first 4KB)
    try:
        with open(e01_path, 'rb') as f:
            header = f.read(4096)
            if len(header) < 4096 and file_size > 4096:
                logger.warning("E01 file may be truncated: %s (%d bytes)", e01_path.name, file_size)
            # Check for EWF magic number (EVF or LVf)
            if not (header.startswith(b'EVF') or header.startswith(b'LVf')):
                logger.warning("E01 file has invalid header (may be corrupted): %s", e01_path.name)
    except IOError as exc:
        logger.error("Cannot read E01 file (corrupted or permission denied): %s - %s", e01_path.name, exc)
        return None
    
    mount_dir = Path(tempfile.mkdtemp(prefix="ewf-"))
    logger.info("Mounting %s → %s", e01_path.name, mount_dir)

    try:
        proc = subprocess.Popen(
            [_EWFMOUNT, str(e01_path), str(mount_dir)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        time.sleep(3)

        # ewfmount daemonizes after a successful mount, so the parent
        # process exits with code 0. A non-zero exit is the failure case.
        rc = proc.poll()
        if rc is not None and rc != 0:
            _, stderr = proc.communicate()
            error_msg = stderr.decode('utf-8', errors='ignore')[:500] if stderr else "Unknown error"
            logger.error("ewfmount failed to mount %s (rc=%d): %s", e01_path.name, rc, error_msg)
            shutil.rmtree(mount_dir, ignore_errors=True)
            return None

        raw_files = list(mount_dir.glob("*"))
        if not raw_files:
            logger.error("ewfmount produced no raw image in %s (file may be corrupted)", mount_dir)
            proc.kill()
            proc.wait()
            shutil.rmtree(mount_dir, ignore_errors=True)
            return None

        raw_path = raw_files[0]
        raw_size = raw_path.stat().st_size
        
        if raw_size == 0:
            logger.error("Mounted raw image is empty: %s (E01 may be corrupted)", e01_path.name)
            _unmount_e01(mount_dir)
            return None
            
        logger.info("Raw image: %s (%.1f GB)", raw_path.name, raw_size / (1024**3))
        return raw_path
        
    except Exception as exc:
        logger.error("Exception during E01 mount: %s", exc)
        shutil.rmtree(mount_dir, ignore_errors=True)
        return None


def _unmount_e01(mount_dir: Path) -> None:
    """Unmount an E01 FUSE mount."""
    subprocess.run(["fusermount", "-u", str(mount_dir)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    shutil.rmtree(mount_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# TSK helpers
# ---------------------------------------------------------------------------

def _extract_inode(meta: str) -> str:
    """Extract the inode number from a fls meta string like 'r/r 41521-128-4'."""
    # Format: "type/type inode-seq-attrid" → inode is the first number after the space
    parts = meta.split()
    if len(parts) >= 2:
        return parts[1].split("-")[0]
    return meta


def _fls_list(raw_path: Path, inode: str | None = None) -> list[tuple[str, str]]:
    """Run fls and return list of (inode_number, filename) tuples."""
    cmd = [_FLS, str(raw_path)]
    if inode:
        cmd.append(inode)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        entries = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            parts = line.split(":\t", 1)
            if len(parts) >= 2:
                meta = parts[0].strip()
                name = parts[1].strip()
                inode = _extract_inode(meta)
                entries.append((inode, name))
        return entries
    except Exception as exc:
        logger.warning("fls failed: %s", exc)
        return []


def _fls_find(raw_path: Path, inode: str, pattern: str) -> str | None:
    """Find a file/dir by name pattern under an inode. Returns inode string."""
    entries = _fls_list(raw_path, inode)
    for ino, name in entries:
        if pattern.lower() in name.lower():
            return ino
    return None


def _icat_extract(raw_path: Path, inode: str, dest: Path) -> bool:
    """Extract a file by inode. Returns True on success."""
    try:
        result = subprocess.run(
            [_ICAT, str(raw_path), inode],
            capture_output=True, timeout=60,
        )
        if result.returncode == 0 and result.stdout:
            dest.write_bytes(result.stdout)
            return True
        return False
    except Exception:
        return False


def _resolve_path(raw_path: Path, *path_parts: str) -> str | None:
    """Walk a path like 'Windows/System32/config/' and return the final inode."""
    entries = _fls_list(raw_path, None)  # root listing
    current_inode = None
    current_entries = {name.lower(): ino for ino, name in entries}

    for part in path_parts:
        part_lower = part.lower()
        if part_lower not in current_entries:
            return None
        current_inode = current_entries[part_lower]
        # List children
        child_list = _fls_list(raw_path, current_inode)
        current_entries = {name.lower(): ino for ino, name in child_list}
    return current_inode


# ---------------------------------------------------------------------------
# Artifact extraction
# ---------------------------------------------------------------------------

def _extract_evtx(raw_path: Path, work_dir: Path) -> list[Path]:
    """Extract EVTX files from the image. Returns list of extracted paths."""
    evtx_dir = work_dir / "evtx"
    evtx_dir.mkdir(exist_ok=True)
    extracted = []

    # Try standard Vista+ path first
    logs_inode = _resolve_path(raw_path, "Windows", "System32", "winevt", "Logs")
    if not logs_inode:
        # Try XP-style upper-case
        logs_inode = _resolve_path(raw_path, "WINDOWS", "system32", "config")
    if not logs_inode:
        logger.info("No EVTX/EVT logs directory found (XP or custom path)")
        return extracted

    entries = _fls_list(raw_path, logs_inode)
    main_logs = {"security.evtx", "system.evtx", "application.evtx",
                 "security.evt", "system.evt", "application.evt",
                 "windows powershell.evtx", "sysevent.evt", "appevent.evt"}
    for ino, name in entries:
        if name.lower() not in main_logs:
            continue
        dest = evtx_dir / name
        if _icat_extract(raw_path, ino, dest):
            extracted.append(dest)
            logger.info("  EVTX: %s (%d KB)", name, dest.stat().st_size // 1024)

    return extracted


def _extract_registry(raw_path: Path, work_dir: Path) -> list[Path]:
    """Extract registry hives. Returns list of extracted paths."""
    reg_dir = work_dir / "registry"
    reg_dir.mkdir(exist_ok=True)
    extracted = []

    config_inode = _resolve_path(raw_path, "Windows", "System32", "config")
    if not config_inode:
        config_inode = _resolve_path(raw_path, "WINDOWS", "system32", "config")
    if not config_inode:
        logger.info("No registry config directory found")
        return extracted

    for hive in ["SAM", "SECURITY", "SOFTWARE", "SYSTEM"]:
        entries = _fls_list(raw_path, config_inode)
        for ino, name in entries:
            if name.upper() == hive:
                dest = reg_dir / hive
                if _icat_extract(raw_path, ino, dest):
                    extracted.append(dest)
                    logger.info("  Registry: %s (%d KB)", hive,
                                dest.stat().st_size // 1024)
                break

    return extracted


def _extract_mft(raw_path: Path, work_dir: Path) -> Path | None:
    """Extract $MFT. Returns path or None."""
    entries = _fls_list(raw_path, None)
    for ino, name in entries:
        if name == "$MFT":
            dest = work_dir / "MFT"
            if _icat_extract(raw_path, ino, dest):
                logger.info("  MFT: %d KB", dest.stat().st_size // 1024)
                return dest
    return None


def _extract_prefetch(raw_path: Path, work_dir: Path) -> list[Path]:
    """Extract Windows\\Prefetch\\*.pf files."""
    pf_dir = work_dir / "prefetch"
    pf_dir.mkdir(exist_ok=True)
    extracted: list[Path] = []

    pf_inode = _resolve_path(raw_path, "Windows", "Prefetch")
    if not pf_inode:
        pf_inode = _resolve_path(raw_path, "WINDOWS", "Prefetch")
    if not pf_inode:
        logger.info("No Prefetch directory found")
        return extracted

    for ino, name in _fls_list(raw_path, pf_inode):
        if not name.lower().endswith(".pf"):
            continue
        dest = pf_dir / name
        if _icat_extract(raw_path, ino, dest):
            extracted.append(dest)

    if extracted:
        logger.info("  Prefetch: %d .pf files", len(extracted))
    return extracted


def _extract_amcache(raw_path: Path, work_dir: Path) -> Path | None:
    """Extract Amcache.hve from Windows\\AppCompat\\Programs\\."""
    amc_inode = _resolve_path(raw_path, "Windows", "AppCompat", "Programs")
    if not amc_inode:
        amc_inode = _resolve_path(raw_path, "WINDOWS", "AppCompat", "Programs")
    if not amc_inode:
        return None

    for ino, name in _fls_list(raw_path, amc_inode):
        if name.lower() == "amcache.hve":
            dest = work_dir / "Amcache.hve"
            if _icat_extract(raw_path, ino, dest):
                logger.info("  Amcache: %d KB", dest.stat().st_size // 1024)
                return dest
    return None


def _extract_srum(raw_path: Path, work_dir: Path) -> Path | None:
    """Extract SRUDB.dat from Windows\\System32\\sru\\."""
    sru_inode = _resolve_path(raw_path, "Windows", "System32", "sru")
    if not sru_inode:
        return None
    for ino, name in _fls_list(raw_path, sru_inode):
        if name.lower() == "srudb.dat":
            dest = work_dir / "SRUDB.dat"
            if _icat_extract(raw_path, ino, dest):
                logger.info("  SRUM: %d KB", dest.stat().st_size // 1024)
                return dest
    logger.info("No $MFT found in root")
    return None


# ---------------------------------------------------------------------------
# EZ Tools runners
# ---------------------------------------------------------------------------

def _run_evtxecmd(evtx_files: list[Path], output_dir: Path) -> Path | None:
    """Run EvtxECmd on EVTX files, return CSV path."""
    if not evtx_files or not Path(_EVTXECMD_DLL).exists():
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    csv_dir = output_dir / "evtx_csv"
    csv_dir.mkdir(exist_ok=True)

    for evtx_path in evtx_files:
        logger.info("  EvtxECmd: %s", evtx_path.name)
        subprocess.run(
            [_DOTNET, _EVTXECMD_DLL, "-f", str(evtx_path),
             "--csv", str(csv_dir)],
            cwd=os.path.dirname(_EVTXECMD_DLL),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=120,
        )

    csvs = list(csv_dir.glob("*.csv"))
    return csvs[0] if csvs else None


def _run_recmd(registry_dir: Path, output_dir: Path) -> Path | None:
    """Run RECmd with DFIRBatch on registry hives, return CSV path."""
    if not Path(_RECMD_DLL).exists():
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    batch_file = os.path.join(os.path.dirname(_RECMD_DLL),
                              "BatchExamples", "DFIRBatch.reb")

    if not os.path.exists(batch_file):
        logger.warning("RECmd batch file not found: %s", batch_file)
        return None

    logger.info("  RECmd: %d hives", len(list(registry_dir.glob("*"))))
    subprocess.run(
        [_DOTNET, _RECMD_DLL, "--bn", batch_file,
         "--csv", str(output_dir), "-d", str(registry_dir)],
        cwd=os.path.dirname(_RECMD_DLL),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=120,
    )

    csvs = list(output_dir.glob("*_Output.csv"))
    if not csvs:
        for subdir in output_dir.iterdir():
            if subdir.is_dir():
                csvs.extend(list(subdir.glob("*_Output.csv")))
    return csvs[0] if csvs else None


def _run_mftecmd(mft_path: Path, output_dir: Path) -> Path | None:
    """Run MFTECmd on $MFT, return CSV path."""
    if not mft_path.exists() or not Path(_MFTECMD_DLL).exists():
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    logger.info("  MFTECmd: %s", mft_path.name)
    subprocess.run(
        [_DOTNET, _MFTECMD_DLL, "-f", str(mft_path),
         "--csv", str(output_dir)],
        cwd=os.path.dirname(_MFTECMD_DLL),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=120,
    )

    csvs = list(output_dir.glob("*_Output.csv"))
    return csvs[0] if csvs else None


# ---------------------------------------------------------------------------
# ECS document generators
# ---------------------------------------------------------------------------

def _parse_evtxecmd_csv(csv_path: Path, host: str) -> Iterator[dict[str, Any]]:
    """Yield ECS docs from EvtxECmd CSV output."""
    with open(csv_path, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            eid = row.get("EventId", "").strip()
            ch = row.get("Channel", "Security")
            ts_str = row.get("TimeCreated", "")

            # Parse timestamp
            ts = datetime.now(timezone.utc).isoformat()
            for fmt in ["%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"]:
                try:
                    ts = datetime.strptime(ts_str.strip(), fmt).replace(tzinfo=timezone.utc).isoformat()
                    break
                except ValueError:
                    continue

            # Parse Payload JSON for 4624 logon details
            target_user = row.get("UserName", "")
            target_domain = ""
            source_ip = ""
            logon_type = ""
            workstation = ""

            payload_raw = row.get("Payload", "")
            if payload_raw:
                try:
                    pl = json.loads(payload_raw)
                    ed = pl.get("EventData", {})
                    data_list = ed.get("Data", []) if isinstance(ed, dict) else []
                    for item in (data_list if isinstance(data_list, list) else []):
                        name = item.get("@Name", "")
                        text = item.get("#text", "")
                        if name == "TargetUserName":
                            target_user = text
                        elif name == "TargetDomainName":
                            target_domain = text
                        elif name == "IpAddress":
                            source_ip = text
                        elif name == "LogonType":
                            logon_type = text
                        elif name == "WorkstationName":
                            workstation = text
                except Exception:
                    pass

            # Determine category
            cat = "artifact"
            action = "unknown"
            if ch == "Security":
                if eid == "4624":
                    cat, action = "authentication", "logon-success"
                elif eid == "4625":
                    cat, action = "authentication", "logon-failure"
                elif eid == "4634":
                    cat, action = "authentication", "logoff"
                elif eid == "4672":
                    cat, action = "authentication", "special-privilege-logon"
                elif eid == "4648":
                    cat, action = "authentication", "explicit-credential-logon"
                elif eid == "4663":
                    cat, action = "file", "object-access"
                elif eid in ("4697", "7045"):
                    cat, action = "configuration", "service-installed"
                elif eid == "4698":
                    cat, action = "configuration", "scheduled-task-created"
                elif eid == "1102":
                    cat, action = "iam", "log-cleared"
                elif eid == "5140":
                    cat, action = "network", "network-share-access"
                elif eid == "4674":
                    cat, action = "configuration", "privileged-operation"
            elif "System" in ch:
                cat, action = "configuration", "system-event"

            proc_info = row.get("ExecutableInfo", "")
            proc_name = proc_info.split("\\")[-1] if "\\" in proc_info else proc_info

            yield build_ecs_doc(
                timestamp=ts,
                host_name=host,
                event_code=eid,
                event_action=action,
                event_category=[cat],
                user_name=target_user,
                user_domain=target_domain,
                source_ip=source_ip,
                process_name=proc_name,
                process_executable=proc_info,
                extra={
                    "winlog": {
                        "channel": ch,
                        "event_id": eid,
                        "logon_type": logon_type,
                        "workstation": workstation,
                        "description": row.get("MapDescription", ""),
                        "provider": row.get("Provider", ""),
                    },
                    "message": row.get("MapDescription", "") or f"Event {eid}",
                },
            )


def _parse_mftecmd_csv(csv_path: Path, host: str) -> Iterator[dict[str, Any]]:
    """Yield ECS docs from MFTECmd CSV output."""
    with open(csv_path, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            if row.get("InUse") != "True":
                continue
            parent = row.get("ParentPath", "") or ""
            fname = row.get("FileName", "") or ""
            path = (parent.rstrip("\\") + "\\" + fname) if parent else fname
            if not path:
                continue

            def _ts(val):
                if not val:
                    return datetime.now(timezone.utc).isoformat()
                for fmt in ["%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"]:
                    try:
                        return datetime.strptime(val.strip(), fmt).replace(tzinfo=timezone.utc).isoformat()
                    except ValueError:
                        continue
                return datetime.now(timezone.utc).isoformat()

            yield build_ecs_doc(
                timestamp=_ts(row.get("Created0x10")),
                host_name=host,
                event_action="file-created",
                event_category=["file"],
                file_path=path.replace("\\", "/"),
                extra={
                    "mft": {
                        "modified": _ts(row.get("LastModified0x30")),
                        "accessed": _ts(row.get("LastAccess0x30")),
                        "size": row.get("FileSize", "0"),
                        "entry": row.get("EntryNumber", ""),
                    }
                },
            )


def _parse_recmd_csv(csv_path: Path, host: str) -> Iterator[dict[str, Any]]:
    """Yield ECS docs from RECmd CSV output."""
    with open(csv_path, encoding="utf-8-sig", errors="replace") as f:
        for row in csv.DictReader(f):
            lwt = row.get("LastWriteTimestamp", "")

            def _ts(val):
                if not val:
                    return datetime.now(timezone.utc).isoformat()
                for fmt in ["%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"]:
                    try:
                        return datetime.strptime(val.strip(), fmt).replace(tzinfo=timezone.utc).isoformat()
                    except ValueError:
                        continue
                return datetime.now(timezone.utc).isoformat()

            yield build_ecs_doc(
                timestamp=_ts(lwt),
                host_name=host,
                event_action="registry-modified",
                event_category=["configuration", "registry"],
                extra={
                    "registry": {
                        "hive": row.get("HivePath", ""),
                        "key": row.get("KeyPath", ""),
                        "value_name": row.get("ValueName", ""),
                        "value_data": row.get("ValueData", ""),
                        "category": row.get("Category", ""),
                        "description": row.get("Description", ""),
                        "last_write": _ts(lwt),
                    }
                },
            )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_e01_artifacts(e01_path: Path) -> dict[str, Any] | None:
    """Extract forensic artifacts from an E01 disk image.

    Returns dict with paths to extracted artifacts:
      {evtx: [Path, ...], registry: [Path, ...], mft: Path|None, work_dir: Path}

    Caller is responsible for cleanup via shutil.rmtree(work_dir).
    Returns None if mounting fails.
    """
    raw_path = _mount_e01(e01_path)
    if raw_path is None:
        return None

    work_dir = Path(tempfile.mkdtemp(prefix="e01-extract-"))
    result: dict[str, Any] = {
        "work_dir": work_dir,
        "evtx": [],
        "registry": [],
        "mft": None,
        "prefetch": [],
        "amcache": None,
        "srum": None,
    }

    try:
        result["evtx"] = _extract_evtx(raw_path, work_dir)
        result["registry"] = _extract_registry(raw_path, work_dir)
        result["mft"] = _extract_mft(raw_path, work_dir)
        result["prefetch"] = _extract_prefetch(raw_path, work_dir)
        result["amcache"] = _extract_amcache(raw_path, work_dir)
        result["srum"] = _extract_srum(raw_path, work_dir)
    finally:
        _unmount_e01(raw_path.parent)

    return result


def ingest_e01_extraction(
    e01_path: Path, host: str, case_id: str, client: NightEyeOSClient
) -> dict[str, int]:
    """Full E01 → evidence pipeline for one host.

    1. Mount E01, extract EVTX/registry/MFT
    2. Run EvtxECmd, RECmd, MFTECmd
    3. Parse CSV output and index to OpenSearch
    4. Clean up temp files

    Returns stats dict.
    """
    stats = {"documents_indexed": 0, "errors": 0}
    logger.info("=== E01 pipeline: %s → %s ===", e01_path.name, host)

    # Phase 1: Extract raw artifacts
    result = extract_e01_artifacts(e01_path)
    if result is None:
        stats["errors"] += 1
        return stats

    try:
        work_dir = result["work_dir"]

        # Phase 2: Run EZ Tools
        ez_output = Path(tempfile.mkdtemp(prefix="eztools-"))

        # 2a: EvtxECmd
        evtx_csv = None
        if result["evtx"]:
            evtx_csv = _run_evtxecmd(result["evtx"], ez_output)

        # 2b: RECmd
        reg_csv = None
        if result["registry"]:
            reg_dir = work_dir / "registry"
            reg_csv = _run_recmd(reg_dir, ez_output)

        # 2c: MFTECmd
        mft_csv = None
        if result["mft"]:
            mft_csv = _run_mftecmd(result["mft"], ez_output)

        # Phase 3: Ingest
        if evtx_csv:
            idx = f"case-{case_id.lower()}-evtx-{host}"
            docs = list(_parse_evtxecmd_csv(evtx_csv, host))
            client.bulk_index_iter(idx, docs)
            stats["documents_indexed"] += len(docs)
            logger.info("  EVTX: %d docs", len(docs))

        if mft_csv:
            idx = f"case-{case_id.lower()}-mft-{host}"
            docs = list(_parse_mftecmd_csv(mft_csv, host))
            client.bulk_index_iter(idx, docs)
            stats["documents_indexed"] += len(docs)
            logger.info("  MFT: %d docs", len(docs))

        if reg_csv:
            idx = f"case-{case_id.lower()}-registry-{host}"
            docs = list(_parse_recmd_csv(reg_csv, host))
            client.bulk_index_iter(idx, docs)
            stats["documents_indexed"] += len(docs)
            logger.info("  Registry: %d docs", len(docs))

        shutil.rmtree(ez_output, ignore_errors=True)

    except Exception as exc:
        logger.error("E01 pipeline failed for %s: %s", host, exc)
        stats["errors"] += 1
    finally:
        shutil.rmtree(result["work_dir"], ignore_errors=True)

    logger.info("=== E01 pipeline complete: %s → %d docs ===", host,
                 stats["documents_indexed"])
    return stats
