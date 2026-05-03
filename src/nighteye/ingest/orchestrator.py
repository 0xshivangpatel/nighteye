"""Ingest orchestrator — plug-and-play evidence ingestion.

Point NightEye at a directory (external hard disk, KAPE output, etc.)
and it auto-discovers all evidence, detects file types, resolves host
names from directory structure, and streams everything into OpenSearch.

Usage::

    nighteye case init "SRL-2015 Investigation"
    nighteye ingest /mnt/evidence/SRL-2015/
    # That's it. NightEye handles the rest.

The orchestrator:
1. Recursively scans the root path for evidence files
2. Auto-detects host names from directory structure
3. Groups evidence by host and artifact type
4. Routes each to the appropriate parser pipeline
5. Streams documents into OpenSearch with progress reporting
6. Manages index lifecycle (refresh interval, force merge)
7. Updates case metadata with ingest statistics

References:
    - docs/ARCHITECTURE.md § 4 (Layer 1: Wide Evidence Ingestion)
    - docs/BUILD_PLAN.md D5 (EVTX ingest end-to-end)
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from nighteye.ingest.dispatch import (
    DetectedEvidence,
    EvidenceType,
    detect_evidence_type,
    is_suspicious_or_forensic,
)
from nighteye.case import get_case_dir
from nighteye.ingest.ecs import make_index_name

__all__ = [
    "IngestPlan",
    "IngestGroup",
    "IngestResult",
    "build_ingest_plan",
    "resolve_host_name",
    "ingest_evidence",
]

logger = logging.getLogger("nighteye.ingest")


# ============================================================
# Common host directory name patterns in forensic images
# ============================================================

# Patterns that indicate a host-level directory
_HOST_DIR_PATTERNS: list[re.Pattern] = [
    re.compile(r"^(?:WKSTN|WS|DC|SRV|PC|HOST|SERVER|DESKTOP|LAPTOP)[-_]?\d*", re.I),
    re.compile(r"^[A-Z]{2,10}[-_]\d{1,4}$", re.I),  # DC-01, SRV_003
    re.compile(r"^(?:C|D|E|F)_drive$", re.I),         # Mounted drive labels
    re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),  # IP-named dirs
]

# Directories that are NOT hosts (skip these for host resolution)
_NON_HOST_DIRS: frozenset[str] = frozenset({
    "c", "d", "e", "f",  # bare drive letters
    "windows", "system32", "users", "programdata",
    "program files", "program files (x86)",
    "appdata", "local", "roaming", "temp",
    "evidence", "triage", "kape", "output", "results",
    "logs", "evtx", "registry", "memory", "prefetch",
    "timeline", "filesystem", "artifacts",
    "winevt", "config", "regback",
    # Common SRL / FOR508 structure dirs
    "c_drive", "exports", "mounted",
})

# KAPE / triage tool output directory markers
_TRIAGE_MARKERS: frozenset[str] = frozenset({
    "c", "c_drive", "filesystem", "eventlogs",
    "registry", "prefetch", "amcache", "shimcache",
    "srum", "mft", "usnjrnl",
})


# ============================================================
# Data structures
# ============================================================


@dataclass
class IngestGroup:
    """A group of evidence files for a single host + artifact type."""
    host: str
    artifact_type: EvidenceType
    files: list[DetectedEvidence] = field(default_factory=list)
    index_name: str = ""
    doc_count: int = 0
    status: str = "pending"  # pending | ingesting | done | failed
    error: str = ""
    duration_ms: int = 0

    @property
    def total_bytes(self) -> int:
        return sum(f.size_bytes for f in self.files)


@dataclass
class IngestPlan:
    """Complete ingest plan for a directory of evidence.

    Built by ``build_ingest_plan()`` before ingest begins. Shows what
    will be ingested, from where, into which indices.
    """
    roots: list[Path]
    case_id: str
    groups: list[IngestGroup] = field(default_factory=list)
    skipped: list[DetectedEvidence] = field(default_factory=list)
    total_bytes: int = 0
    host_count: int = 0
    auto_detected: bool = True

    def summary(self) -> dict[str, Any]:
        """Human-readable summary for CLI output."""
        hosts = sorted(set(g.host for g in self.groups))
        type_counts: dict[str, int] = {}
        for g in self.groups:
            key = g.artifact_type.value
            type_counts[key] = type_counts.get(key, 0) + len(g.files)

        return {
            "roots": [str(r) for r in self.roots],
            "case_id": self.case_id,
            "hosts": hosts,
            "host_count": len(hosts),
            "groups": len(self.groups),
            "files_by_type": type_counts,
            "total_files": sum(len(g.files) for g in self.groups),
            "total_bytes": self.total_bytes,
            "total_bytes_human": _human_bytes(self.total_bytes),
            "skipped": len(self.skipped),
        }


@dataclass
class IngestResult:
    """Result of executing an ingest plan."""
    plan: IngestPlan
    total_docs_indexed: int = 0
    total_errors: int = 0
    duration_s: float = 0.0
    groups_completed: int = 0
    groups_failed: int = 0


# ============================================================
# Host name resolution
# ============================================================


def resolve_host_name(
    evidence_path: Path,
    root: Path,
    explicit_host: str | None = None,
) -> str:
    """Resolve the host name for an evidence file.

    Resolution order:
    1. Explicit ``--host`` flag (always wins)
    2. KAPE-style triage output structure detection
    3. Directory name heuristics (look for host-like parent dirs)
    4. Fallback to the root directory name

    Common forensic directory structures detected:
    - ``/evidence/DC01/C/Windows/System32/winevt/Logs/Security.evtx``
      → host = "DC01"
    - ``/kape_output/DC01/filesystem/C/...`` → host = "DC01"
    - ``/SRL-2015/DC01/...`` → host = "DC01"
    - ``/evidence/10.0.0.5/...`` → host = "10.0.0.5"

    Args:
        evidence_path: Path to the evidence file.
        root: Root directory of the ingest scan.
        explicit_host: If provided, use this host name directly.

    Returns:
        Resolved host name (lowercased, sanitized).
    """
    if explicit_host:
        return _sanitize_host(explicit_host)

    # Get the relative path from root to the evidence file
    try:
        rel = evidence_path.relative_to(root)
    except ValueError:
        rel = evidence_path

    parts = list(rel.parts)

    # Strategy 1: Look for KAPE/triage structure markers
    # e.g., DC01/C/Windows/... or DC01/filesystem/C/...
    for i, part in enumerate(parts):
        lower = part.lower()
        if lower in _TRIAGE_MARKERS and i > 0:
            # The directory BEFORE the triage marker is likely the host
            candidate = parts[i - 1]
            if _is_host_like(candidate):
                return _sanitize_host(candidate)

    # Strategy 2: Look for host-like directory names in the path
    for part in parts:
        if _is_host_like(part):
            return _sanitize_host(part)

    # Strategy 2.5: Extract a real hostname from the TOP-LEVEL extraction dir
    # E.g., "win7-32-nromanoff-10.3.58.5_nighteye" → find "nromanoff"
    # Only search in parts before we hit deep system directories
    for part in parts:
        if part.lower() in _NON_HOST_DIRS or part.lower() in _TRIAGE_MARKERS:
            break  # Don't scan into system directories
        # Skip nighteye extraction directories themselves
        if "nighteye" in part.lower():
            continue
        segments = part.lower().replace("_", "-").split("-")
        for seg in segments:
            bad = {"nighteye", "win7", "win", "xp", "c", "drive", "32", "64", "86"}
            if seg in bad or seg.isdigit():
                continue
            if len(seg) >= 3 and any(c.isalpha() for c in seg):
                return _sanitize_host(seg)

    # Strategy 2.6: Extract IP from directory name fragments (lower priority than real hostnames)
    # E.g., "win7-32-nromanoff-10.3.58.5_nighteye" → "10.3.58.5"
    for part in parts:
        if "nighteye" in part.lower():
            continue
        import re as _re
        ip_match = _re.search(r"(\d{1,3}[\.\-]\d{1,3}[\.\-]\d{1,3}[\.\-]\d{1,3})", part)
        if ip_match:
            ip = ip_match.group(1).replace("-", ".")
            octets = ip.split(".")
            if len(octets) == 4 and all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
                return _sanitize_host(ip)

    # Strategy 3: First non-root directory
    if len(parts) >= 2:
        candidate = parts[0]
        if candidate.lower() not in _NON_HOST_DIRS:
            return _sanitize_host(candidate)

    # Fallback: root directory name
    return _sanitize_host(root.name) if root.name else "unknown-host"


def _is_host_like(name: str) -> bool:
    """Check if a directory name looks like a hostname."""
    lower = name.lower()

    # Skip known non-host directories
    if lower in _NON_HOST_DIRS:
        return False

    # Check against known host patterns
    for pattern in _HOST_DIR_PATTERNS:
        if pattern.match(name):
            return True

    # Heuristic: short alphanumeric with at least one letter and one digit
    if 2 <= len(name) <= 20:
        has_alpha = any(c.isalpha() for c in name)
        has_digit = any(c.isdigit() for c in name)
        if has_alpha and has_digit and re.match(r'^[\w-]+$', name):
            return True

    return False


def _sanitize_host(name: str) -> str:
    """Sanitize a host name for use in index names."""
    clean = name.lower().strip()
    # Preserve dots in valid IPv4 addresses; otherwise replace non-alphanum with dash
    import re as _re
    ipv4_match = _re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", clean)
    if ipv4_match:
        return clean
    clean = _re.sub(r'[^a-z0-9\-]', '-', clean)
    clean = _re.sub(r'-+', '-', clean).strip('-')
    return clean or "unknown-host"


# ============================================================
# Ingest plan builder
# ============================================================


def build_ingest_plan(
    roots: Path | list[Path],
    case_id: str,
    explicit_host: str | None = None,
    exclude_types: set[EvidenceType] | None = None,
    recursive: bool = True,
) -> IngestPlan:
    """Scan a directory and build a complete ingest plan.

    This is the "plug and play" entry point: point at a directory with
    100-200GB of forensic data and it figures out everything.

    Args:
        roots: Root directory or list of directories to scan.
        case_id: Case ID for index naming.
        explicit_host: If provided, all evidence is attributed to this host.
            Otherwise, hosts are auto-detected from directory structure.
        exclude_types: Evidence types to skip (e.g. UNKNOWN).

    Returns:
        An IngestPlan ready for execution.
    """
    # Normalize: accept a single Path or a list
    if isinstance(roots, Path):
        roots = [roots]
    
    exclude = exclude_types or set()  # include UNKNOWN files — metadata fallback indexes them
    plan = IngestPlan(roots=roots, case_id=case_id)

    # Phase 1: Discover all evidence files
    discovered: list[tuple[DetectedEvidence, Path]] = []

    for root in roots:
        if not root.exists():
            logger.warning("Evidence path does not exist: %s", root)
            continue

        if root.is_file():
            detected = detect_evidence_type(root)
            discovered.append((detected, root))
        else:
            # Evidence scan
            # SMART RECURSION: Always recurse into "extractions" folders (they are safe/isolated)
            # but respect the 'recursive' flag for the external evidence drive.
            is_extraction = "extractions" in str(root).lower()
            effective_recursive = True if is_extraction else recursive
            
            scan_fn = root.rglob if effective_recursive else root.glob
            archive_exts = {".zip", ".7z", ".rar", ".tar", ".gz", ".e01", ".ex01", ".e02"}
            for item in sorted(scan_fn("*")):
                if item.is_file():
                    if item.suffix.lower() in archive_exts:
                        continue
                    detected = detect_evidence_type(item)
                    # Filter: skip known-system UNKNOWN files (.exe from System32 etc.)
                    if not is_suspicious_or_forensic(detected.evidence_type, item):
                        continue
                    discovered.append((detected, root))
                elif item.is_dir():
                    # Check if directory contains recognized evidence bundles
                    detected = detect_evidence_type(item)
                    if detected.evidence_type != EvidenceType.UNKNOWN:
                        discovered.append((detected, root))

    # Phase 2: Group by host + artifact type
    groups_map: dict[tuple[str, EvidenceType], IngestGroup] = {}

    for evidence, ev_root in discovered:
        if evidence.evidence_type in exclude:
            plan.skipped.append(evidence)
            continue

        host = resolve_host_name(evidence.path, ev_root, explicit_host)
        key = (host, evidence.evidence_type)

        if key not in groups_map:
            index_name = make_index_name(
                case_id, evidence.evidence_type.value, host
            )
            groups_map[key] = IngestGroup(
                host=host,
                artifact_type=evidence.evidence_type,
                index_name=index_name,
            )

        groups_map[key].files.append(evidence)

    # Phase 3: Build the plan
    plan.groups = sorted(
        groups_map.values(),
        key=lambda g: (g.host, g.artifact_type.value),
    )
    plan.total_bytes = sum(g.total_bytes for g in plan.groups)
    plan.host_count = len(set(g.host for g in plan.groups))
    plan.auto_detected = explicit_host is None

    logger.info(
        "Ingest plan: %d hosts, %d groups, %d files, %s",
        plan.host_count,
        len(plan.groups),
        sum(len(g.files) for g in plan.groups),
        _human_bytes(plan.total_bytes),
    )

    return plan


# ============================================================
# Helpers
# ============================================================


def ingest_evidence(
    evidence_dir: str,
    case_id: str,
    examiner: str,
    tool_filter: str | None = None,
    force_reingest: bool = False,
) -> dict[str, Any]:
    """High-level wrapper for the entire ingest process.

    This orchestrates:
    1. Archive extraction (E01, ZIP, 7z)
    2. Evidence discovery and type detection
    3. Host name resolution
    4. Parallel ingestion execution

    Args:
        evidence_dir: Directory to scan for evidence
        case_id: ID of the case to ingest into
        examiner: Name of the examiner
        tool_filter: Optional filter for specific artifact types

    Returns:
        Dictionary with ingest statistics
    """
    from nighteye.ingest.executor import execute_ingest_plan
    from nighteye.ingest.extract import extract_archives

    evidence_path = Path(evidence_dir)

    # 1. Extract archives (always recursive for internal safety)
    evidence_path = Path(evidence_dir)
    extractions = extract_archives(evidence_path, recursive=True)
    roots = [evidence_path] + extractions

    # Always include the case's extractions directory if it contains evidence from a
    # previous run — the user may have deleted zip files after first ingest.
    try:
        case_dir = get_case_dir(case_id)
    except Exception:
        case_dir = None
    extractions_dir = (Path(case_dir) / "extractions").resolve() if case_dir else None
    if extractions_dir and extractions_dir.exists() and extractions_dir not in roots:
        has_content = any(extractions_dir.iterdir())
        if has_content:
            roots.append(extractions_dir)

    # 2. Build plan
    plan = build_ingest_plan(
        roots=roots,
        case_id=case_id,
        recursive=True,
    )

    # 3. Filter by tool if requested
    if tool_filter:
        plan.groups = [g for g in plan.groups if g.artifact_type.value == tool_filter]

    # 4. Execute plan
    from nighteye.ingest.opensearch_client import NightEyeOSClient

    client = NightEyeOSClient()
    result = execute_ingest_plan(plan, client, force_reingest=force_reingest)

    stats = {
        "files_processed": len(plan.groups),
        "documents_indexed": result.total_docs_indexed,
        "errors": result.total_errors,
        "hosts_detected": sorted(list(set(g.host for g in plan.groups))),
    }

    return stats


def _human_bytes(n: int) -> str:
    """Convert bytes to human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n = int(n / 1024)
    return f"{n:.1f} PB"
