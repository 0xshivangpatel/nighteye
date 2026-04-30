"""Evidence file type detection and routing.

Given a path, detect whether it's an E01 image, KAPE triage zip,
EVTX folder/file, memory dump, registry hive, MFT, or other artifact.
Routes each to the appropriate parser pipeline.

References:
    - docs/ARCHITECTURE.md § 4 (Layer 1: Wide Evidence Ingestion)
    - docs/BUILD_PLAN.md D4 (dispatch.py)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

__all__ = [
    "EvidenceType",
    "DetectedEvidence",
    "detect_evidence_type",
    "scan_evidence_directory",
]


class EvidenceType(str, Enum):
    """Recognized evidence file types."""
    E01_IMAGE = "e01"
    EVTX_FILE = "evtx"
    EVTX_FOLDER = "evtx_folder"
    MEMORY_DUMP = "memory"
    REGISTRY_HIVE = "registry"
    MFT = "mft"
    PREFETCH = "prefetch"
    KAPE_ZIP = "kape_zip"
    PCAP = "pcap"
    AMCACHE = "amcache"
    SHIMCACHE = "shimcache"
    SRUM = "srum"
    UNKNOWN = "unknown"


# Extension → type mapping (case-insensitive)
_EXTENSION_MAP: dict[str, EvidenceType] = {
    ".e01": EvidenceType.E01_IMAGE,
    ".evtx": EvidenceType.EVTX_FILE,
    ".mem": EvidenceType.MEMORY_DUMP,
    ".dmp": EvidenceType.MEMORY_DUMP,
    ".vmem": EvidenceType.MEMORY_DUMP,
    ".raw": EvidenceType.MEMORY_DUMP,
    ".pf": EvidenceType.PREFETCH,
    ".pcap": EvidenceType.PCAP,
    ".pcapng": EvidenceType.PCAP,
}

# Known registry hive filenames (no extension)
_REGISTRY_HIVE_NAMES: frozenset[str] = frozenset({
    "sam", "security", "system", "software", "ntuser.dat",
    "usrclass.dat", "default", "components",
})

# Known filename patterns for specific artifact types
_FILENAME_MAP: dict[str, EvidenceType] = {
    "$mft": EvidenceType.MFT,
    "amcache.hve": EvidenceType.AMCACHE,
    "appcompatcache": EvidenceType.SHIMCACHE,
    "srudb.dat": EvidenceType.SRUM,
}


@dataclass
class DetectedEvidence:
    """Result of evidence type detection."""
    path: Path
    evidence_type: EvidenceType
    size_bytes: int = 0
    note: str = ""


def detect_evidence_type(path: Path) -> DetectedEvidence:
    """Detect the evidence type of a single file or directory.

    Detection priority:
    1. Directory containing .evtx files → EVTX_FOLDER
    2. KAPE zip (zip containing triage artifacts) → KAPE_ZIP
    3. Extension-based detection (.e01, .evtx, .mem, etc.)
    4. Filename-based detection ($MFT, Amcache.hve, registry hives)
    5. Unknown

    Args:
        path: Path to the evidence file or directory.

    Returns:
        DetectedEvidence with the identified type.
    """
    if not path.exists():
        return DetectedEvidence(
            path=path,
            evidence_type=EvidenceType.UNKNOWN,
            note="Path does not exist",
        )

    size = 0
    if path.is_file():
        size = path.stat().st_size

    # Directory: check if it's an EVTX folder
    if path.is_dir():
        evtx_files = list(path.rglob("*.evtx"))
        if evtx_files:
            return DetectedEvidence(
                path=path,
                evidence_type=EvidenceType.EVTX_FOLDER,
                size_bytes=sum(f.stat().st_size for f in evtx_files),
                note=f"Contains {len(evtx_files)} EVTX files",
            )
        return DetectedEvidence(
            path=path,
            evidence_type=EvidenceType.UNKNOWN,
            note="Directory without recognized artifacts",
        )

    # Extension-based detection
    ext = path.suffix.lower()
    if ext in _EXTENSION_MAP:
        return DetectedEvidence(
            path=path,
            evidence_type=_EXTENSION_MAP[ext],
            size_bytes=size,
        )

    # KAPE zip detection
    if ext == ".zip":
        return DetectedEvidence(
            path=path,
            evidence_type=EvidenceType.KAPE_ZIP,
            size_bytes=size,
            note="Zip archive — assumed KAPE triage package",
        )

    # Filename-based detection (case-insensitive)
    filename_lower = path.name.lower()
    for pattern, etype in _FILENAME_MAP.items():
        if filename_lower == pattern or filename_lower.startswith(pattern):
            return DetectedEvidence(
                path=path,
                evidence_type=etype,
                size_bytes=size,
            )

    # Registry hive detection (no extension, known names)
    if filename_lower in _REGISTRY_HIVE_NAMES or ext == ".hve":
        return DetectedEvidence(
            path=path,
            evidence_type=EvidenceType.REGISTRY_HIVE,
            size_bytes=size,
        )

    return DetectedEvidence(
        path=path,
        evidence_type=EvidenceType.UNKNOWN,
        size_bytes=size,
        note=f"Unrecognized file type: {ext or '(no extension)'}",
    )


def scan_evidence_directory(root: Path) -> list[DetectedEvidence]:
    """Recursively scan a directory for evidence files.

    Returns a list of DetectedEvidence objects, one per recognized file.
    Unknown files are included but marked as UNKNOWN.

    Args:
        root: Root directory to scan.

    Returns:
        Sorted list of detected evidence items (by type, then path).
    """
    if not root.is_dir():
        # Single file
        return [detect_evidence_type(root)]

    results: list[DetectedEvidence] = []

    # First check if root itself is an EVTX folder
    evtx_files_in_root = list(root.rglob("*.evtx"))
    if evtx_files_in_root:
        # Don't descend into individual files — treat as folder
        results.append(DetectedEvidence(
            path=root,
            evidence_type=EvidenceType.EVTX_FOLDER,
            size_bytes=sum(f.stat().st_size for f in evtx_files_in_root),
            note=f"Contains {len(evtx_files_in_root)} EVTX files",
        ))
    else:
        # Scan individual files
        for item in sorted(root.rglob("*")):
            if item.is_file():
                detected = detect_evidence_type(item)
                results.append(detected)

    return sorted(results, key=lambda d: (d.evidence_type.value, str(d.path)))
