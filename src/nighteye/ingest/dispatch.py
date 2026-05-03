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
    "is_suspicious_or_forensic",
]


class EvidenceType(str, Enum):
    """Recognized evidence file types."""
    E01_IMAGE = "e01"
    EVTX_FILE = "evtx"
    EVTX_FOLDER = "evtx_folder"
    MEMORY_DUMP = "memory"
    REGISTRY_HIVE = "registry"
    MFT = "mft"
    USN_JOURNAL = "usn_journal"
    LOGFILE = "logfile"            # NTFS $LogFile
    PREFETCH = "prefetch"
    KAPE_ZIP = "kape_zip"
    PCAP = "pcap"
    AMCACHE = "amcache"
    SHIMCACHE = "shimcache"
    SRUM = "srum"
    JUMPLIST = "jumplist"
    LNK = "lnk"
    SHELLBAG = "shellbag"
    RECYCLEBIN = "recyclebin"
    WIN_TIMELINE = "win_timeline"  # ActivitiesCache.db
    BROWSER_HISTORY = "browser_history"
    OUTLOOK = "outlook"            # PST / OST
    SYSLOG = "syslog"
    AUTH_LOG = "auth_log"
    BASH_HISTORY = "bash_history"
    AUDITD = "auditd"
    IIS_LOG = "iis_log"
    APACHE_LOG = "apache_log"
    SCHEDULED_TASK_XML = "scheduled_task_xml"
    SYSMON_CONFIG = "sysmon_config"
    UNKNOWN = "unknown"


# Extension → type mapping (case-insensitive)
_EXTENSION_MAP: dict[str, EvidenceType] = {
    ".e01": EvidenceType.E01_IMAGE,
    ".ex01": EvidenceType.E01_IMAGE,
    ".e02": EvidenceType.E01_IMAGE,
    ".evtx": EvidenceType.EVTX_FILE,
    ".mem": EvidenceType.MEMORY_DUMP,
    ".dmp": EvidenceType.MEMORY_DUMP,
    ".vmem": EvidenceType.MEMORY_DUMP,
    ".raw": EvidenceType.MEMORY_DUMP,
    ".lime": EvidenceType.MEMORY_DUMP,
    ".pf": EvidenceType.PREFETCH,
    ".pcap": EvidenceType.PCAP,
    ".pcapng": EvidenceType.PCAP,
    ".cap": EvidenceType.PCAP,
    ".lnk": EvidenceType.LNK,
    ".pst": EvidenceType.OUTLOOK,
    ".ost": EvidenceType.OUTLOOK,
    ".automaticdestinations-ms": EvidenceType.JUMPLIST,
    ".customdestinations-ms": EvidenceType.JUMPLIST,
    ".csv": EvidenceType.WIN_TIMELINE,   # bodyfile / supertimeline / volatility output
    ".json": EvidenceType.WIN_TIMELINE,  # volatility JSON / redline JSON output
    ".jsonl": EvidenceType.WIN_TIMELINE,
    # Executable types — metadata-indexed for path/timestamp evidence
    ".exe": EvidenceType.UNKNOWN,
    ".dll": EvidenceType.UNKNOWN,
    ".sys": EvidenceType.UNKNOWN,
    ".bat": EvidenceType.UNKNOWN,
    ".cmd": EvidenceType.UNKNOWN,
    ".vbs": EvidenceType.UNKNOWN,
    ".ps1": EvidenceType.UNKNOWN,
    ".js": EvidenceType.UNKNOWN,
    ".vbe": EvidenceType.UNKNOWN,
    ".scr": EvidenceType.UNKNOWN,
    ".msi": EvidenceType.UNKNOWN,
    ".dat": EvidenceType.UNKNOWN,
    # Document types — metadata-indexed for content context
    ".doc": EvidenceType.UNKNOWN,
    ".docx": EvidenceType.UNKNOWN,
    ".xls": EvidenceType.UNKNOWN,
    ".xlsx": EvidenceType.UNKNOWN,
    ".pdf": EvidenceType.UNKNOWN,
    ".txt": EvidenceType.UNKNOWN,
    ".rtf": EvidenceType.UNKNOWN,
    ".log": EvidenceType.UNKNOWN,
}

# Known registry hive filenames (no extension)
_REGISTRY_HIVE_NAMES: frozenset[str] = frozenset({
    "sam", "security", "system", "software", "ntuser.dat",
    "usrclass.dat", "default", "components", "schema.dat",
    "drivers", "elam",
})

# Known filename patterns for specific artifact types
_FILENAME_MAP: dict[str, EvidenceType] = {
    "$mft": EvidenceType.MFT,
    "$j": EvidenceType.USN_JOURNAL,
    "$usnjrnl": EvidenceType.USN_JOURNAL,
    "$logfile": EvidenceType.LOGFILE,
    "amcache.hve": EvidenceType.AMCACHE,
    "appcompatcache": EvidenceType.SHIMCACHE,
    "srudb.dat": EvidenceType.SRUM,
    "activitiescache.db": EvidenceType.WIN_TIMELINE,
    "history": EvidenceType.BROWSER_HISTORY,
    "places.sqlite": EvidenceType.BROWSER_HISTORY,
    "webcachev01.dat": EvidenceType.BROWSER_HISTORY,
    "auth.log": EvidenceType.AUTH_LOG,
    "secure": EvidenceType.AUTH_LOG,
    "syslog": EvidenceType.SYSLOG,
    "messages": EvidenceType.SYSLOG,
    ".bash_history": EvidenceType.BASH_HISTORY,
    "audit.log": EvidenceType.AUDITD,
    "shellbag": EvidenceType.SHELLBAG,
}

# Path-substring hints (case-insensitive, matched against full path)
_PATH_SUBSTRING_HINTS: list[tuple[str, EvidenceType]] = [
    ("$recycle.bin", EvidenceType.RECYCLEBIN),
    ("recyclebin", EvidenceType.RECYCLEBIN),
    ("/scheduled tasks/", EvidenceType.SCHEDULED_TASK_XML),
    ("\\scheduled tasks\\", EvidenceType.SCHEDULED_TASK_XML),
    ("/automaticdestinations/", EvidenceType.JUMPLIST),
    ("\\automaticdestinations\\", EvidenceType.JUMPLIST),
    ("/customdestinations/", EvidenceType.JUMPLIST),
    ("/iis/logs/", EvidenceType.IIS_LOG),
    ("\\inetpub\\logs\\", EvidenceType.IIS_LOG),
    ("/apache2/", EvidenceType.APACHE_LOG),
    ("/httpd/", EvidenceType.APACHE_LOG),
    ("/shimcache/", EvidenceType.SHIMCACHE),
    ("\\shimcache\\", EvidenceType.SHIMCACHE),
    ("/volatility/", EvidenceType.MEMORY_DUMP),
    ("/memory/", EvidenceType.MEMORY_DUMP),
    ("/timeline/", EvidenceType.WIN_TIMELINE),
    ("\\timeline\\", EvidenceType.WIN_TIMELINE),
    ("/redline/", EvidenceType.WIN_TIMELINE),
    ("\\redline\\", EvidenceType.WIN_TIMELINE),
    ("/precooked/",  EvidenceType.KAPE_ZIP),  # Treat precooked as triage bundle — scan contents recursively
]

# Directory-level detection: if dir contains X type of files, treat as Y
_DIR_CONTENT_HINTS: list[tuple[str, EvidenceType]] = [
    (".evtx", EvidenceType.EVTX_FOLDER),
    (".pf", EvidenceType.PREFETCH),
    ("$mft", EvidenceType.MFT),
    ("sam", EvidenceType.REGISTRY_HIVE),
    ("system", EvidenceType.REGISTRY_HIVE),
    ("software", EvidenceType.REGISTRY_HIVE),
    ("amcache.hve", EvidenceType.AMCACHE),
    ("srudb.dat", EvidenceType.SRUM),
]


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

    # Directory: check if it contains recognized evidence patterns
    if path.is_dir():
        size = 0
        # Check for each content pattern
        for pattern, etype in _DIR_CONTENT_HINTS:
            if pattern.startswith("."):
                # Extension match
                files = list(path.rglob(f"*{pattern}"))
            else:
                # Filename match (case-insensitive)
                files = [
                    f for f in path.rglob("*")
                    if f.is_file() and f.name.lower() == pattern.lower()
                ]
            if files:
                total_size = sum(f.stat().st_size for f in files)
                return DetectedEvidence(
                    path=path,
                    evidence_type=etype,
                    size_bytes=total_size,
                    note=f"Contains {len(files)} {pattern} files",
                )

        # Check path hints for directories
        full_path_lower = str(path).lower().replace("\\", "/")
        for needle, etype in _PATH_SUBSTRING_HINTS:
            if needle.replace("\\", "/") in full_path_lower:
                # For precooked/triage dirs, return as KAPE_ZIP (will be processed as triage)
                return DetectedEvidence(
                    path=path,
                    evidence_type=etype,
                    size_bytes=0,
                    note=f"Matched directory hint: {needle}",
                )

        # Fall through: let individual files inside this dir be detected
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

    # Path-substring hints (e.g. anything inside $Recycle.Bin, IIS log dirs)
    full_path_lower = str(path).lower().replace("\\", "/")
    for needle, etype in _PATH_SUBSTRING_HINTS:
        if needle.replace("\\", "/") in full_path_lower:
            return DetectedEvidence(
                path=path,
                evidence_type=etype,
                size_bytes=size,
                note=f"Matched path hint: {needle}",
            )

    # Scheduled Task XML (Windows Task Scheduler stores as XML in
    # \Windows\System32\Tasks\). Detected by content sniff fallback.
    if ext == ".xml" and "tasks" in full_path_lower:
        return DetectedEvidence(
            path=path,
            evidence_type=EvidenceType.SCHEDULED_TASK_XML,
            size_bytes=size,
        )

    return DetectedEvidence(
        path=path,
        evidence_type=EvidenceType.UNKNOWN,
        size_bytes=size,
        note=f"Unrecognized file type: {ext or '(no extension)'}",
    )


# Directories whose contents are known benign — skip UNKNOWN files here
_SKIP_SYSTEM_DIRS: frozenset[str] = frozenset({
    "windows\\system32", "windows\\syswow64", "windows\\winsxs",
    "windows\\servicing", "windows\\assembly", "windows\\microsoft.net",
    "windows\\softwaredistribution", "windows\\fonts", "windows\\globalization",
    "windows\\resources", "windows\\csc",
    "program files", "program files (x86)", "programdata\\microsoft",
    "programdata\\package cache",
})

# Executable extensions that are always interesting regardless of location
_ALWAYS_INTERESTING_EXTS: frozenset[str] = frozenset({
    ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".wsf",
})

# Extensions that are only interesting in suspicious directories
_UNKNOWN_EXTS: frozenset[str] = frozenset({
    ".exe", ".dll", ".sys", ".scr", ".msi", ".dat",
    ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".rtf",
    ".xml", ".cfg", ".ini", ".inf",
})

# Substrings that indicate a suspicious location for executables
_SUSPICIOUS_PATH_PARTS: tuple[str, ...] = (
    "\\temp\\", "\\tmp\\", "\\downloads\\", "\\appdata\\",
    "\\programdata\\", "\\users\\public\\", "\\recycler\\", "\\recycle.bin",
    "\\startup\\", "\\start menu\\programs\\startup",
    "\\tasks\\", "\\prefetch\\", "\\windows\\tasks",
    "\\perflogs\\", "\\system volume information",
)


def is_suspicious_or_forensic(evidence_type: EvidenceType, path: Path) -> bool:
    """Return True if this file should be ingested.

    Known forensic artifacts (evtx, registry, mft, prefetch, etc.) always pass.
    UNKNOWN files (.exe, .dll, .sys, .bat, etc.) pass only if:
      - They're scripts (.bat/.ps1/.vbs/.js) — always interesting
      - They're in suspicious directories (Temp, AppData, Downloads, etc.)
      - They're NOT in known benign system directories

    This filters out millions of harmless Windows system files while
    retaining executables in unusual locations that could be malware.
    """
    # Always ingest known forensic types
    if evidence_type != EvidenceType.UNKNOWN:
        return True

    path_lower = str(path).lower().replace("\\", "/")
    ext = path.suffix.lower()

    # Scripts are always suspicious — they don't belong in system dirs
    if ext in _ALWAYS_INTERESTING_EXTS:
        return True

    # Skip files in known system directories
    for sys_dir in _SKIP_SYSTEM_DIRS:
        if sys_dir in path_lower:
            return False

    # For executables/documents: only ingest from suspicious locations
    if ext in _UNKNOWN_EXTS:
        for suspicious in _SUSPICIOUS_PATH_PARTS:
            if suspicious in path_lower:
                return True
        # Not in a suspicious location — skip
        return False

    # All other unknown extensions: ingest (they might be relevant)
    return True


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
