"""Counter-evidence baselines — whitelist hashes, known-good paths.

Loads MD5 hash whitelists from Redline precooked data and known-good
Windows system paths. Provides counter-signal evaluators that can fire
REFUTED verdicts on clusters when evidence matches known-good baselines.

References:
    - docs/ARCHITECTURE.md § 8 (Counter-Signals)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("nighteye.constructors.counter_evidence")

# ---------------------------------------------------------------------------
# Known-good hash baseline (loaded at module import)
# ---------------------------------------------------------------------------

_KNOWN_GOOD_MD5: set[str] = set()

# Canonical Windows system paths (processes here are usually legitimate)
_SYSTEM_PATHS: frozenset[str] = frozenset({
    "\\windows\\system32\\", "\\windows\\syswow64\\",
    "\\program files\\", "\\program files (x86)\\",
    "\\windows\\winsxs\\",
})

# Processes that legitimately live in System32
_SYSTEM32_PROCESSES: frozenset[str] = frozenset({
    "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe",
    "services.exe", "spoolsv.exe", "winlogon.exe", "explorer.exe",
    "taskhost.exe", "dwm.exe", "conhost.exe", "rundll32.exe",
    "taskmgr.exe", "regedit.exe", "cmd.exe", "powershell.exe",
    "msiexec.exe", "wuauclt.exe", "trustedinstaller.exe",
})


def load_whitelist(whitelist_path: Path) -> int:
    """Load a Mandiant Redline MD5 whitelist file. Returns count of hashes loaded."""
    if not whitelist_path.exists():
        logger.warning("Whitelist not found: %s", whitelist_path)
        return 0

    count = 0
    with open(whitelist_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Format is just MD5 per line
            if len(line) == 32 and all(c in "0123456789abcdef" for c in line.lower()):
                _KNOWN_GOOD_MD5.add(line.lower())
                count += 1

    logger.info("Loaded %d known-good MD5 hashes from %s", count, whitelist_path.name)
    return count


def load_all_whitelists(base_dir: Path) -> int:
    """Find and load all m-whitelist-*.txt files under base_dir. Returns total count."""
    total = 0
    for p in base_dir.rglob("m-whitelist-*.txt"):
        total += load_whitelist(p)
    return total


def _auto_load_whitelists() -> int:
    """Try to auto-load whitelists from common SRL 2015 paths."""
    paths = [
        Path("/media/sansforensics/Aeon_s HDD/Hackathon/SRL 2015"),
    ]
    total = 0
    for base in paths:
        if base.exists():
            total += load_all_whitelists(base)
    return total


_WHITELIST_LOADED = False
_REDLINE_MD5_MAP: dict[str, str] = {}  # path → md5


def _ensure_whitelist_loaded() -> int:
    """Lazy-load whitelists and Redline MD5 map on first access."""
    global _WHITELIST_LOADED
    if _WHITELIST_LOADED:
        return len(_KNOWN_GOOD_MD5)
    _WHITELIST_LOADED = True
    total = _auto_load_whitelists()
    _load_redline_md5_map()
    logger.info("Counter-evidence loaded: %d known-good hashes, %d path→MD5 entries",
                total, len(_REDLINE_MD5_MAP))
    return total


def _load_redline_md5_map() -> None:
    """Extract path→MD5 mappings from Redline .mans ProcessSections table."""
    import sqlite3 as _sql
    candidates = [
        Path("/media/sansforensics/Aeon_s HDD/Hackathon/SRL 2015/win7-32-nromanoff-10.3.58.5_nighteye/win7-32-nromanoff-c-drive/precooked/redline/nromanoff.mans"),
        Path("/media/sansforensics/Aeon_s HDD/Hackathon/SRL 2015/xp-tdungan-10.3.58.7_nighteye/xp-tdungan-c-drive/precooked/redline/xp_tdungan.mans"),
    ]
    total = 0
    for mans_path in candidates:
        if not mans_path.exists():
            continue
        try:
            conn = _sql.connect(str(mans_path))
            # ProcessSections has SectionPath + MD5
            for row in conn.execute(
                "SELECT SectionPath, MD5 FROM ProcessSections WHERE MD5 IS NOT NULL AND MD5 != ''"
            ):
                path = (row[0] or "").strip()
                md5 = (row[1] or "").strip().lower()
                if path and len(md5) == 32:
                    # Normalize: lowercase, backslashes
                    norm = path.lower().replace("/", "\\")
                    _REDLINE_MD5_MAP[norm] = md5
                    total += 1
            # Also try Drivers table
            try:
                for row in conn.execute(
                    "SELECT DriverPath, MD5 FROM Drivers WHERE MD5 IS NOT NULL AND MD5 != ''"
                ):
                    path = (row[0] or "").strip()
                    md5 = (row[1] or "").strip().lower()
                    if path and len(md5) == 32:
                        norm = path.lower().replace("/", "\\")
                        if norm not in _REDLINE_MD5_MAP:
                            _REDLINE_MD5_MAP[norm] = md5
                            total += 1
            except _sql.OperationalError:
                pass
            conn.close()
        except Exception as exc:
            logger.debug("Redline MD5 load skipped for %s: %s", mans_path.name, exc)
    if total:
        logger.info("Loaded %d path→MD5 entries from Redline .mans files", total)


def is_known_good_hash(md5: str) -> bool:
    """Check if an MD5 hash is in the known-good whitelist."""
    _ensure_whitelist_loaded()
    return md5.lower() in _KNOWN_GOOD_MD5
    """Find and load all m-whitelist-*.txt files under base_dir. Returns total count."""
    total = 0
    for p in base_dir.rglob("m-whitelist-*.txt"):
        total += load_whitelist(p)
    return total


# ---------------------------------------------------------------------------
# Counter-signal evaluators — usable by any constructor
# ---------------------------------------------------------------------------

def counter_known_good_hash(cluster: Any, db: Any) -> tuple[bool, str]:
    """Check if any process in the cluster has a known-good MD5 hash.

    Checks three sources:
    1. event.raw_data["process"]["hash"]["md5"]
    2. Redline .mans ProcessSections → path→MD5 lookup
    3. Direct MD5 from event fields

    Returns (applies, evidence_text).
    """
    _ensure_whitelist_loaded()
    from nighteye.canonical.types import CanonicalType
    for evt in cluster.events:
        if evt.canonical_type != CanonicalType.PROCESS_EXECUTION:
            continue
        proc_path = (evt.process_path or "").lower().replace("/", "\\")
        
        # 1. Direct MD5 from raw data
        raw = evt.raw_data or {}
        md5 = (raw.get("process", {}).get("hash", {}).get("md5", "")
               or raw.get("process_hash", "")
               or raw.get("hash", "")
               or raw.get("md5", ""))
        if md5 and is_known_good_hash(md5):
            return True, f"Process {evt.process_name} has known-good MD5 {md5}"
        
        # 2. Path→MD5 lookup from Redline .mans
        if proc_path and proc_path in _REDLINE_MD5_MAP:
            md5 = _REDLINE_MD5_MAP[proc_path]
            if is_known_good_hash(md5):
                return True, f"Process {evt.process_name} at {proc_path} matched known-good MD5 {md5} (Redline)"
        
        # 3. File name match in Redline map
        proc_name = (evt.process_name or "").lower()
        if proc_path and proc_name:
            for rpath, md5 in _REDLINE_MD5_MAP.items():
                if proc_name in rpath and rpath.endswith(proc_path.rstrip("\\").split("\\")[-1]):
                    if is_known_good_hash(md5):
                        return True, f"Process {proc_name} matched {rpath} MD5={md5} (known-good)"
    return False, ""


def counter_system_legitimate_path(cluster: Any, db: Any) -> tuple[bool, str]:
    """Check if the process runs from a legitimate system path.

    Only fires when the process binary is DIRECTLY in a system
    directory — not in a subdirectory (e.g., system32\\svchost.exe
    is legitimate; system32\\dllhost\\svchost.exe is masquerading).
    Returns (applies, evidence_text).
    """
    from nighteye.canonical.types import CanonicalType
    for evt in cluster.events:
        if evt.canonical_type != CanonicalType.PROCESS_EXECUTION:
            continue
        proc_path = (evt.process_path or "").lower().replace("/", "\\")
        proc_name = (evt.process_name or "").lower()

        if not proc_path or not proc_name:
            continue

        if proc_name not in _SYSTEM32_PROCESSES:
            continue

        for sys_path in _SYSTEM_PATHS:
            if sys_path not in proc_path:
                continue
            # Check that the binary is DIRECTLY in the system path
            prefix_end = proc_path.index(sys_path) + len(sys_path)
            remaining = proc_path[prefix_end:]
            # If remaining contains a backslash → binary is in a subdirectory
            if "\\" in remaining:
                continue
            # Binary must match the expected name
            if not remaining.endswith(proc_name):
                continue
            return True, (
                f"Process {proc_name} at {proc_path} is a legitimate "
                f"Windows system binary directly in {sys_path}"
            )
    return False, ""
