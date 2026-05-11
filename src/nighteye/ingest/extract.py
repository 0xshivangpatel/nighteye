"""Automatic Archive & Image Extractor.

Pre-processes raw evidence containers (ZIP, 7z, RAR, E01, ...) into
``case/extractions/<archive_stem>/`` directories that downstream parsers
can scan. Designed to be **idempotent**: running ingest a second time
after the original archives have been deleted or moved still surfaces
the previously-extracted contents.

Two responsibilities:
  1. Extract any new archives discovered in the target_dir.
  2. Always return every directory under ``case/extractions/`` that
     looks like extracted evidence, regardless of whether the source
     archive is still on disk.

A non-empty extracted dir is identified by either having any subfile or
by carrying a ``.nighteye_extracted`` marker file written at the time of
extraction (so we can distinguish a partial/aborted extraction).
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from nighteye.case import get_active_case_dir, get_case_dir

logger = logging.getLogger("nighteye.ingest.extract")

ARCHIVE_EXTS: frozenset[str] = frozenset({
    ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".tar.gz", ".tar.bz2",
})
IMAGE_EXTS: frozenset[str] = frozenset({
    # Disk image formats that have container/archive structure 7z can crack.
    # Raw images (.raw, .img, .dd, .001) are not archives — they pass through
    # to dispatch which routes them as MEMORY_DUMP or RAW disk depending on
    # filename hints. Trying to 7z-extract them produces a fatal error.
    ".e01", ".ex01", ".e02", ".vmdk", ".vhd", ".vhdx",
})
E01_EXTS: frozenset[str] = frozenset({".e01", ".ex01", ".e02"})

_MARKER_FILENAME = ".nighteye_extracted"

# Per-run cache of paths that failed extraction — don't retry these
# within the same process lifetime. Cleared on restart.
_failed_extraction_cache: dict[str, bool] = {}


# ============================================================
# Helpers
# ============================================================


def _resolve_extractions_dir() -> Path | None:
    """Return the case extractions/ directory, or None if no case is active."""
    case_dir = get_active_case_dir()
    if case_dir is None:
        try:
            case_dir = get_case_dir()
        except Exception:
            return None
    if case_dir is None:
        return None
    extractions = Path(case_dir) / "extractions"
    extractions.mkdir(parents=True, exist_ok=True)
    return extractions


def _is_archive(path: Path) -> bool:
    """Whether the file is a known archive."""
    if not path.is_file():
        return False
    name = path.name.lower()
    if name.endswith(".tar.gz") or name.endswith(".tar.bz2"):
        return True
    return path.suffix.lower() in ARCHIVE_EXTS


def _is_image(path: Path) -> bool:
    """Whether the file is a forensic image (non-E01, use 7zip)."""
    if not path.is_file():
        return False
    if path.suffix.lower() in E01_EXTS:
        return False  # E01 handled by ewfmount
    return path.suffix.lower() in IMAGE_EXTS


def _has_marker(out_dir: Path) -> bool:
    return (out_dir / _MARKER_FILENAME).exists()


def _write_marker(out_dir: Path, source: Path) -> None:
    try:
        (out_dir / _MARKER_FILENAME).write_text(
            f"source: {source.name}\n", encoding="utf-8"
        )
    except OSError:
        # Marker is best-effort; don't fail the extraction over it.
        pass


def _has_any_content(out_dir: Path) -> bool:
    """A directory counts as 'extracted' if it contains any non-marker file."""
    if not out_dir.is_dir():
        return False
    for child in out_dir.iterdir():
        if child.name == _MARKER_FILENAME:
            continue
        return True
    return False


def _output_dir_for(source: Path) -> Path:
    """Determine extraction output directory: next to source on same filesystem.

    Extracts into ``<source_dir>/<archive_stem>_nighteye/`` alongside the
    archive so disk space is consumed on the external drive, not the VM.
    Falls back to the case extractions dir only if the source directory
    is not writable.
    """
    same_drive = source.parent
    name = source.stem
    if source.suffixes[-2:] == [".tar", ".gz"] or source.suffixes[-2:] == [".tar", ".bz2"]:
        name = source.name.replace(".tar.gz", "").replace(".tar.bz2", "")
    out_dir = same_drive / f"{name}_nighteye"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        # Test writability
        (out_dir / ".write_test").touch()
        (out_dir / ".write_test").unlink()
        return out_dir
    except (OSError, PermissionError):
        pass
    # Fallback to case extractions dir
    extractions_dir = _resolve_extractions_dir()
    if extractions_dir:
        return extractions_dir / name
    # Last resort: same drive, may fail on write
    return out_dir


def _have_7z() -> bool:
    return shutil.which("7z") is not None or shutil.which("7zz") is not None


def _seven_zip_binary() -> str:
    return shutil.which("7z") or shutil.which("7zz") or "7z"


def _extract_one(source: Path, out_dir: Path) -> bool:
    """Run 7zip on `source` into `out_dir`. Returns True on success."""
    if not _have_7z():
        logger.error(
            "7zip is not installed; cannot extract %s. Install p7zip-full "
            "(Linux) or 7-Zip (Windows) and retry.",
            source.name,
        )
        return False
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            [_seven_zip_binary(), "x", str(source), f"-o{out_dir}", "-y"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        logger.error("7zip failed to extract %s: %s", source.name, exc)
        return False
    _write_marker(out_dir, source)
    return True


def _have_plaso() -> bool:
    return shutil.which("log2timeline.py") is not None and shutil.which("psort.py") is not None


# Comprehensive Windows artifact filters for DFIR-relevant data.
# Covers execution, persistence, temp/startup locations, registry,
# event logs, recycle bin, and system caches.
_PLASO_ARTIFACT_FILTERS = (
    "WindowsEventLogs,"
    "WindowsPrefetchFiles,"
    "WindowsRegistrySystem,"
    "WindowsRegistrySoftware,"
    "WindowsRegistrySecurity,"
    "WindowsRegistrySAM,"
    "WindowsRecycleBin,"
    "WindowsRecycleBinMetadata,"
    "WindowsShimCache,"
    "WindowsAMCacheHveFile,"
    "WindowsActivitiesCacheDatabase,"
    "WindowsTempDirectories,"
    "WindowsStartupFolders,"
    "WindowsStartupFolderModification,"
    "WindowsScheduledTasks,"
    "WindowsSharedTaskScheduler,"
    "WindowsStartupScript,"
    "WindowsEnvironmentVariableTemp"
)


def _extract_e01(source: Path, out_dir: Path) -> bool:
    """Extract forensic artifacts from an E01 image using Plaso.

    Instead of tsk_recover (which extracts millions of benign system
    files and often misses key forensic artifacts), we run Plaso with
    targeted artifact filters.  Plaso produces a structured timeline CSV
    that the generic ingest pipeline can parse directly.

    The resulting ``plaso.csv`` is placed in
    ``out_dir/precooked/timeline/plaso.csv`` so that ``build_ingest_plan``
    discovers it as a ``WIN_TIMELINE`` artifact.
    """
    if not _have_plaso():
        logger.warning(
            "Plaso (log2timeline.py / psort.py) not found — cannot process E01 %s. "
            "Install with: sudo apt install plaso-tools", source.name
        )
        return False

    out_dir.mkdir(parents=True, exist_ok=True)
    plaso_store = out_dir / "_nighteye.plaso"
    timeline_dir = out_dir / "precooked" / "timeline"
    timeline_dir.mkdir(parents=True, exist_ok=True)
    csv_path = timeline_dir / "plaso.csv"

    try:
        # 1. Run log2timeline.py with artifact filters
        logger.info("Running Plaso log2timeline on %s ...", source.name)
        result = subprocess.run(
            [
                "log2timeline.py",
                "--artifact_filters", _PLASO_ARTIFACT_FILTERS,
                "--storage-file", str(plaso_store),
                str(source),
            ],
            capture_output=True, text=True, timeout=7200,
        )
        if result.returncode != 0:
            logger.error(
                "log2timeline.py failed for %s: %s",
                source.name, result.stderr[-800:]
            )
            return False

        # 2. Export to l2tcsv
        logger.info("Exporting Plaso timeline for %s ...", source.name)
        result = subprocess.run(
            [
                "psort.py",
                "-o", "l2tcsv",
                "-w", str(csv_path),
                str(plaso_store),
            ],
            capture_output=True, text=True, timeout=3600,
        )
        if result.returncode != 0:
            logger.error(
                "psort.py failed for %s: %s",
                source.name, result.stderr[-800:]
            )
            return False

        # Clean up the large .plaso store to save disk space
        try:
            plaso_store.unlink()
        except OSError:
            pass

    except subprocess.TimeoutExpired:
        logger.error("Plaso extraction timed out for %s", source.name)
        return False
    except Exception as exc:
        logger.error("Plaso extraction failed for %s: %s", source.name, exc)
        return False

    _write_marker(out_dir, source)
    logger.info(
        "Plaso extraction complete for %s → %s (%s)",
        source.name, csv_path, _human_bytes(csv_path.stat().st_size) if csv_path.exists() else "0 B"
    )
    return True


def _human_bytes(n: int) -> str:
    """Convert bytes to human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n = int(n / 1024)
    return f"{n:.1f} PB"


# ============================================================
# Public API
# ============================================================


def extract_archives(target_dir: Path, recursive: bool = True) -> list[Path]:
    """Scan and extract supported archives, returning all extraction dirs.

    Extractions go alongside the source archive on the same filesystem
    (e.g. HDD) so the VM disk is not consumed. Falls back to the case
    extractions dir only if the source drive is read-only.

    Smart resolution: if the zip is gone but the extracted directory
    remains, the extracted dir is still returned. If both exist, the
    zip is skipped (already extracted). Always prefers already-extracted
    content over re-extraction.
    """
    target_dir = Path(target_dir)
    extracted: dict[Path, None] = {}

    # ---- Phase 1: discover already-extracted directories ----
    # Look for *_nighteye directories that contain real content.
    # These are the extraction targets (created alongside zips on HDD).
    if target_dir.is_dir():
        scan_fn = target_dir.rglob if recursive else target_dir.glob
        for d in scan_fn("*_nighteye"):
            if d.is_dir() and _has_any_content(d):
                extracted[d.resolve()] = None

        # Also discover via marker dotfiles (`.nighteye_extracted` inside dirs)
        for marker in scan_fn(_MARKER_FILENAME):
            parent = marker.parent
            if parent.is_dir() and _has_any_content(parent):
                extracted[parent.resolve()] = None

    # Also seed from case extractions dir as fallback
    extractions_dir = _resolve_extractions_dir()
    if extractions_dir and extractions_dir.is_dir():
        for child in sorted(extractions_dir.iterdir()):
            if child.is_dir() and (_has_marker(child) or _has_any_content(child)):
                extracted[child.resolve()] = None

    # ---- Phase 2: find archives and extract anything missing ----
    targets: list[Path] = []
    if target_dir.is_file():
        if _is_archive(target_dir) or _is_image(target_dir):
            targets.append(target_dir)
    elif target_dir.is_dir():
        scan_fn = target_dir.rglob if recursive else target_dir.glob
        for ext in (ARCHIVE_EXTS | IMAGE_EXTS):
            for p in scan_fn(f"*{ext}"):
                if p.is_file() and not p.is_symlink():
                    targets.append(p)
            for p in scan_fn(f"*{ext.upper()}"):
                if p.is_file() and not p.is_symlink():
                    targets.append(p)
        for p in scan_fn("*.tar.gz"):
            if p.is_file() and not p.is_symlink():
                targets.append(p)

    try:
        from tqdm import tqdm
        target_iter = tqdm(targets, desc="Extracting evidence", unit="file", leave=False)
    except ImportError:
        target_iter = targets

    for source in target_iter:
        out_dir = _output_dir_for(source)

        if _has_marker(out_dir) or _has_any_content(out_dir):
            logger.info("Skipping already-extracted %s → %s", source.name, out_dir.name)
            extracted[out_dir.resolve()] = None
            continue

        # Skip previously-failed extractions within this run
        source_key = str(source.resolve())
        if source_key in _failed_extraction_cache:
            logger.debug("Skipping previously-failed %s", source.name)
            continue

        # Skip nested ZIPs/RARs/etc inside already-extracted dirs — these
        # are application data (McAfee agents, browser caches), not forensic
        # evidence. BUT forensic images (.E01/.e01/.001/.dd) embedded inside
        # an extracted-zip layout ARE the primary disk image and must be
        # extracted by the next ewfmount/E01 step below.
        if "_nighteye/" in source_key.lower() or "_nighteye\\" in source_key.lower():
            if source.suffix.lower() not in E01_EXTS and not _is_image(source):
                logger.debug("Skipping nested archive inside extraction: %s", source.name)
                continue
            logger.info("Found forensic image inside extraction: %s", source.name)

        if _is_archive(source):
            logger.info("Extracting archive %s -> %s", source.name, out_dir)
            if _extract_one(source, out_dir):
                extracted[out_dir.resolve()] = None
            else:
                _failed_extraction_cache[source_key] = True
        elif source.suffix.lower() in E01_EXTS:
            logger.info("Extracting E01 image %s -> %s via ewfmount", source.name, out_dir)
            if _extract_e01(source, out_dir):
                extracted[out_dir.resolve()] = None
            else:
                _failed_extraction_cache[source_key] = True
        elif _is_image(source):
            logger.info("Extracting image %s -> %s", source.name, out_dir)
            if _extract_one(source, out_dir):
                extracted[out_dir.resolve()] = None
            else:
                _failed_extraction_cache[source_key] = True
                logger.warning(
                    "Could not extract %s with available tools.", source.name
                )

    if not extracted:
        logger.warning("No evidence archives or extracted directories found in %s", target_dir)
    else:
        logger.info("Evidence roots: %d extracted directories available", len(extracted))

    return sorted(extracted.keys())
