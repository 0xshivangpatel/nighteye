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
    ".e01", ".ex01", ".e02", ".raw", ".dd", ".img", ".vmdk", ".vhd", ".vhdx",
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


def _have_ewf() -> bool:
    return shutil.which("ewfmount") is not None


def _have_tsk() -> bool:
    return shutil.which("tsk_recover") is not None and shutil.which("fls") is not None


def _extract_e01(source: Path, out_dir: Path) -> bool:
    """Extract files from an E01 forensic image via ewfmount + tsk_recover.

    On SIFT, ewfmount and sleuthkit are pre-installed. This mounts the
    E01 as a raw device, then uses tsk_recover to extract all files into
    out_dir preserving the original directory structure.
    """
    if not _have_ewf():
        logger.warning("ewfmount not found — cannot extract E01 %s. Install with: sudo apt install ewf-tools", source.name)
        return False
    if not _have_tsk():
        logger.warning("sleuthkit not found — cannot recover files from E01 %s. Install with: sudo apt install sleuthkit", source.name)
        return False

    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nighteye_ewf_") as mount_dir:
        mount_point = Path(mount_dir)
        try:
            # Mount E01 as raw device
            result = subprocess.run(
                ["ewfmount", str(source), str(mount_point)],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode != 0:
                logger.error("ewfmount failed for %s: %s", source.name, result.stderr[:500])
                return False

            # The raw image is at mount_point/ewf1
            raw_image = mount_point / "ewf1"
            if not raw_image.exists():
                logger.error("ewfmount produced no ewf1 device for %s", source.name)
                return False

            # Extract all files with tsk_recover
            logger.info("Recovering files from %s via tsk_recover...", source.name)
            result = subprocess.run(
                ["tsk_recover", str(raw_image), str(out_dir)],
                capture_output=True, text=True, timeout=3600,
            )
            if result.returncode != 0:
                logger.warning("tsk_recover completed with warnings for %s", source.name)

        except subprocess.TimeoutExpired:
            logger.error("E01 extraction timed out for %s", source.name)
            return False
        except Exception as exc:
            logger.error("E01 extraction failed for %s: %s", source.name, exc)
            return False
        finally:
            # Unmount (umount the fuse mount)
            subprocess.run(["fusermount", "-u", str(mount_point)], capture_output=True, timeout=30)

    _write_marker(out_dir, source)
    return True


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

        # Skip nested zips inside already-extracted dirs — these are
        # application data (McAfee agents, etc.), not forensic evidence.
        # Check for _nighteye/ or \_nighteye\ (dir separator before marker name).
        if "_nighteye/" in source_key.lower() or "_nighteye\\" in source_key.lower():
            logger.debug("Skipping nested zip inside extraction: %s", source.name)
            continue

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
