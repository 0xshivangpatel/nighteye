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
from pathlib import Path

from nighteye.case import get_active_case_dir, get_case_dir

logger = logging.getLogger("nighteye.ingest.extract")

ARCHIVE_EXTS: frozenset[str] = frozenset({
    ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".tar.gz", ".tar.bz2",
})
IMAGE_EXTS: frozenset[str] = frozenset({
    ".e01", ".raw", ".dd", ".img", ".vmdk", ".vhd", ".vhdx",
})

# Marker placed at the root of every successful extraction. Re-runs use
# this to prove an extraction completed, distinguishing it from a
# partial/aborted one.
_MARKER_FILENAME = ".nighteye_extracted"


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
    """Whether the file is a forensic image."""
    if not path.is_file():
        return False
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


def _existing_extractions(extractions_dir: Path) -> list[Path]:
    """List every subdir in extractions/ that holds previously-extracted data."""
    out: list[Path] = []
    if not extractions_dir.is_dir():
        return out
    for child in sorted(extractions_dir.iterdir()):
        if not child.is_dir():
            continue
        if _has_marker(child) or _has_any_content(child):
            out.append(child)
    return out


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


# ============================================================
# Public API
# ============================================================


def extract_archives(target_dir: Path, recursive: bool = True) -> list[Path]:
    """Scan and extract supported archives, returning all extraction dirs.

    Idempotency guarantees:
      - Re-running with the same target_dir is safe; previously-extracted
        archives are skipped.
      - **If the source archive has been deleted or moved**, the existing
        extracted directory is still returned. This was the user-reported
        bug — earlier the function returned ``[]`` early when no archives
        were found, hiding the previously-extracted content.

    Args:
        target_dir: A file or directory to scan for archives/images.
        recursive: Recurse into subdirectories.

    Returns:
        List of directory paths under ``case/extractions/`` containing
        evidence for downstream parsers. Sorted, de-duplicated.
    """
    extractions_dir = _resolve_extractions_dir()
    if extractions_dir is None:
        return []

    target_dir = Path(target_dir)
    extracted: dict[Path, None] = {}

    # Always seed the result with previously-extracted dirs. This is the
    # idempotency fix.
    for prior in _existing_extractions(extractions_dir):
        extracted[prior.resolve()] = None

    # Collect new archives/images to try extracting.
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
        # double-extension archives (.tar.gz, .tar.bz2)
        for p in scan_fn("*.tar.gz"):
            if p.is_file() and not p.is_symlink():
                targets.append(p)

    # Wrap in tqdm if available; fall back gracefully.
    try:
        from tqdm import tqdm  # type: ignore

        target_iter = tqdm(targets, desc="Extracting evidence", unit="file", leave=False)
    except ImportError:
        target_iter = targets

    for source in target_iter:
        out_dir = extractions_dir / source.stem
        # Some tools name `archive.tar.gz` whose .stem is `archive.tar`.
        # Use the full name (without final extension) when that happens.
        if source.suffixes[-2:] == [".tar", ".gz"] or source.suffixes[-2:] == [
            ".tar",
            ".bz2",
        ]:
            out_dir = extractions_dir / source.name.replace(".tar.gz", "").replace(
                ".tar.bz2", ""
            )

        if _has_marker(out_dir) or _has_any_content(out_dir):
            logger.info(
                "Skipping already-extracted %s (existing dir: %s)",
                source.name,
                out_dir.name,
            )
            extracted[out_dir.resolve()] = None
            continue

        if _is_archive(source):
            logger.info("Extracting archive %s -> %s", source.name, out_dir)
            if _extract_one(source, out_dir):
                extracted[out_dir.resolve()] = None
        elif _is_image(source):
            # 7zip handles many forensic image formats. For E01 the success
            # rate depends on the variant; fall back instructions are
            # logged on failure.
            logger.info("Extracting image %s -> %s", source.name, out_dir)
            if _extract_one(source, out_dir):
                extracted[out_dir.resolve()] = None
            else:
                logger.warning(
                    "7zip could not extract image %s. For deep E01 support "
                    "use ewfmount + tsk_recover manually and place output "
                    "in %s.",
                    source.name,
                    out_dir,
                )

    return sorted(extracted.keys())
