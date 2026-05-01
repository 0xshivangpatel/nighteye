"""Automatic Archive & Image Extractor.

Handles pre-processing of raw evidence containers (ZIP, 7z, RAR, E01)
before the ingest plan is built. Extracted contents are placed in the
case's `extractions/` directory.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from nighteye.case import get_case_dir

logger = logging.getLogger("nighteye.ingest.extract")

def extract_archives(target_dir: Path, recursive: bool = True) -> list[Path]:
    """Scan and extract all supported archives in the target directory.
    
    Returns a list of directories containing the extracted evidence.
    """
    case_dir = get_case_dir()
    if not case_dir:
        return []
        
    extractions_dir = case_dir / "extractions"
    extractions_dir.mkdir(exist_ok=True)
    
    extracted_paths = []
    
    # Extensions we know we can handle automatically
    archive_exts = {".zip", ".7z", ".rar", ".tar", ".gz"}
    image_exts = {".e01", ".raw", ".dd"}
    
    if target_dir.is_file():
        targets = [target_dir] if target_dir.suffix.lower() in (archive_exts | image_exts) else []
    else:
        # Targeted scanning is much faster than rglob("*") on slow HDDs
        targets = []
        scan_fn = target_dir.rglob if recursive else target_dir.glob
        for ext in (archive_exts | image_exts):
            targets.extend(list(scan_fn(f"*{ext}")))
            targets.extend(list(scan_fn(f"*{ext.upper()}")))
    
    if not targets:
        return []

    try:
        from tqdm import tqdm
        target_iter = tqdm(targets, desc="Unzipping Evidence", unit="file", leave=True)
    except ImportError:
        target_iter = targets

    for f in target_iter:
        ext = f.suffix.lower()
        if ext in archive_exts:
            out_dir = extractions_dir / f.stem
            if out_dir.exists():
                logger.info("Skipping already extracted archive: %s", f.name)
                extracted_paths.append(out_dir)
                continue
                
            logger.info("Extracting archive %s via 7zip...", f.name)
            out_dir.mkdir(parents=True, exist_ok=True)
            try:
                subprocess.run(
                    ["7z", "x", str(f), f"-o{out_dir}", "-y"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=True
                )
                extracted_paths.append(out_dir)
            except subprocess.CalledProcessError as e:
                msg = f"Failed to extract {f.name} with 7zip: {e}"
                if 'tqdm' in globals() or 'tqdm' in locals():
                    try:
                        tqdm.write(msg)
                    except:
                        logger.error(msg)
                else:
                    logger.error(msg)
                
        elif ext in image_exts:
            out_dir = extractions_dir / f.stem
            if out_dir.exists():
                logger.info("Skipping already extracted image: %s", f.name)
                extracted_paths.append(out_dir)
                continue
                
            logger.info("Attempting to extract forensic image %s via 7zip...", f.name)
            # Modern 7zip can actually parse and extract NTFS filesystems 
            # from RAW and some E01 variants!
            out_dir.mkdir(parents=True, exist_ok=True)
            try:
                subprocess.run(
                    ["7z", "x", str(f), f"-o{out_dir}", "-y"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=True
                )
                extracted_paths.append(out_dir)
            except subprocess.CalledProcessError as e:
                msg = f"7zip failed to extract image {f.name}: {e}. For deep E01 support, manual ewfmount + tsk_recover may be required."
                if 'tqdm' in globals() or 'tqdm' in locals():
                    try:
                        tqdm.write(msg)
                    except:
                        logger.warning(msg)
                else:
                    logger.warning(msg)
                
    return extracted_paths
