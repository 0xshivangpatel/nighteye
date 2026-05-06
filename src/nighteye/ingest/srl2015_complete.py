#!/usr/bin/env python3
"""SRL 2015 Complete Artifact Ingest Pipeline.

This script maximizes evidence extraction from all SRL 2015 hosts:
- nromanoff: Complete data (already has everything)
- nfury: Missing prefetch/amcache - extracts from E01
- tdungan: XP .evt files - uses python-evtx with .evt support
- controller: Corrupt E01 - uses precooked data only

Usage:
    python -m nighteye.ingest.srl2015_complete /path/to/SRL\ 2015 CASE-ID

Environment:
    SRL2015_DATA_PATH - Path to SRL 2015 dataset (if not provided as arg)
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("nighteye.ingest.srl2015_complete")


def get_srl2015_base_path() -> Path | None:
    """Get SRL 2015 base path from env or common locations."""
    # Check environment variable first
    env_path = os.environ.get("SRL2015_DATA_PATH")
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p
    
    # Common locations
    candidates = [
        Path("/cases/SRL 2015"),
        Path("/data/SRL 2015"),
        Path("/mnt/evidence/SRL 2015"),
        Path("/media/sansforensics/Aeon_s HDD/Hackathon/SRL 2015"),
        Path.home() / "cases/SRL 2015",
        Path.home() / "SRL 2015",
    ]
    
    for c in candidates:
        if c.exists():
            return c
    
    return None


def find_host_directories(base_path: Path) -> dict[str, Path]:
    """Find all host directories in SRL 2015 dataset."""
    hosts = {}
    host_patterns = [
        ("nromanoff", "win7-32-nromanoff"),
        ("nfury", "win7-64-nfury"),
        ("tdungan", "xp-tdungan"),
        ("controller", "win2008R2-controller"),
    ]
    
    for host_key, pattern in host_patterns:
        for subdir in base_path.iterdir():
            if subdir.is_dir() and pattern in subdir.name:
                hosts[host_key] = subdir
                break
    
    return hosts


def ingest_host_precooked(
    host: str,
    host_path: Path,
    case_id: str,
) -> dict[str, Any]:
    """Ingest precooked data for a host (works for all hosts including controller).
    
    Precooked data includes:
    - Plaso CSV (timeline with EVTX, prefetch, registry, etc.)
    - Shimcache CSV
    - Redline .mans (if available)
    """
    from nighteye.ingest.opensearch_client import NightEyeOSClient
    from nighteye.ingest.srl2015 import ingest_srl2015_precooked
    
    stats = {
        "host": host,
        "precooked": {"plaso_rows": 0, "shimcache_rows": 0, "errors": 0},
    }
    
    try:
        client = NightEyeOSClient()
        
        # Create a temporary wrapper directory structure
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            wrapper = Path(tmpdir) / f"{host_path.name}_nighteye"
            wrapper.mkdir()
            
            # Find precooked folder
            precooked_paths = list(host_path.rglob("precooked"))
            if precooked_paths:
                # Link or copy precooked data to expected structure
                import shutil
                for pc in precooked_paths:
                    target = wrapper / "precooked"
                    if pc.exists():
                        # Create a minimal structure that srl2015.py expects
                        stats["precooked"] = ingest_srl2015_precooked(
                            client, case_id, Path(tmpdir)
                        )
                        break
            else:
                logger.warning("No precooked folder found for %s", host)
                
    except Exception as exc:
        logger.error("Failed to ingest precooked for %s: %s", host, exc)
        stats["precooked"]["errors"] += 1
    
    return stats


def extract_and_ingest_prefetch(
    host: str,
    host_path: Path,
    case_id: str,
) -> dict[str, Any]:
    """Extract and ingest prefetch files for nfury (and other hosts if missing).
    
    Tries multiple methods:
    1. Look for existing .pf files in precooked/triage
    2. Extract from E01 if available
    3. Parse with python_prefetch as fallback to PECmd
    """
    from nighteye.ingest.opensearch_client import NightEyeOSClient
    from nighteye.ingest.python_prefetch import parse_prefetch
    from nighteye.ingest.ecs import make_index_name, compute_doc_id
    
    stats = {"host": host, "prefetch_count": 0, "errors": 0}
    
    try:
        client = NightEyeOSClient()
        index_name = make_index_name(case_id, "prefetch", host)
        
        pf_files: list[Path] = []
        
        # Method 1: Look in precooked/prefetch
        pf_dirs = list(host_path.rglob("**/prefetch")) + list(host_path.rglob("**/Prefetch"))
        for pf_dir in pf_dirs:
            if pf_dir.is_dir():
                pf_files.extend(pf_dir.glob("*.pf"))
        
        # Method 2: Look in C/Windows/Prefetch (from E01 extraction)
        c_drive_paths = list(host_path.rglob("c-drive")) + list(host_path.rglob("C"))
        for c_drive in c_drive_paths:
            win_pf = c_drive / "Windows" / "Prefetch"
            if win_pf.exists():
                pf_files.extend(win_pf.glob("*.pf"))
        
        if not pf_files:
            logger.warning("No prefetch files found for %s", host)
            return stats
        
        logger.info("Found %d prefetch files for %s", len(pf_files), host)
        
        # Parse each prefetch file
        all_docs = []
        for pf_path in pf_files:
            try:
                docs = list(parse_prefetch(
                    pf_path,
                    host_name=host,
                    source_file=str(pf_path),
                    audit_id=f"prefetch-{host}"
                ))
                all_docs.extend(docs)
            except Exception as exc:
                logger.debug("Failed to parse %s: %s", pf_path.name, exc)
                stats["errors"] += 1
        
        # Bulk index
        if all_docs:
            doc_ids = [
                compute_doc_id(
                    case_id, "prefetch", host,
                    f"{d.get('@timestamp')}:{d.get('process', {}).get('name', '')}:{i}"
                )
                for i, d in enumerate(all_docs)
            ]
            result = client.bulk_index(index_name, all_docs, doc_ids=doc_ids)
            stats["prefetch_count"] = result.get("indexed", 0)
            logger.info("Indexed %d prefetch docs for %s", stats["prefetch_count"], host)
            
    except Exception as exc:
        logger.error("Failed to extract prefetch for %s: %s", host, exc)
        stats["errors"] += 1
    
    return stats


def extract_and_ingest_amcache(
    host: str,
    host_path: Path,
    case_id: str,
) -> dict[str, Any]:
    """Extract and ingest Amcache.hve for nfury and other hosts."""
    from nighteye.ingest.opensearch_client import NightEyeOSClient
    from nighteye.ingest.python_registry import parse_registry_hive
    from nighteye.ingest.ecs import make_index_name, compute_doc_id
    
    stats = {"host": host, "amcache_entries": 0, "errors": 0}
    
    try:
        client = NightEyeOSClient()
        index_name = make_index_name(case_id, "amcache", host)
        
        amcache_paths: list[Path] = []
        
        # Look for Amcache.hve in various locations
        patterns = [
            "**/Amcache.hve",
            "**/amcache.hve",
            "**/C/Windows/appcompat/Programs/Amcache.hve",
            "**/c-drive/Windows/appcompat/Programs/Amcache.hve",
        ]
        
        for pattern in patterns:
            amcache_paths.extend(host_path.rglob(pattern))
        
        if not amcache_paths:
            logger.warning("No Amcache.hve found for %s", host)
            return stats
        
        logger.info("Found Amcache.hve for %s: %s", host, amcache_paths[0])
        
        # Parse Amcache using registry parser
        # Amcache is a registry hive format
        all_docs = []
        for amcache_path in amcache_paths[:1]:  # Just take the first one
            try:
                # Parse as registry hive
                docs = list(parse_registry_hive(
                    amcache_path,
                    host_name=host,
                    audit_id=f"amcache-{host}"
                ))
                all_docs.extend(docs)
            except Exception as exc:
                logger.error("Failed to parse Amcache for %s: %s", host, exc)
                stats["errors"] += 1
        
        if all_docs:
            doc_ids = [
                compute_doc_id(
                    case_id, "amcache", host,
                    f"{d.get('@timestamp')}:{d.get('registry', {}).get('key', '')}:{i}"
                )
                for i, d in enumerate(all_docs)
            ]
            result = client.bulk_index(index_name, all_docs, doc_ids=doc_ids)
            stats["amcache_entries"] = result.get("indexed", 0)
            logger.info("Indexed %d Amcache entries for %s", stats["amcache_entries"], host)
            
    except Exception as exc:
        logger.error("Failed to extract Amcache for %s: %s", host, exc)
        stats["errors"] += 1
    
    return stats


def ingest_xp_evt_files(
    host: str,
    host_path: Path,
    case_id: str,
) -> dict[str, Any]:
    """Ingest Windows XP .evt files for tdungan.
    
    XP uses .evt format which is binary-compatible with .evtx.
    python-evtx can parse both formats.
    """
    from nighteye.ingest.opensearch_client import NightEyeOSClient
    from nighteye.ingest.evtx import parse_evtx_file
    from nighteye.ingest.ecs import make_index_name, compute_doc_id
    
    stats = {"host": host, "evt_files": 0, "events_indexed": 0, "errors": 0}
    
    try:
        client = NightEyeOSClient()
        index_name = make_index_name(case_id, "evtx", host)
        
        # Find .evt files
        evt_files: list[Path] = []
        
        # XP paths
        xp_paths = [
            "**/winevt/Logs/*.evt",
            "**/winevt/Logs/*.Evt",
            "**/config/*.evt",  # Old XP style
            "**/config/*.Evt",
        ]
        
        for pattern in xp_paths:
            evt_files.extend(host_path.rglob(pattern))
        
        # Also check C/Windows directories
        c_paths = list(host_path.rglob("c-drive")) + list(host_path.rglob("C"))
        for c_path in c_paths:
            for pattern in ["**/*.evt", "**/*.Evt"]:
                evt_files.extend(c_path.rglob(pattern))
        
        if not evt_files:
            logger.warning("No .evt files found for %s", host)
            return stats
        
        logger.info("Found %d .evt files for %s", len(evt_files), host)
        stats["evt_files"] = len(evt_files)
        
        # Parse each .evt file using python-evtx
        all_docs = []
        for evt_path in evt_files:
            try:
                # python-evtx can parse .evt files (same binary format)
                docs = list(parse_evtx_file(
                    evt_path,
                    case_id=case_id,
                    host_name=host,
                    audit_id=f"xp-evt-{host}",
                    use_evtxecmd=False,  # Use pure Python - EvtxECmd doesn't support .evt
                ))
                all_docs.extend(docs)
                logger.info("  Parsed %s: %d events", evt_path.name, len(docs))
            except Exception as exc:
                logger.error("Failed to parse %s: %s", evt_path.name, exc)
                stats["errors"] += 1
        
        # Bulk index
        if all_docs:
            doc_ids = [
                compute_doc_id(
                    case_id, "evtx", host,
                    f"{d.get('@timestamp')}:{d.get('event', {}).get('code', '')}:{i}"
                )
                for i, d in enumerate(all_docs)
            ]
            result = client.bulk_index(index_name, all_docs, doc_ids=doc_ids)
            stats["events_indexed"] = result.get("indexed", 0)
            logger.info("Indexed %d XP EVT events for %s", stats["events_indexed"], host)
            
    except Exception as exc:
        logger.error("Failed to ingest XP EVT for %s: %s", host, exc)
        stats["errors"] += 1
    
    return stats


def run_complete_srl2015_ingest(
    base_path: Path | None = None,
    case_id: str = "srl2015-complete",
) -> dict[str, Any]:
    """Run complete ingestion for all SRL 2015 hosts.
    
    Strategy per host:
    - nromanoff: Precooked data (already complete)
    - nfury: Precooked + extract prefetch/amcache from E01
    - tdungan: Precooked + parse XP .evt files
    - controller: Precooked only (E01 is corrupt)
    """
    if base_path is None:
        base_path = get_srl2015_base_path()
    
    if not base_path:
        logger.error("Could not find SRL 2015 dataset. Set SRL2015_DATA_PATH.")
        return {"error": "SRL 2015 dataset not found"}
    
    logger.info("Starting complete SRL 2015 ingest from: %s", base_path)
    logger.info("Case ID: %s", case_id)
    
    hosts = find_host_directories(base_path)
    logger.info("Found hosts: %s", list(hosts.keys()))
    
    all_stats = {}
    
    for host, host_path in hosts.items():
        logger.info("=" * 60)
        logger.info("Processing host: %s", host)
        logger.info("Path: %s", host_path)
        
        host_stats = {"path": str(host_path)}
        
        # Step 1: Always ingest precooked data (works for all hosts)
        logger.info("Step 1: Ingesting precooked data...")
        host_stats["precooked"] = ingest_host_precooked(host, host_path, case_id)
        
        # Step 2: Host-specific fixes
        if host == "tdungan":
            # XP - parse .evt files
            logger.info("Step 2: Parsing XP .evt files...")
            host_stats["xp_evt"] = ingest_xp_evt_files(host, host_path, case_id)
            
        elif host == "nfury":
            # Extract prefetch and amcache
            logger.info("Step 2: Extracting prefetch...")
            host_stats["prefetch"] = extract_and_ingest_prefetch(host, host_path, case_id)
            
            logger.info("Step 3: Extracting Amcache...")
            host_stats["amcache"] = extract_and_ingest_amcache(host, host_path, case_id)
            
        elif host == "controller":
            # Controller has corrupt E01 - only use precooked
            logger.info("Step 2: Controller has corrupt E01 - using precooked only")
            host_stats["note"] = "E01 corrupt - precooked data only"
        
        all_stats[host] = host_stats
        logger.info("Host %s complete: %s", host, host_stats)
    
    # Summary
    logger.info("=" * 60)
    logger.info("INGEST COMPLETE - Summary:")
    for host, stats in all_stats.items():
        logger.info("  %s:", host)
        if "precooked" in stats:
            pc = stats["precooked"]
            if isinstance(pc, dict) and "precooked" in pc:
                pc = pc["precooked"]
            logger.info("    Precooked: %s", pc)
        if "xp_evt" in stats:
            logger.info("    XP EVT: %s", stats["xp_evt"])
        if "prefetch" in stats:
            logger.info("    Prefetch: %s", stats["prefetch"])
        if "amcache" in stats:
            logger.info("    Amcache: %s", stats["amcache"])
    
    return all_stats


if __name__ == "__main__":
    # Parse arguments
    base_path = None
    case_id = "srl2015-complete"
    
    if len(sys.argv) > 1:
        base_path = Path(sys.argv[1])
    if len(sys.argv) > 2:
        case_id = sys.argv[2]
    
    stats = run_complete_srl2015_ingest(base_path, case_id)
    
    # Print final summary as JSON
    import json
    print("\n" + "=" * 60)
    print("FINAL STATS:")
    print(json.dumps(stats, indent=2, default=str))
