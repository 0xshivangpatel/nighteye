#!/usr/bin/env python3
"""Run the full SRL 2015 pipeline.

Uses the unified ``nighteye ingest`` engine (``ingest_evidence``) which
auto-discovers Plaso CSVs, Shimcache CSVs, EVTX, registry hives, and
E01 images.  E01 images are processed via Plaso artifact extraction
instead of the old tsk_recover metadata-flood path.

Usage (from repo root) ::

    .venv/bin/python scripts/run_srl2015_pipeline.py --clean
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

# Ensure src/ is on the path when run directly
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from nighteye.case import get_active_case, CaseInfo
from nighteye.ingest.opensearch_client import NightEyeOSClient
from nighteye.ingest.orchestrator import ingest_evidence
from nighteye.canonical.engine import run_normalization_pass
from nighteye.graph.graph import build_graph_from_canonical
from nighteye.constructors.base import run_all_constructors

logger = logging.getLogger("run_srl2015_pipeline")


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _resolve_case(args: argparse.Namespace) -> CaseInfo:
    if args.case_id:
        logger.error("--case-id is not yet supported; please set the active case.")
        sys.exit(1)
    case = get_active_case()
    if not case:
        logger.error("No active case. Run: nighteye init --name SRL-2015 --examiner <you>")
        sys.exit(1)
    return case


def _clean_case_indices(client: NightEyeOSClient, case_id: str) -> int:
    """Delete all case-related OpenSearch indices. Returns count removed."""
    pattern = f"case-{case_id.lower()}-*"
    indices = client.list_indices(pattern)
    removed = 0
    for idx in indices:
        try:
            client.delete_index(idx)
            removed += 1
            logger.debug("Deleted index %s", idx)
        except Exception as exc:
            logger.warning("Could not delete index %s: %s", idx, exc)
    return removed


def run_pipeline(args: argparse.Namespace) -> int:
    case = _resolve_case(args)
    base_dir = Path(args.base_dir)
    if not base_dir.exists():
        logger.error("Base directory does not exist: %s", base_dir)
        return 1

    print("=" * 70)
    print("SRL 2015 FULL PIPELINE")
    print("=" * 70)
    print(f"Case : {case.id} ({case.case_name})")
    print(f"Evidence: {base_dir}")
    print("=" * 70)

    client = NightEyeOSClient()
    total_start = time.time()

    # ------------------------------------------------------------------
    # 0. Clean old indices
    # ------------------------------------------------------------------
    if args.clean:
        print("\n[0/4] Cleaning old case indices...")
        removed = _clean_case_indices(client, case.id)
        print(f"  → Removed {removed} old indices")

    # ------------------------------------------------------------------
    # 1. Ingest (unified pipeline)
    # ------------------------------------------------------------------
    print("\n[1/4] Ingesting evidence...")
    t0 = time.time()
    ingest_stats = ingest_evidence(
        evidence_dir=str(base_dir),
        case_id=case.id,
        examiner=case.examiner,
        force_reingest=args.force,
    )
    t1 = time.time()
    print(f"  → Files processed: {ingest_stats['files_processed']}")
    print(f"  → Documents indexed: {ingest_stats['documents_indexed']}")
    print(f"  → Errors: {ingest_stats['errors']}")
    print(f"  → Hosts detected: {', '.join(ingest_stats['hosts_detected'])}")
    print(f"  → Duration: {t1 - t0:.1f}s")

    if ingest_stats["documents_indexed"] == 0:
        logger.warning("No documents were ingested. Aborting pipeline.")
        return 1

    # ------------------------------------------------------------------
    # 2. Normalize
    # ------------------------------------------------------------------
    print("\n[2/4] Normalizing to canonical events...")
    t0 = time.time()
    norm_stats = run_normalization_pass(client, case.id)
    t1 = time.time()
    print(f"  → Scanned:  {norm_stats['raw_docs_scanned']} raw docs")
    print(f"  → Created:  {norm_stats['canonical_docs_created']} canonical events")
    print(f"  → Skipped:  {norm_stats['skipped']} | Errors: {norm_stats['errors']}")
    print(f"  → Duration: {t1 - t0:.1f}s")

    if norm_stats["canonical_docs_created"] == 0:
        logger.warning("No canonical events were created. Graph will be empty.")

    # ------------------------------------------------------------------
    # 3. Build Graph
    # ------------------------------------------------------------------
    print("\n[3/4] Building entity-relationship graph...")
    t0 = time.time()
    graph_stats = build_graph_from_canonical(client, case.id, case.graph_db)
    t1 = time.time()
    print(f"  → Events:   {graph_stats['events_processed']}")
    print(f"  → Entities: {graph_stats['entities_created']} | Edges: {graph_stats['edges_created']}")
    print(f"  → Duration: {t1 - t0:.1f}s")

    # ------------------------------------------------------------------
    # 4. Cluster
    # ------------------------------------------------------------------
    print("\n[4/4] Running behavioral clustering...")
    t0 = time.time()
    cluster_stats = run_all_constructors(client, case.id, case.graph_db)
    t1 = time.time()
    print(f"  → Constructors: {cluster_stats['constructors_run']}")
    print(f"  → Clusters:     {cluster_stats['clusters_created']} "
          f"({cluster_stats.get('high_confidence', 0)} high confidence)")
    if cluster_stats.get("anti_forensic", 0) > 0:
        print(f"  → Anti-forensic indicators: {cluster_stats['anti_forensic']}")
    print(f"  → Duration: {t1 - t0:.1f}s")

    total_end = time.time()
    print("\n" + "=" * 70)
    print(f"PIPELINE COMPLETE in {total_end - total_start:.0f}s")
    print("=" * 70)
    print("Next steps:")
    print("  • View status:   .venv/bin/python -m nighteye.cli status")
    print("  • List clusters: .venv/bin/python -m nighteye.cli clusters")
    print("  • Start portal:  .venv/bin/python -m nighteye.cli serve")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the full SRL 2015 pipeline"
    )
    parser.add_argument(
        "--base-dir",
        default="/media/sansforensics/Aeon_s HDD/Hackathon/SRL 2015",
        help="Path to SRL 2015 evidence directory (default: external HDD)",
    )
    parser.add_argument(
        "--case-id",
        default="",
        help="Case ID (default: use active case)",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Delete old case indices before ingest",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-ingest even if index exists",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable debug logging"
    )
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)
    return run_pipeline(args)


if __name__ == "__main__":
    sys.exit(main())
