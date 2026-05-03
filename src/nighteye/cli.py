"""NightEye CLI.

Command-line interface for case management, ingest, normalization,
clustering, investigation, and reporting.

References:
  - docs/ARCHITECTURE.md § 13 (CLI Design)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nighteye import __version__
from nighteye.case import create_case, get_active_case, list_cases, CaseInfo
from nighteye.db import connect
from nighteye.ingest.opensearch_client import NightEyeOSClient
from nighteye.ingest.orchestrator import ingest_evidence
from nighteye.canonical.engine import run_normalization_pass
from nighteye.graph.graph import build_graph_from_canonical
from nighteye.constructors.base import run_all_constructors
from nighteye.hypothesis_lifecycle import list_hypotheses

__all__ = ["main"]

logger = logging.getLogger("nighteye.cli")


def _setup_logging(verbose: bool = False) -> None:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize a new case."""
    case = create_case(
        name=args.name,
        examiner=args.examiner,
        description=args.description or "",
        cases_dir=Path(args.base_dir) if getattr(args, "base_dir", None) else None,
    )
    print(f"Case created: {case.id}")
    print(f"  Name: {case.case_name}")
    print(f"  Examiner: {case.examiner}")
    print(f"  Graph DB: {case.graph_db}")
    print(f"  Case Dir: {case.case_dir}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Show case status."""
    case = get_active_case()
    if not case:
        print("No active case. Use 'nighteye init' to create one.")
        return 1

    with connect(case.graph_db, read_only=True) as conn:
        counts = {
            "clusters": conn.execute(
                "SELECT COUNT(*) FROM clusters WHERE case_id = ?", (case.id,)
            ).fetchone()[0],
            "hypotheses": conn.execute(
                "SELECT COUNT(*) FROM hypotheses WHERE case_id = ?", (case.id,)
            ).fetchone()[0],
            "approved": conn.execute(
                "SELECT COUNT(*) FROM hypotheses WHERE case_id = ? AND status = 'APPROVED'",
                (case.id,),
            ).fetchone()[0],
            "entities": conn.execute(
                "SELECT COUNT(*) FROM entities WHERE case_id = ?", (case.id,)
            ).fetchone()[0],
            "edges": conn.execute(
                "SELECT COUNT(*) FROM edges WHERE case_id = ?", (case.id,)
            ).fetchone()[0],
            "gaps": conn.execute(
                "SELECT COUNT(*) FROM evidence_gaps WHERE case_id = ?", (case.id,)
            ).fetchone()[0],
            "disturbances": conn.execute(
                "SELECT COUNT(*) FROM evidence_disturbances WHERE case_id = ?", (case.id,)
            ).fetchone()[0],
        }

    print(f"Case: {case.case_name} ({case.id})")
    print(f"  Status: {case.status}")
    print(f"  Examiner: {case.examiner}")
    print(f"  Created: {case.created_at}")
    print(f"  Clusters: {counts['clusters']}")
    print(f"  Hypotheses: {counts['hypotheses']} ({counts['approved']} approved)")
    print(f"  Entities: {counts['entities']} ({counts['edges']} edges)")
    print(f"  Evidence Gaps: {counts['gaps']}")
    print(f"  Disturbances: {counts['disturbances']}")
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    """Ingest evidence into case."""
    case = get_active_case()
    if not case:
        print("No active case. Use 'nighteye init' to create one.")
        return 1

    print(f"Ingesting evidence into case {case.id}...")

    stats = ingest_evidence(
        evidence_dir=args.directory,
        case_id=case.id,
        examiner=case.examiner,
        tool_filter=args.tool,
    )

    print(f"Ingest complete:")
    print(f"  Files processed: {stats['files_processed']}")
    print(f"  Documents indexed: {stats['documents_indexed']}")
    print(f"  Errors: {stats['errors']}")
    print(f"  Hosts detected: {', '.join(stats['hosts_detected'])}")
    return 0


def cmd_normalize(args: argparse.Namespace) -> int:
    """Run canonical normalization pass."""
    case = get_active_case()
    if not case:
        print("No active case.")
        return 1

    print(f"Running normalization pass for case {case.id}...")

    client = NightEyeOSClient()
    stats = run_normalization_pass(client, case.id)

    print(f"Normalization complete:")
    print(f"  Raw docs scanned: {stats['raw_docs_scanned']}")
    print(f"  Canonical events created: {stats['canonical_docs_created']}")
    print(f"  Errors: {stats['errors']}")
    print(f"  Skipped: {stats['skipped']}")
    return 0


def cmd_graph(args: argparse.Namespace) -> int:
    """Build entity-relationship graph."""
    case = get_active_case()
    if not case:
        print("No active case.")
        return 1

    print(f"Building graph for case {case.id}...")

    client = NightEyeOSClient()
    stats = build_graph_from_canonical(client, case.id, case.graph_db)

    print(f"Graph build complete:")
    print(f"  Events processed: {stats['events_processed']}")
    print(f"  Entities created: {stats['entities_created']}")
    print(f"  Edges created: {stats['edges_created']}")
    print(f"  Errors: {stats['errors']}")
    return 0


def cmd_cluster(args: argparse.Namespace) -> int:
    """Run behavioral clustering."""
    case = get_active_case()
    if not case:
        print("No active case.")
        return 1

    print(f"Running behavioral clustering for case {case.id}...")

    client = NightEyeOSClient()
    stats = run_all_constructors(client, case.id, case.graph_db)

    print(f"Clustering complete:")
    print(f"  Constructors run: {stats['constructors_run']}")
    print(f"  Clusters created: {stats['clusters_created']}")
    print(f"  High-confidence: {stats['high_confidence']}")
    print(f"  Anti-forensic: {stats['anti_forensic']}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Generate investigation report."""
    from nighteye.mcp.tools.report_tools import generate_report

    case = get_active_case()
    if not case:
        print("No active case.")
        return 1

    print(f"Generating report for case {case.id}...")

    result = generate_report(
        case_id=case.id,
        format=args.format,
        include_evidence=args.include_evidence,
        include_hypotheses=args.include_hypotheses,
        include_clusters=args.include_clusters,
        include_timeline=args.include_timeline,
    )

    if not result["success"]:
        print(f"Error: {result['error']}")
        return 1

    if args.format == "json":
        output_path = args.output or f"report-{case.id}.json"
        with open(output_path, "w") as f:
            json.dump(result["report"], f, indent=2, default=str)
        print(f"Report saved to: {output_path}")

    elif args.format in ("markdown", "html"):
        output_path = args.output or f"report-{case.id}.{args.format}"
        with open(output_path, "w") as f:
            f.write(result["content"])
        print(f"Report saved to: {output_path}")

    return 0


def cmd_list_cases(args: argparse.Namespace) -> int:
    """List all cases."""
    cases = list_cases()

    if not cases:
        print("No cases found.")
        return 0

    print(f"{'Case ID':<30} {'Name':<25} {'Examiner':<20} {'Status':<12} {'Created'}")
    print("-" * 110)
    for case in cases:
        print(f"{case.id:<30} {case.case_name:<25} {case.examiner:<20} {case.status:<12} {case.created_at}")
    return 0


def cmd_hypotheses(args: argparse.Namespace) -> int:
    """List hypotheses."""
    case = get_active_case()
    if not case:
        print("No active case.")
        return 1

    with connect(case.graph_db, read_only=True) as conn:
        rows = conn.execute(
            """
            SELECT hypothesis_id, title, status, confidence_score, confidence_tier, staged_at
            FROM hypotheses WHERE case_id = ?
            ORDER BY staged_at DESC
            """,
            (case.id,),
        ).fetchall()

    if not rows:
        print("No hypotheses recorded.")
        return 0

    print(f"{'ID':<35} {'Title':<40} {'Status':<18} {'Score':<8} {'Tier':<12} {'Staged'}")
    print("-" * 130)
    for r in rows:
        print(f"{r['hypothesis_id']:<35} {r['title'][:38]:<40} {r['status']:<18} {r['confidence_score']:<8} {r['confidence_tier']:<12} {r['staged_at']}")
    return 0


def cmd_clusters(args: argparse.Namespace) -> int:
    """List clusters."""
    case = get_active_case()
    if not case:
        print("No active case.")
        return 1

    with connect(case.graph_db, read_only=True) as conn:
        rows = conn.execute(
            """
            SELECT cluster_id, cluster_type, primary_host, score, strength, status, summary
            FROM clusters WHERE case_id = ?
            ORDER BY score DESC
            """,
            (case.id,),
        ).fetchall()

    if not rows:
        print("No clusters found.")
        return 0

    print(f"{'ID':<35} {'Constructor':<20} {'Host':<20} {'Score':<8} {'Strength':<12} {'Status':<12}")
    print("-" * 120)
    for r in rows:
        print(f"{r['cluster_id']:<35} {r['cluster_type']:<20} {r['primary_host']:<20} {r['score']:<8} {r['strength']:<12} {r['status']:<12}")
        if args.verbose:
            print(f"  {r['summary']}")
    return 0


def cmd_entities(args: argparse.Namespace) -> int:
    """List entities."""
    case = get_active_case()
    if not case:
        print("No active case.")
        return 1

    with connect(case.graph_db, read_only=True) as conn:
        sql = "SELECT entity_id, entity_type, canonical_key, first_seen, last_seen, seen_count FROM entities WHERE case_id = ?"
        params = [case.id]

        if args.type:
            sql += " AND entity_type = ?"
            params.append(args.type)

        sql += " ORDER BY last_seen DESC LIMIT ?"
        params.append(args.limit)

        rows = conn.execute(sql, params).fetchall()

    if not rows:
        print("No entities found.")
        return 0

    print(f"{'ID':<35} {'Type':<12} {'Key':<40} {'Seen':<8} {'Last Seen'}")
    print("-" * 110)
    for r in rows:
        print(f"{r['entity_id']:<35} {r['entity_type']:<12} {r['canonical_key'][:38]:<40} {r['seen_count']:<8} {r['last_seen']}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Start the MCP server (port 4509) and the Portal (port 4510).

    Runs both as concurrent uvicorn servers within a single asyncio
    event loop. Ctrl+C stops both cleanly.
    """
    import asyncio

    import uvicorn

    from nighteye.mcp.server import create_mcp_server
    from nighteye.portal.app import create_portal_app

    mcp_host = args.mcp_host
    mcp_port = args.mcp_port
    portal_host = args.portal_host
    portal_port = args.portal_port

    print("=" * 60)
    print("NIGHTEYE — Starting MCP server + Portal")
    print("=" * 60)
    print(f"  MCP server: http://{mcp_host}:{mcp_port}/mcp/")
    print(f"  Portal:     http://{portal_host}:{portal_port}/")
    case = get_active_case()
    if case:
        print(f"  Active case: {case.id} ({case.case_name})")
    else:
        print("  Active case: <none — run `nighteye init` first>")
    print("=" * 60)

    mcp = create_mcp_server()
    if hasattr(mcp, "http_app"):
        mcp_asgi = mcp.http_app()
    else:
        mcp_asgi = getattr(mcp, "app", None)
    if mcp_asgi is None:
        print("FATAL: cannot resolve MCP ASGI app", file=sys.stderr)
        return 1

    portal_asgi = create_portal_app()

    mcp_config = uvicorn.Config(
        mcp_asgi, host=mcp_host, port=mcp_port, log_level="info", lifespan="on"
    )
    portal_config = uvicorn.Config(
        portal_asgi, host=portal_host, port=portal_port, log_level="info"
    )

    mcp_server = uvicorn.Server(mcp_config)
    portal_server = uvicorn.Server(portal_config)

    async def runner() -> None:
        await asyncio.gather(mcp_server.serve(), portal_server.serve())

    try:
        asyncio.run(runner())
    except KeyboardInterrupt:
        print("\nShutdown requested.")
    return 0


def cmd_full_pipeline(args: argparse.Namespace) -> int:
    """Run full pipeline: ingest → normalize → graph → cluster."""
    import time as _time

    case = get_active_case()
    if not case:
        print("No active case.")
        return 1

    print("=" * 60)
    print("NIGHTEYE FULL PIPELINE")
    print("=" * 60)
    total_start = _time.time()

    # Step 0: Clean old OpenSearch indices from previous runs
    client = NightEyeOSClient()
    try:
        old_indices = client.list_indices(f"case-{case.id.lower()}-*")
        if old_indices and not args.no_clean:
            print("\n[0/4] Cleaning old case indices...")
            for idx in old_indices:
                try:
                    client.delete_index(idx)
                except Exception:
                    pass
            print(f"  → Removed {len(old_indices)} old indices")
    except Exception:
        pass

    # Step 1: Ingest
    print("\n[1/4] Ingesting evidence...")
    t0 = _time.time()
    ingest_stats = ingest_evidence(
        evidence_dir=args.directory,
        case_id=case.id,
        examiner=case.examiner,
    )
    t1 = _time.time()
    print(f"  → {ingest_stats['documents_indexed']} docs indexed in {t1 - t0:.0f}s "
          f"({ingest_stats.get('errors', 0)} errors)")
    print(f"  → Hosts: {', '.join(ingest_stats['hosts_detected'])}")

    # Step 2: Normalize
    print("\n[2/4] Normalizing to canonical events...")
    t0 = _time.time()
    client = NightEyeOSClient()
    norm_stats = run_normalization_pass(client, case.id)
    t1 = _time.time()
    print(f"  → {norm_stats['canonical_docs_created']} canonical events in {t1 - t0:.0f}s "
          f"({norm_stats.get('errors', 0)} errors, {norm_stats.get('skipped', 0)} skipped)")

    # Step 3: Build Graph
    print("\n[3/4] Building entity-relationship graph...")
    t0 = _time.time()
    graph_stats = build_graph_from_canonical(client, case.id, case.graph_db)
    t1 = _time.time()
    print(f"  → {graph_stats['entities_created']} entities, "
          f"{graph_stats['edges_created']} edges in {t1 - t0:.0f}s")

    # Step 4: Cluster
    print("\n[4/4] Running behavioral clustering...")
    t0 = _time.time()
    cluster_stats = run_all_constructors(client, case.id, case.graph_db)
    t1 = _time.time()
    print(f"  → {cluster_stats['clusters_created']} clusters "
          f"({cluster_stats.get('high_confidence', 0)} high) in {t1 - t0:.0f}s")
    if cluster_stats.get("anti_forensic", 0) > 0:
        print(f"  → {cluster_stats['anti_forensic']} anti-forensic indicators detected")

    total_end = _time.time()
    print("\n" + "=" * 60)
    print(f"PIPELINE COMPLETE in {total_end - total_start:.0f}s")
    print("=" * 60)
    print(f"View results at: http://localhost:4510")
    return 0


# ============================================================
# Main
# ============================================================

def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="nighteye",
        description="NightEye — AI-Driven Digital Forensics & Incident Response",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--base-dir", default="/var/lib/nighteye", help="Base data directory")
    parser.add_argument("--version", action="version", version=f"nighteye {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # init
    init_parser = subparsers.add_parser("init", help="Initialize a new case")
    init_parser.add_argument("--name", "-n", required=True, help="Case name")
    init_parser.add_argument("--examiner", "-e", required=True, help="Examiner name")
    init_parser.add_argument("--description", "-d", help="Case description")
    init_parser.add_argument("--base-dir", default=None, help="Base data directory (default: /var/lib/nighteye)")
    init_parser.set_defaults(func=cmd_init)

    # status
    status_parser = subparsers.add_parser("status", help="Show case status")
    status_parser.set_defaults(func=cmd_status)

    # ingest
    ingest_parser = subparsers.add_parser("ingest", help="Ingest evidence")
    ingest_parser.add_argument("directory", help="Evidence directory")
    ingest_parser.add_argument("--tool", help="Filter by tool")
    ingest_parser.set_defaults(func=cmd_ingest)

    # normalize
    normalize_parser = subparsers.add_parser("normalize", help="Run canonical normalization")
    normalize_parser.set_defaults(func=cmd_normalize)

    # graph
    graph_parser = subparsers.add_parser("graph", help="Build entity-relationship graph")
    graph_parser.set_defaults(func=cmd_graph)

    # cluster
    cluster_parser = subparsers.add_parser("cluster", help="Run behavioral clustering")
    cluster_parser.set_defaults(func=cmd_cluster)

    # report
    report_parser = subparsers.add_parser("report", help="Generate investigation report")
    report_parser.add_argument("--format", choices=["json", "markdown", "html"], default="json")
    report_parser.add_argument("--output", "-o", help="Output file path")
    report_parser.add_argument("--no-evidence", action="store_true", dest="exclude_evidence")
    report_parser.add_argument("--no-hypotheses", action="store_true", dest="exclude_hypotheses")
    report_parser.add_argument("--no-clusters", action="store_true", dest="exclude_clusters")
    report_parser.add_argument("--no-timeline", action="store_true", dest="exclude_timeline")
    report_parser.set_defaults(
        func=cmd_report,
        include_evidence=True,
        include_hypotheses=True,
        include_clusters=True,
        include_timeline=True,
    )

    # list-cases
    list_parser = subparsers.add_parser("list-cases", help="List all cases")
    list_parser.set_defaults(func=cmd_list_cases)

    # hypotheses
    hypotheses_parser = subparsers.add_parser("hypotheses", help="List hypotheses")
    hypotheses_parser.set_defaults(func=cmd_hypotheses)

    # clusters
    clusters_parser = subparsers.add_parser("clusters", help="List clusters")
    clusters_parser.add_argument("--verbose", "-v", action="store_true")
    clusters_parser.set_defaults(func=cmd_clusters)

    # entities
    entities_parser = subparsers.add_parser("entities", help="List entities")
    entities_parser.add_argument("--type", "-t", help="Filter by entity type")
    entities_parser.add_argument("--limit", "-l", type=int, default=50)
    entities_parser.set_defaults(func=cmd_entities)

    # full-pipeline
    pipeline_parser = subparsers.add_parser("full-pipeline", help="Run complete pipeline")
    pipeline_parser.add_argument("directory", help="Evidence directory")
    pipeline_parser.add_argument("--no-clean", action="store_true", help="Skip cleaning old case indices")
    pipeline_parser.set_defaults(func=cmd_full_pipeline, no_clean=False)

    # serve
    serve_parser = subparsers.add_parser(
        "serve",
        help="Start MCP server (port 4509) and Portal (port 4510)",
    )
    serve_parser.add_argument(
        "--mcp-host", default="127.0.0.1", help="MCP server bind host (default: 127.0.0.1)"
    )
    serve_parser.add_argument(
        "--mcp-port", type=int, default=4509, help="MCP server port (default: 4509)"
    )
    serve_parser.add_argument(
        "--portal-host",
        default="127.0.0.1",
        help="Portal bind host (default: 127.0.0.1)",
    )
    serve_parser.add_argument(
        "--portal-port",
        type=int,
        default=4510,
        help="Portal port (default: 4510)",
    )
    serve_parser.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    if not args.command:
        parser.print_help()
        return 1

    # Handle report flag inversion
    if args.command == "report":
        args.include_evidence = not getattr(args, "exclude_evidence", False)
        args.include_hypotheses = not getattr(args, "exclude_hypotheses", False)
        args.include_clusters = not getattr(args, "exclude_clusters", False)
        args.include_timeline = not getattr(args, "exclude_timeline", False)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
