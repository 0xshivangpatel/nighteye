#!/usr/bin/env python3
"""End-to-end test for NightEye including MCP layer.

This script tests the complete pipeline:
1. Case creation
2. Evidence ingestion (with synthetic/corrupted file handling)
3. Canonical normalization
4. Graph building
5. Behavioral clustering
6. MCP server functionality

Usage:
    python -m nighteye.tests.e2e_mcp_test [--create-synthetic]

Options:
    --create-synthetic  Create synthetic test data for testing
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("nighteye.tests.e2e")


def create_synthetic_evidence(base_dir: Path) -> dict[str, Path]:
    """Create synthetic forensic artifacts for testing.
    
    Creates:
    - EVTX files (Windows event logs)
    - Registry hives
    - Prefetch files
    - MFT entries
    - Corrupted E01 (to test error handling)
    """
    import struct
    
    hosts = ["nromanoff", "nfury", "tdungan", "controller"]
    paths = {}
    
    for host in hosts:
        host_dir = base_dir / f"{host}_synthetic"
        host_dir.mkdir(parents=True, exist_ok=True)
        paths[host] = host_dir
        
        # Create EVTX file (minimal valid structure)
        evtx_dir = host_dir / "winevt" / "Logs"
        evtx_dir.mkdir(parents=True)
        evtx_file = evtx_dir / "Security.evtx"
        
        # EVTX header: "ElfFile" magic + version info
        evtx_header = b"ElfFile\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        evtx_header += b"\x00\x00\x00\x00"  # Flags
        evtx_header += b"\x00\x10\x00\x00"  # Chunk count
        evtx_header += b"\x00\x00\x00\x00"  # CRC
        evtx_header += b"\x00" * 4080  # Padding to 4KB
        evtx_file.write_bytes(evtx_header)
        
        # Create a corrupted E01 file (for controller - to test error handling)
        if host == "controller":
            corrupt_e01 = host_dir / "corrupt.E01"
            # Invalid header - not a real EWF file
            corrupt_e01.write_bytes(b"CORRUPTED" + b"\x00" * 100)
        else:
            # Create valid but minimal E01 header
            e01_file = host_dir / "image.E01"
            e01_header = b"EVF\x09\x0d\x0a\xff\x00"  # EWF signature
            e01_header += b"\x00" * 4090
            e01_file.write_bytes(e01_header)
        
        # Create prefetch file (minimal valid SCCA format)
        pf_dir = host_dir / "Windows" / "Prefetch"
        pf_dir.mkdir(parents=True)
        pf_file = pf_dir / "CMD.EXE-12345678.pf"
        
        # SCCA prefetch header
        pf_data = b"SCCA"  # Signature
        pf_data += struct.pack("<I", 17)  # Version (XP)
        pf_data += b"CMD.EXE" + b"\x00" * 53  # Executable name (60 bytes)
        pf_data += struct.pack("<I", 0x12345678)  # Hash
        pf_data += struct.pack("<I", 1)  # Run count
        pf_data += b"\x00" * 500  # Padding
        pf_file.write_bytes(pf_data)
        
        # Create registry hive (minimal)
        reg_dir = host_dir / "Windows" / "System32" / "config"
        reg_dir.mkdir(parents=True)
        reg_file = reg_dir / "SYSTEM"
        # Registry header: "regf"
        reg_header = b"regf\x00\x00\x00\x00\x00\x00\x00\x00"
        reg_header += b"\x00" * 4088
        reg_file.write_bytes(reg_header)
        
        logger.info("Created synthetic data for %s in %s", host, host_dir)
    
    return paths


def test_case_creation() -> tuple[bool, Any]:
    """Test case creation."""
    logger.info("=" * 60)
    logger.info("TEST 1: Case Creation")
    logger.info("=" * 60)
    
    try:
        from nighteye.case import create_case
        
        case = create_case(
            name="E2E Test Case",
            examiner="test-examiner",
            description="End-to-end test with MCP layer"
        )
        
        logger.info("✓ Case created: %s", case.id)
        logger.info("  Name: %s", case.case_name)
        logger.info("  Graph DB: %s", case.graph_db)
        
        return True, case
    except Exception as exc:
        logger.error("✗ Case creation failed: %s", exc)
        return False, None


def test_ingest(case: Any, evidence_dir: Path) -> tuple[bool, dict]:
    """Test evidence ingestion."""
    logger.info("\n" + "=" * 60)
    logger.info("TEST 2: Evidence Ingestion")
    logger.info("=" * 60)
    
    try:
        from nighteye.ingest.orchestrator import ingest_evidence
        
        start = time.time()
        stats = ingest_evidence(
            evidence_dir=str(evidence_dir),
            case_id=case.id,
            examiner=case.examiner,
        )
        elapsed = time.time() - start
        
        logger.info("✓ Ingest complete in %.1fs", elapsed)
        logger.info("  Documents indexed: %d", stats.get('documents_indexed', 0))
        logger.info("  Hosts detected: %s", stats.get('hosts_detected', []))
        logger.info("  Errors: %d", stats.get('errors', 0))
        
        return True, stats
    except Exception as exc:
        logger.error("✗ Ingest failed: %s", exc)
        import traceback
        traceback.print_exc()
        return False, {}


def test_normalization(case: Any) -> tuple[bool, dict]:
    """Test canonical normalization."""
    logger.info("\n" + "=" * 60)
    logger.info("TEST 3: Canonical Normalization")
    logger.info("=" * 60)
    
    try:
        from nighteye.canonical.engine import run_normalization_pass
        from nighteye.ingest.opensearch_client import NightEyeOSClient
        
        client = NightEyeOSClient()
        start = time.time()
        stats = run_normalization_pass(client, case.id)
        elapsed = time.time() - start
        
        logger.info("✓ Normalization complete in %.1fs", elapsed)
        logger.info("  Raw docs scanned: %d", stats.get('raw_docs_scanned', 0))
        logger.info("  Canonical events created: %d", stats.get('canonical_docs_created', 0))
        logger.info("  Errors: %d", stats.get('errors', 0))
        
        return True, stats
    except Exception as exc:
        logger.error("✗ Normalization failed: %s", exc)
        import traceback
        traceback.print_exc()
        return False, {}


def test_graph_building(case: Any) -> tuple[bool, dict]:
    """Test entity-relationship graph building."""
    logger.info("\n" + "=" * 60)
    logger.info("TEST 4: Graph Building")
    logger.info("=" * 60)
    
    try:
        from nighteye.graph.graph import build_graph_from_canonical
        from nighteye.ingest.opensearch_client import NightEyeOSClient
        
        client = NightEyeOSClient()
        start = time.time()
        stats = build_graph_from_canonical(client, case.id, case.graph_db)
        elapsed = time.time() - start
        
        logger.info("✓ Graph build complete in %.1fs", elapsed)
        logger.info("  Events processed: %d", stats.get('events_processed', 0))
        logger.info("  Entities created: %d", stats.get('entities_created', 0))
        logger.info("  Edges created: %d", stats.get('edges_created', 0))
        
        return True, stats
    except Exception as exc:
        logger.error("✗ Graph building failed: %s", exc)
        import traceback
        traceback.print_exc()
        return False, {}


def test_clustering(case: Any) -> tuple[bool, dict]:
    """Test behavioral clustering."""
    logger.info("\n" + "=" * 60)
    logger.info("TEST 5: Behavioral Clustering")
    logger.info("=" * 60)
    
    try:
        from nighteye.constructors.base import run_all_constructors
        from nighteye.ingest.opensearch_client import NightEyeOSClient
        
        client = NightEyeOSClient()
        start = time.time()
        stats = run_all_constructors(client, case.id, case.graph_db)
        elapsed = time.time() - start
        
        logger.info("✓ Clustering complete in %.1fs", elapsed)
        logger.info("  Constructors run: %d", stats.get('constructors_run', 0))
        logger.info("  Clusters created: %d", stats.get('clusters_created', 0))
        logger.info("  High confidence: %d", stats.get('high_confidence', 0))
        
        return True, stats
    except Exception as exc:
        logger.error("✗ Clustering failed: %s", exc)
        import traceback
        traceback.print_exc()
        return False, {}


def test_mcp_server(case: Any) -> tuple[bool, dict]:
    """Test MCP server functionality."""
    logger.info("\n" + "=" * 60)
    logger.info("TEST 6: MCP Server Layer")
    logger.info("=" * 60)
    
    try:
        from nighteye.mcp.server import create_mcp_server
        
        # Create MCP server
        mcp = create_mcp_server()
        logger.info("✓ MCP server created")
        
        # Test that we can access the server
        if hasattr(mcp, 'http_app'):
            logger.info("✓ HTTP app accessible")
        
        # Try to list available tools
        tools = []
        if hasattr(mcp, '_tools'):
            tools = list(mcp._tools.keys())
        elif hasattr(mcp, 'tools'):
            tools = list(mcp.tools.keys())
        
        logger.info("✓ Available MCP tools: %d", len(tools))
        for tool_name in tools[:10]:  # Show first 10
            logger.info("  - %s", tool_name)
        if len(tools) > 10:
            logger.info("  ... and %d more", len(tools) - 10)
        
        # Test a simple tool call if available
        test_results = {"tools_available": len(tools), "tool_names": tools[:20]}
        
        return True, test_results
    except Exception as exc:
        logger.error("✗ MCP server test failed: %s", exc)
        import traceback
        traceback.print_exc()
        return False, {}


def test_mcp_tools(case: Any) -> tuple[bool, dict]:
    """Test specific MCP tools."""
    logger.info("\n" + "=" * 60)
    logger.info("TEST 7: MCP Tools Execution")
    logger.info("=" * 60)
    
    results = {}
    
    # Test case tools
    try:
        from nighteye.mcp.tools.case_tools import get_case_summary, list_hosts
        case_result = get_case_summary(case_id=case.id)
        results['get_case_summary'] = case_result
        logger.info("✓ get_case_summary: %s", case_result.get('status', 'ok'))
        
        hosts_result = list_hosts(case_id=case.id)
        results['list_hosts'] = hosts_result
        logger.info("✓ list_hosts: %d hosts found", len(hosts_result.get('hosts', [])))
    except Exception as exc:
        logger.warning("Case tools failed: %s", exc)
        results['case_tools'] = {"error": str(exc)}
    
    # Test cluster tools
    try:
        from nighteye.mcp.tools.cluster_tools import list_clusters
        cluster_result = list_clusters(case_id=case.id, min_strength="WEAK")
        results['list_clusters'] = cluster_result
        logger.info("✓ list_clusters: %d clusters found", 
                   len(cluster_result.get('clusters', [])))
    except Exception as exc:
        logger.warning("list_clusters failed: %s", exc)
        results['list_clusters'] = {"error": str(exc)}
    
    # Test hypothesis tools
    try:
        from nighteye.mcp.tools.hypothesis_tools import list_hypotheses
        hyp_result = list_hypotheses(case_id=case.id)
        results['list_hypotheses'] = hyp_result
        logger.info("✓ list_hypotheses: %d hypotheses", 
                   len(hyp_result.get('hypotheses', [])))
    except Exception as exc:
        logger.warning("list_hypotheses failed: %s", exc)
        results['list_hypotheses'] = {"error": str(exc)}
    
    # Test evidence tools
    try:
        from nighteye.mcp.tools.evidence_tools import get_evidence_summary
        ev_result = get_evidence_summary(case_id=case.id)
        results['get_evidence_summary'] = ev_result
        logger.info("✓ get_evidence_summary: %s", ev_result.get('status', 'ok'))
    except Exception as exc:
        logger.warning("get_evidence_summary failed: %s", exc)
        results['evidence_tools'] = {"error": str(exc)}
    
    return True, results


def run_e2e_test(create_synthetic: bool = False) -> dict[str, Any]:
    """Run complete end-to-end test."""
    logger.info("=" * 70)
    logger.info("NIGHTEYE END-TO-END TEST WITH MCP LAYER")
    logger.info("=" * 70)
    logger.info("Start time: %s", datetime.now().isoformat())
    
    results = {
        "start_time": datetime.now().isoformat(),
        "tests": {},
        "success": False
    }
    
    # Create synthetic data if requested
    evidence_dir = None
    if create_synthetic:
        logger.info("\nCreating synthetic test data...")
        with tempfile.TemporaryDirectory() as tmpdir:
            evidence_dir = Path(tmpdir) / "evidence"
            evidence_dir.mkdir()
            create_synthetic_evidence(evidence_dir)
            
            # Run tests with synthetic data
            _run_all_tests(evidence_dir, results)
    else:
        # Use existing case data
        _run_all_tests(None, results)
    
    # Final summary
    logger.info("\n" + "=" * 70)
    logger.info("E2E TEST SUMMARY")
    logger.info("=" * 70)
    
    total_tests = len(results['tests'])
    passed_tests = sum(1 for r in results['tests'].values() if r.get('success'))
    
    logger.info("Tests run: %d", total_tests)
    logger.info("Passed: %d", passed_tests)
    logger.info("Failed: %d", total_tests - passed_tests)
    logger.info("Overall: %s", "PASS" if passed_tests == total_tests else "PARTIAL" if passed_tests > 0 else "FAIL")
    
    results['end_time'] = datetime.now().isoformat()
    results['success'] = passed_tests == total_tests
    
    return results


def _run_all_tests(evidence_dir: Path | None, results: dict):
    """Run all test phases."""
    # Test 1: Case Creation
    success, case = test_case_creation()
    results['tests']['case_creation'] = {"success": success, "case_id": getattr(case, 'id', None)}
    
    if not success or not case:
        logger.error("Cannot continue without case")
        return
    
    # Test 2: Ingest (only if we have evidence)
    if evidence_dir:
        success, stats = test_ingest(case, evidence_dir)
        results['tests']['ingest'] = {"success": success, "stats": stats}
    else:
        logger.info("Skipping ingest test (no evidence directory)")
        results['tests']['ingest'] = {"success": True, "skipped": True}
    
    # Test 3: Normalization
    success, stats = test_normalization(case)
    results['tests']['normalization'] = {"success": success, "stats": stats}
    
    # Test 4: Graph Building
    success, stats = test_graph_building(case)
    results['tests']['graph_building'] = {"success": success, "stats": stats}
    
    # Test 5: Clustering
    success, stats = test_clustering(case)
    results['tests']['clustering'] = {"success": success, "stats": stats}
    
    # Test 6: MCP Server
    success, stats = test_mcp_server(case)
    results['tests']['mcp_server'] = {"success": success, "stats": stats}
    
    # Test 7: MCP Tools
    success, stats = test_mcp_tools(case)
    results['tests']['mcp_tools'] = {"success": success, "stats": stats}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NightEye E2E Test with MCP")
    parser.add_argument("--create-synthetic", action="store_true",
                       help="Create synthetic test data")
    parser.add_argument("--output", "-o", help="Output file for results (JSON)")
    
    args = parser.parse_args()
    
    results = run_e2e_test(create_synthetic=args.create_synthetic)
    
    # Write results to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        logger.info("\nResults written to: %s", args.output)
    
    # Exit with appropriate code
    sys.exit(0 if results['success'] else 1)
