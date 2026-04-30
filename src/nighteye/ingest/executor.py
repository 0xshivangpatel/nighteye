"""Ingest Executor — executes an ingest plan.

Takes an IngestPlan, runs the appropriate parsers/tools on each
evidence file, and streams the results into OpenSearch.

Features:
- Disables OpenSearch refresh interval during bulk ingest for speed
- Groups multiple files into a single continuous stream per index
- Handles both pure-Python EVTX parsing and external EZ Tools
- Updates the IngestGroup status and counts in real-time
- Optionally forces an index merge after ingest is complete
"""

from __future__ import annotations

import logging
import time
from typing import Any, Iterator

from nighteye.ingest.dispatch import EvidenceType
from nighteye.ingest.evtx import parse_evtx_file
from nighteye.ingest.ez_tools import is_tool_available, run_ez_tool
from nighteye.ingest.opensearch_client import NightEyeOSClient
from nighteye.ingest.orchestrator import IngestGroup, IngestPlan, IngestResult
from nighteye.ingest.parsers.amcache import parse_amcache_record
from nighteye.ingest.parsers.mft import parse_mft_record
from nighteye.ingest.parsers.prefetch import parse_prefetch_record
from nighteye.ingest.parsers.registry import parse_registry_record
from nighteye.ingest.parsers.shimcache import parse_shimcache_record
from nighteye.ingest.parsers.srum import parse_srum_record

__all__ = ["execute_ingest_plan"]

logger = logging.getLogger("nighteye.ingest.executor")


def execute_ingest_plan(
    plan: IngestPlan,
    client: NightEyeOSClient,
    *,
    force_merge: bool = True,
) -> IngestResult:
    """Execute an ingest plan and stream documents to OpenSearch.

    Args:
        plan: The IngestPlan to execute.
        client: OpenSearch client instance.
        force_merge: If True, forces a segment merge on modified
            indices after the ingest completes (optimizes query speed).

    Returns:
        IngestResult with execution statistics.
    """
    result = IngestResult(plan=plan)
    start_time = time.time()
    modified_indices: set[str] = set()

    for group in plan.groups:
        group_start = time.time()
        group.status = "ingesting"

        logger.info(
            "Ingesting group: %s (%s, %d files)",
            group.host,
            group.artifact_type.value,
            len(group.files),
        )

        try:
            # Disable refresh interval for this index to maximize throughput
            client.set_refresh_interval(group.index_name, "-1")

            # Stream all files in this group into a single bulk ingest
            doc_stream = _stream_group_docs(group, plan.case_id)
            
            # Execute the bulk stream to OpenSearch
            success_count, error_count = client.bulk_index_iter(
                index_name=group.index_name,
                documents=doc_stream,
            )

            group.doc_count = success_count
            result.total_docs_indexed += success_count
            result.total_errors += error_count

            if error_count > 0:
                logger.warning("Group %s had %d indexing errors", group.host, error_count)

            group.status = "done"
            result.groups_completed += 1
            modified_indices.add(group.index_name)

        except Exception as exc:
            group.status = "failed"
            group.error = str(exc)
            result.groups_failed += 1
            logger.error("Group %s failed: %s", group.host, exc, exc_info=True)
        finally:
            # Re-enable standard refresh interval (1s) and record duration
            try:
                client.set_refresh_interval(group.index_name, "1s")
            except Exception as e:
                logger.debug("Failed to reset refresh interval for %s: %s", group.index_name, e)

            group.duration_ms = int((time.time() - group_start) * 1000)

    # Post-ingest optimization
    if force_merge and modified_indices:
        logger.info("Forcing segment merge on %d indices...", len(modified_indices))
        for idx in modified_indices:
            try:
                client.force_merge(idx, max_num_segments=1)
            except Exception as e:
                logger.debug("Force merge failed on %s: %s", idx, e)

    result.duration_s = time.time() - start_time
    
    logger.info(
        "Ingest complete: %d docs in %.1fs (%d errors)",
        result.total_docs_indexed,
        result.duration_s,
        result.total_errors,
    )
    
    return result


def _stream_group_docs(group: IngestGroup, case_id: str) -> Iterator[dict[str, Any]]:
    """Yield all ECS documents from all files in a group."""
    artifact_type = group.artifact_type
    host_name = group.host

    for evidence in group.files:
        source_file = str(evidence.path)
        # Unique audit ID for this file's ingestion
        audit_id = f"nighteye-ingest-{evidence.path.name}-{int(time.time())}"

        # 1. EVTX Parsing
        if artifact_type in (EvidenceType.EVTX_FILE, EvidenceType.EVTX_FOLDER):
            yield from parse_evtx_file(
                evidence.path,
                case_id=case_id,
                host_name=host_name,
                audit_id=audit_id,
                use_evtxecmd=True,  # Will fallback to pure-Python if missing
            )
            
            # 1b. Hayabusa Alerts
            from nighteye.ingest.hayabusa import run_hayabusa, is_hayabusa_available
            if is_hayabusa_available():
                yield from run_hayabusa(evidence.path, host_name=host_name, case_id=case_id)
            
            # 1c. Chainsaw Alerts
            from nighteye.ingest.chainsaw import run_chainsaw, is_chainsaw_available
            if is_chainsaw_available():
                yield from run_chainsaw(evidence.path, host_name=host_name, case_id=case_id)
                
            continue

        # 2. EZ Tools Parsing
        if not is_tool_available(artifact_type):
            logger.warning("Required EZ Tool not found for %s. Skipping %s.", artifact_type.value, evidence.path.name)
            continue

        row_stream = run_ez_tool(artifact_type, evidence.path)
        if not row_stream:
            continue

        # Map rows to ECS based on the artifact type
        for row in row_stream:
            doc = None
            if artifact_type == EvidenceType.REGISTRY_HIVE:
                doc = parse_registry_record(row, host_name=host_name, source_file=source_file, audit_id=audit_id)
            elif artifact_type == EvidenceType.MFT:
                doc = parse_mft_record(row, host_name=host_name, source_file=source_file, audit_id=audit_id)
            elif artifact_type == EvidenceType.PREFETCH:
                doc = parse_prefetch_record(row, host_name=host_name, source_file=source_file, audit_id=audit_id)
            elif artifact_type == EvidenceType.AMCACHE:
                doc = parse_amcache_record(row, host_name=host_name, source_file=source_file, audit_id=audit_id)
            elif artifact_type == EvidenceType.SHIMCACHE:
                doc = parse_shimcache_record(row, host_name=host_name, source_file=source_file, audit_id=audit_id)
            elif artifact_type == EvidenceType.SRUM:
                doc = parse_srum_record(row, host_name=host_name, source_file=source_file, audit_id=audit_id)

            if doc:
                yield doc
