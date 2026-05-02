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
from pathlib import Path
from typing import Any, Iterator

from nighteye.ingest.dispatch import EvidenceType, detect_evidence_type
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

# Memory-dump file extensions that Volatility / MemProcFS can actually parse.
# Anything else routed through MEMORY_DUMP (e.g. .body, .txt, .json from
# previous Vol2 output) is a false positive and should be skipped.
_REAL_MEMORY_EXTENSIONS = frozenset({
    ".mem", ".raw", ".dmp", ".vmem", ".lime", ".bin",
})

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

    try:
        from tqdm import tqdm

        # Show per-group progress with host/type info
        group_iter = tqdm(
            plan.groups,
            desc="Ingesting",
            unit="group",
            dynamic_ncols=True,
            postfix={"host": "", "type": "", "docs": 0},
        )
    except ImportError:
        group_iter = plan.groups
        _tqdm_available = False
    else:
        _tqdm_available = True

    for group in group_iter:
        group_start = time.time()
        group.status = "ingesting"

        if _tqdm_available:
            group_iter.set_postfix(
                host=group.host, type=group.artifact_type.value, docs="..."
            )

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

            # Wrap with a counter-based progress bar for large groups
            if _tqdm_available:
                doc_counter = tqdm(
                    doc_stream,
                    desc=f"  {group.host}/{group.artifact_type.value}",
                    unit="docs",
                    unit_scale=True,
                    dynamic_ncols=True,
                    leave=False,
                )
                success_count, error_count = client.bulk_index_iter(
                    index_name=group.index_name,
                    documents=doc_counter,
                )
                doc_counter.close()
            else:
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

            if _tqdm_available:
                group_iter.set_postfix(
                    host=group.host,
                    type=f"{group.artifact_type.value} ✓",
                    docs=success_count,
                )

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


def _stream_directory(
    dir_path: Path,
    artifact_type: EvidenceType,
    case_id: str,
    host_name: str,
    source_file: str,
    audit_id: str,
) -> Iterator[dict[str, Any]]:
    """Recursively scan a directory and stream all parsable evidence files.

    Used for both KAPE_ZIP / extracted-triage containers and for any
    `IngestGroup` whose `evidence.path` is a directory rather than a
    single file. Individual files are detected and routed to the
    correct parser.
    """
    for item in sorted(dir_path.rglob("*")):
        if not item.is_file():
            continue
        # Skip our own marker files from the extractor.
        if item.name == ".nighteye_extracted":
            continue
        detected = detect_evidence_type(item)
        # Skip unknown and recursive container types.
        if detected.evidence_type in (EvidenceType.UNKNOWN, EvidenceType.KAPE_ZIP):
            continue

        file_audit_id = f"{audit_id}-{item.name}"

        if detected.evidence_type in (EvidenceType.EVTX_FILE, EvidenceType.EVTX_FOLDER):
            yield from parse_evtx_file(
                item,
                case_id=case_id,
                host_name=host_name,
                audit_id=file_audit_id,
                use_evtxecmd=True,
            )
            continue

        if detected.evidence_type == EvidenceType.MEMORY_DUMP:
            if not _is_real_memory_dump(item):
                logger.debug(
                    "Skipping non-memory file routed as MEMORY_DUMP: %s",
                    item.name,
                )
                continue
            yield from _run_memory_pipeline(item, host_name, case_id)
            continue

        if detected.evidence_type in (
            EvidenceType.REGISTRY_HIVE,
            EvidenceType.MFT,
            EvidenceType.PREFETCH,
            EvidenceType.AMCACHE,
            EvidenceType.SHIMCACHE,
            EvidenceType.SRUM,
        ):
            if is_tool_available(detected.evidence_type):
                yield from _ez_tool_to_docs(
                    detected.evidence_type, item, host_name, file_audit_id
                )
            elif detected.evidence_type == EvidenceType.REGISTRY_HIVE:
                from nighteye.ingest.python_registry import parse_registry_hive
                yield from parse_registry_hive(
                    item, host_name=host_name,
                    source_file=str(item), audit_id=file_audit_id,
                )
            else:
                yield _metadata_doc(item, detected.evidence_type, host_name, source_file, file_audit_id)
            continue

        # Other recognized but unparseable-here types (LNK, JUMPLIST,
        # WIN_TIMELINE, PCAP, AUTH_LOG, ...) — emit a metadata document
        # so the file is indexed even without a dedicated parser.
        yield _metadata_doc(item, detected.evidence_type, host_name, source_file, audit_id)


def _metadata_doc(
    path: Path,
    evidence_type: EvidenceType,
    host_name: str,
    source_file: str,
    audit_id: str,
) -> dict[str, Any]:
    """Produce a minimal ECS metadata document for unsupported file types.

    Ensures every evidence file is indexed in OpenSearch so the case has
    complete provenance even when dedicated parsers are unavailable.
    """
    try:
        size = path.stat().st_size
        mtime = path.stat().st_mtime
    except OSError:
        size = 0
        mtime = 0

    from nighteye.ingest.ecs import build_ecs_doc

    return build_ecs_doc(
        host_name=host_name,
        event_code=evidence_type.value,
        event_action="evidence-indexed",
        event_category="artifact",
        nighteye_source_file=str(path),
        nighteye_audit_id=audit_id,
        nighteye_parser="metadata",
        nighteye_canonical_type=evidence_type.value.upper(),
        extra={
            "file.name": path.name,
            "file.path": str(path),
            "file.size": size,
            "file.mtime": mtime,
        },
    )


def _is_real_memory_dump(path: Path) -> bool:
    """Return True only if the file extension matches a real memory dump.

    Volatility 3 fails noisily on text/csv files routed through here
    because previous Vol2 outputs (timeliner.body, *-apihooks.txt, etc.)
    are sometimes co-located with real memory dumps in evidence folders.
    """
    return path.suffix.lower() in _REAL_MEMORY_EXTENSIONS


def _run_memory_pipeline(
    path: Path, host_name: str, case_id: str
) -> Iterator[dict[str, Any]]:
    """Run Vol3 + carvers + MemProcFS on a real memory dump."""
    from nighteye.ingest.carvers import run_1768, run_bstrings
    from nighteye.ingest.memprocfs import (
        extract_memprocfs,
        is_memprocfs_available,
    )
    from nighteye.ingest.volatility import (
        is_volatility_available,
        run_volatility,
    )

    if is_volatility_available():
        yield from run_volatility(path, host_name=host_name, case_id=case_id)
    yield from run_bstrings(path, host_name=host_name, case_id=case_id)
    yield from run_1768(path, host_name=host_name, case_id=case_id)
    if is_memprocfs_available():
        for ext_dir in extract_memprocfs(path):
            logger.info(
                "MemProcFS extracted memory to %s. Re-run `nighteye ingest`"
                " on this directory to process the artifacts.",
                ext_dir,
            )


def _ez_tool_to_docs(
    artifact_type: EvidenceType,
    path: Path,
    host_name: str,
    audit_id: str,
) -> Iterator[dict[str, Any]]:
    """Run the matching EZ Tool and convert each row to an ECS doc."""
    if not is_tool_available(artifact_type):
        logger.debug(
            "EZ Tool not available for %s; skipping %s",
            artifact_type.value,
            path.name,
        )
        return
    row_stream = run_ez_tool(artifact_type, path)
    for row in row_stream or []:
        doc = None
        if artifact_type == EvidenceType.REGISTRY_HIVE:
            doc = parse_registry_record(row, host_name=host_name, source_file=str(path), audit_id=audit_id)
        elif artifact_type == EvidenceType.MFT:
            doc = parse_mft_record(row, host_name=host_name, source_file=str(path), audit_id=audit_id)
        elif artifact_type == EvidenceType.PREFETCH:
            doc = parse_prefetch_record(row, host_name=host_name, source_file=str(path), audit_id=audit_id)
        elif artifact_type == EvidenceType.AMCACHE:
            doc = parse_amcache_record(row, host_name=host_name, source_file=str(path), audit_id=audit_id)
        elif artifact_type == EvidenceType.SHIMCACHE:
            doc = parse_shimcache_record(row, host_name=host_name, source_file=str(path), audit_id=audit_id)
        elif artifact_type == EvidenceType.SRUM:
            doc = parse_srum_record(row, host_name=host_name, source_file=str(path), audit_id=audit_id)
        if doc:
            yield doc


def _stream_group_docs(group: IngestGroup, case_id: str) -> Iterator[dict[str, Any]]:
    """Yield all ECS documents from all files in a group."""
    artifact_type = group.artifact_type
    host_name = group.host

    for evidence in group.files:
        source_file = str(evidence.path)
        audit_id = f"nighteye-ingest-{evidence.path.name}-{int(time.time())}"

        # Directories: scan for individual files inside and process each.
        # Also covers KAPE_ZIP "containers" — a directory of mixed
        # triage artifacts that we fan out per-file.
        if evidence.path.is_dir():
            yield from _stream_directory(
                evidence.path, artifact_type, case_id, host_name, source_file, audit_id
            )
            continue

        # KAPE_ZIP files (rare — usually a directory) get treated the same.
        if artifact_type == EvidenceType.KAPE_ZIP:
            logger.debug(
                "KAPE_ZIP file %s — handled by extractor; per-file dispatch happens"
                " on the extracted directory in another group.",
                evidence.path.name,
            )
            continue

        # 1. EVTX Parsing
        if artifact_type in (EvidenceType.EVTX_FILE, EvidenceType.EVTX_FOLDER):
            yield from parse_evtx_file(
                evidence.path,
                case_id=case_id,
                host_name=host_name,
                audit_id=audit_id,
                use_evtxecmd=True,
            )
            from nighteye.ingest.hayabusa import is_hayabusa_available, run_hayabusa
            if is_hayabusa_available():
                yield from run_hayabusa(evidence.path, host_name=host_name, case_id=case_id)
            from nighteye.ingest.chainsaw import is_chainsaw_available, run_chainsaw
            if is_chainsaw_available():
                yield from run_chainsaw(evidence.path, host_name=host_name, case_id=case_id)
            continue

        # 2. Memory Dumps — only run heavy memory tools on real memory files.
        # The dispatch layer used to coerce previous Vol2 output (.body,
        # apihooks.txt, ...) into MEMORY_DUMP; this guard keeps Volatility
        # from failing a thousand times on text artifacts.
        if artifact_type == EvidenceType.MEMORY_DUMP:
            if not _is_real_memory_dump(evidence.path):
                logger.info(
                    "Skipping non-memory file routed as MEMORY_DUMP: %s",
                    evidence.path.name,
                )
                continue
            yield from _run_memory_pipeline(evidence.path, host_name, case_id)
            continue

        # 3. EZ Tools / Python parser fallback
        if artifact_type in (
            EvidenceType.REGISTRY_HIVE,
            EvidenceType.MFT,
            EvidenceType.PREFETCH,
            EvidenceType.AMCACHE,
            EvidenceType.SHIMCACHE,
            EvidenceType.SRUM,
        ):
            # Try EZ Tools first, fall back to Python parser
            if is_tool_available(artifact_type):
                yield from _ez_tool_to_docs(
                    artifact_type, evidence.path, host_name, audit_id
                )
            elif artifact_type == EvidenceType.REGISTRY_HIVE:
                from nighteye.ingest.python_registry import parse_registry_hive
                yield from parse_registry_hive(
                    evidence.path, host_name=host_name,
                    source_file=str(evidence.path), audit_id=audit_id,
                )
            else:
                # No parser available — metadata doc for provenance
                yield _metadata_doc(evidence.path, artifact_type, host_name, source_file, audit_id)
            continue

        # 4. Recognized but no parser yet (LNK, JUMPLIST, WIN_TIMELINE,
        # PCAP, AUTH_LOG, ...) — emit metadata doc so file is indexed.
        if artifact_type != EvidenceType.UNKNOWN:
            yield _metadata_doc(evidence.path, artifact_type, host_name, source_file, audit_id)
        else:
            logger.debug("Skipping UNKNOWN file: %s", evidence.path.name)
