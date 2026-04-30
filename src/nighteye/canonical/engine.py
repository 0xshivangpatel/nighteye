"""Canonical Normalization Engine.

Runs the post-ingest normalization pass over raw OpenSearch indices,
mapping ECS documents to CanonicalEvents, and indexing them into
the standard canonical indices for downstream behavior construction.
"""

from __future__ import annotations

import logging
from typing import Iterator

from nighteye.canonical.mapper import map_ecs_to_canonical
from nighteye.canonical.types import CanonicalEvent
from nighteye.ingest.opensearch_client import NightEyeOSClient

__all__ = ["run_normalization_pass"]

logger = logging.getLogger("nighteye.canonical.engine")


def run_normalization_pass(client: NightEyeOSClient, case_id: str) -> dict[str, int]:
    """Run a full normalization pass across all evidence for a case.

    Iterates through all raw evidence indices for the given case,
    maps matching ECS events to CanonicalEvents, and streams them
    into canonical host indices.

    Args:
        client: The NightEyeOSClient instance.
        case_id: The active case ID.

    Returns:
        Statistics dictionary containing processing counts.
    """
    stats = {
        "raw_docs_scanned": 0,
        "canonical_docs_created": 0,
        "errors": 0,
    }

    # Identify all indices for this case
    case_indices = client.list_indices(f"case-{case_id}-*")
    
    # Filter out existing canonical indices to avoid infinite loops
    raw_indices = [idx for idx in case_indices if "-canonical-" not in idx]

    if not raw_indices:
        logger.warning("No raw indices found for case %s.", case_id)
        return stats

    logger.info("Starting normalization pass over %d raw indices for case %s...", len(raw_indices), case_id)

    # Disable refresh interval on the target canonical indices ahead of time
    # We don't know exactly which hosts we'll hit, so we apply to a wildcard.
    canonical_pattern = f"case-{case_id}-canonical-*"
    try:
        client.set_refresh_interval(canonical_pattern, "-1")
    except Exception as e:
        logger.debug("Could not set refresh interval on wildcard %s: %s", canonical_pattern, e)

    # Group the canonical events by their target host index for efficient streaming
    # To keep memory footprint low, we'll process one raw index at a time.
    for raw_index in raw_indices:
        logger.info("Scanning raw index: %s", raw_index)
        
        # Generator that yields (target_index, doc_dict) for bulk_index_iter
        def _doc_generator() -> Iterator[tuple[str, dict]]:
            for hit in client.scroll_search(index=raw_index, query={"match_all": {}}, batch_size=5000):
                stats["raw_docs_scanned"] += 1
                
                doc_id = hit["_id"]
                source = hit.get("_source", {})
                
                canonical_event = map_ecs_to_canonical(
                    doc=source,
                    doc_id=doc_id,
                    index_name=raw_index,
                    case_id=case_id,
                )
                
                if canonical_event:
                    stats["canonical_docs_created"] += 1
                    
                    # Target index: case-{case_id}-canonical-{host}
                    # Replace spaces and special chars in host name just to be safe
                    safe_host = canonical_event.host_name.lower().replace(" ", "-").replace("\\", "-")
                    if not safe_host:
                        safe_host = "unknown"
                        
                    target_index = f"case-{case_id}-canonical-{safe_host}"
                    
                    yield target_index, canonical_event.to_dict()

        # Execute bulk stream with dynamic index routing
        success, errors = client.bulk_index_iter(
            index_name="",  # Not used when yielding tuples
            documents=_doc_generator(),
            dynamic_routing=True,
        )
        
        stats["errors"] += errors
        logger.info("Finished %s: Generated %d canonical events.", raw_index, success)

    # Re-enable refresh interval and force merge
    try:
        client.set_refresh_interval(canonical_pattern, "1s")
        client.force_merge(canonical_pattern, max_num_segments=1)
    except Exception as e:
        logger.debug("Failed to finalize canonical indices: %s", e)

    logger.info(
        "Normalization pass complete! Scanned %d raw docs, generated %d canonical events (%d errors).",
        stats["raw_docs_scanned"],
        stats["canonical_docs_created"],
        stats["errors"]
    )
    
    return stats
