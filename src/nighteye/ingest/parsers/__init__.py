"""Parser registry — maps artifact types to their parser functions.

Each parser accepts structured tool output (CSV rows, JSON records)
and yields ECS-mapped documents for OpenSearch indexing.
"""

from __future__ import annotations

__all__ = ["PARSER_REGISTRY"]

PARSER_REGISTRY: dict[str, str] = {
    "evtx": "nighteye.ingest.evtx",
    "registry": "nighteye.ingest.parsers.registry",
    "mft": "nighteye.ingest.parsers.mft",
    "prefetch": "nighteye.ingest.parsers.prefetch",
    "amcache": "nighteye.ingest.parsers.amcache",
    "shimcache": "nighteye.ingest.parsers.shimcache",
    "srum": "nighteye.ingest.parsers.srum",
}
