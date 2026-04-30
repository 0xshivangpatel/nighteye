"""Ingest pipeline — evidence file detection, routing, and orchestration.

This package handles the first two layers of NightEye's stack:
- L1: Wide evidence ingestion (EZ Tools, Hayabusa, Chainsaw, Vol3, etc.)
- L2: Canonical event store (OpenSearch, ECS v8.x mapping)

Submodules:
- dispatch: detect file types and route to appropriate parsers
- ecs: ECS field mapping helpers + NightEye extension fields
- opensearch_client: async OpenSearch wrapper with bulk indexer
- index_template: installs the case-* index template
"""

from __future__ import annotations

__all__: list[str] = []
