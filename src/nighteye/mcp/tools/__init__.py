"""MCP Tool Definitions for NightEye.

All ~40 tools exposed to the AI agent via Model Context Protocol.
Tools are organized by investigation phase.

References:
  - docs/ARCHITECTURE.md § 9 (Layer 5: Recursive AI Investigation)
"""

from __future__ import annotations

from nighteye.mcp.tools.evidence_tools import *
from nighteye.mcp.tools.cluster_tools import *
from nighteye.mcp.tools.hypothesis_tools import *
from nighteye.mcp.tools.graph_tools import *
from nighteye.mcp.tools.report_tools import *
from nighteye.mcp.tools.case_tools import *

__all__ = [
    # Evidence tools
    "search_evidence",
    "get_evidence_details",
    "list_evidence_types",
    "get_host_timeline",
    "get_process_tree",
    "get_file_history",
    "get_network_connections",
    "get_registry_changes",
    "get_service_changes",
    "get_authentication_events",
    # Cluster tools
    "list_clusters",
    "get_cluster_details",
    "get_cluster_timeline",
    "get_cluster_artifacts",
    "get_cluster_counter_evidence",
    # Hypothesis tools
    "record_hypothesis",
    "challenge_hypothesis",
    "approve_hypothesis",
    "reject_hypothesis",
    "list_hypotheses",
    "get_hypothesis_details",
    "establish_causation",
    "mark_insufficient_evidence",
    # Graph tools
    "query_entity",
    "query_neighbors",
    "find_path",
    "get_entity_details",
    "search_entities",
    # Report tools
    "generate_report",
    "get_report_status",
    "export_evidence",
    # Case tools
    "get_case_status",
    "get_case_summary",
    "list_hosts",
    "get_evidence_gaps",
    "get_disturbances",
]
