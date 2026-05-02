"""NightEye MCP Server.

Model Context Protocol server exposing all investigation tools to AI agents.
Runs on port 4509 alongside the Portal on 4510.

References:
  - docs/ARCHITECTURE.md § 9 (Layer 5: Recursive AI Investigation)
"""

from __future__ import annotations

import logging
from typing import Any

from fastmcp import FastMCP

from nighteye.mcp.tools.evidence_tools import (
    search_evidence,
    get_evidence_details,
    list_evidence_types,
    get_host_timeline,
    get_process_tree,
    get_file_history,
    get_network_connections,
    get_registry_changes,
    get_service_changes,
    get_authentication_events,
)
from nighteye.mcp.tools.cluster_tools import (
    list_clusters,
    get_cluster_details,
    get_cluster_timeline,
    get_cluster_artifacts,
    get_cluster_counter_evidence,
)
from nighteye.mcp.tools.hypothesis_tools import (
    record_hypothesis,
    challenge_hypothesis,
    approve_hypothesis,
    reject_hypothesis,
    list_hypotheses,
    get_hypothesis_details,
    establish_causation,
    mark_insufficient_evidence,
)
from nighteye.mcp.tools.graph_tools import (
    query_entity,
    query_neighbors,
    find_path,
    get_entity_details,
    search_entities,
)
from nighteye.mcp.tools.report_tools import (
    generate_report,
    get_report_status,
    export_evidence,
)
from nighteye.mcp.tools.case_tools import (
    get_case_status,
    get_case_summary,
    list_hosts,
    get_evidence_gaps,
    get_disturbances,
)
from nighteye.mcp.tools.journal_tools import (
    journal_checkpoint,
    journal_record_decision,
    journal_query,
    journal_resume,
)
from nighteye.correlation.root_cause import find_root_cause as find_root_cause_impl
from nighteye.validation.end_of_case import validate_case_readiness as validate_case_readiness_impl

__all__ = ["create_mcp_server"]

logger = logging.getLogger("nighteye.mcp.server")

# ============================================================
# Server Factory
# ============================================================

def create_mcp_server() -> FastMCP:
    """Create and configure the NightEye MCP server with all tools."""

    mcp = FastMCP("NightEye")

    # ========================================================
    # Evidence Tools (~10 tools)
    # ========================================================

    @mcp.tool()
    def tool_search_evidence(
        case_id: str,
        query: str,
        evidence_type: str | None = None,
        host: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Search evidence using natural language or structured query.

        Use this to find specific events, processes, files, or network connections.
        Examples:
        - query="powershell -enc" → find encoded PowerShell commands
        - query="file.path:*.exe" AND host="WKSTN-01" → find EXE files on specific host
        - query="destination.ip:192.168.1.100" → find connections to specific IP
        """
        return search_evidence(case_id, query, evidence_type, host, start_time, end_time, limit)

    @mcp.tool()
    def tool_get_evidence_details(
        case_id: str,
        evidence_id: str,
        index_name: str,
    ) -> dict[str, Any]:
        """Get full details of a specific evidence document.

        Use when you need to examine the raw fields of a specific event.
        """
        return get_evidence_details(case_id, evidence_id, index_name)

    @mcp.tool()
    def tool_list_evidence_types(
        case_id: str,
    ) -> dict[str, Any]:
        """List all evidence types available for a case.

        Use to understand what data sources are available.
        """
        return list_evidence_types(case_id)

    @mcp.tool()
    def tool_get_host_timeline(
        case_id: str,
        host: str,
        start_time: str | None = None,
        end_time: str | None = None,
        granularity: str = "minute",
    ) -> dict[str, Any]:
        """Get chronological timeline of all events for a host.

        Use to understand the sequence of activity on a specific host.
        """
        return get_host_timeline(case_id, host, start_time, end_time, granularity)

    @mcp.tool()
    def tool_get_process_tree(
        case_id: str,
        host: str,
        root_pid: int | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> dict[str, Any]:
        """Get process execution tree for a host.

        Use to understand parent-child relationships of processes.
        """
        return get_process_tree(case_id, host, root_pid, start_time, end_time)

    @mcp.tool()
    def tool_get_file_history(
        case_id: str,
        host: str,
        file_path: str,
    ) -> dict[str, Any]:
        """Get history of a specific file (creation, modification, deletion).

        Use to track a suspicious file across time.
        """
        return get_file_history(case_id, host, file_path)

    @mcp.tool()
    def tool_get_network_connections(
        case_id: str,
        host: str | None = None,
        remote_ip: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> dict[str, Any]:
        """Get network connection events.

        Use to find C2 beaconing, lateral movement, or data exfiltration.
        """
        return get_network_connections(case_id, host, remote_ip, start_time, end_time)

    @mcp.tool()
    def tool_get_registry_changes(
        case_id: str,
        host: str | None = None,
        registry_key: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> dict[str, Any]:
        """Get registry modification events.

        Use to find persistence mechanisms or configuration changes.
        """
        return get_registry_changes(case_id, host, registry_key, start_time, end_time)

    @mcp.tool()
    def tool_get_service_changes(
        case_id: str,
        host: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> dict[str, Any]:
        """Get service installation and modification events.

        Use to find persistence via Windows services.
        """
        return get_service_changes(case_id, host, start_time, end_time)

    @mcp.tool()
    def tool_get_authentication_events(
        case_id: str,
        host: str | None = None,
        user: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> dict[str, Any]:
        """Get authentication events (logon, logoff, failure).

        Use to find lateral movement, brute force, or unauthorized access.
        """
        return get_authentication_events(case_id, host, user, start_time, end_time)

    # ========================================================
    # Cluster Tools (~5 tools)
    # ========================================================

    @mcp.tool()
    def tool_list_clusters(
        case_id: str,
        constructor_name: str | None = None,
        host: str | None = None,
        min_score: int = 0,
        status: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List behavioral clusters for a case.

        Use to see pre-computed attack behaviors. These are the AI's starting point
        for investigation — they contain pre-attached counter-evidence.
        """
        return list_clusters(case_id, constructor_name, host, min_score, status, limit)

    @mcp.tool()
    def tool_get_cluster_details(
        cluster_id: str,
    ) -> dict[str, Any]:
        """Get full details of a specific cluster.

        Use to examine a behavioral cluster's trigger, signals, and counter-evidence.
        """
        return get_cluster_details(cluster_id)

    @mcp.tool()
    def tool_get_cluster_timeline(
        cluster_id: str,
    ) -> dict[str, Any]:
        """Get chronological timeline of events within a cluster.

        Use to understand the sequence of events that make up a behavior.
        """
        return get_cluster_timeline(cluster_id)

    @mcp.tool()
    def tool_get_cluster_artifacts(
        cluster_id: str,
    ) -> dict[str, Any]:
        """Get all artifacts (raw evidence) associated with a cluster.

        Use to examine the underlying evidence documents.
        """
        return get_cluster_artifacts(cluster_id)

    @mcp.tool()
    def tool_get_cluster_counter_evidence(
        cluster_id: str,
    ) -> dict[str, Any]:
        """Get counter-evidence attached to a cluster.

        Use to challenge your own conclusions — every cluster comes with
        pre-computed reasons it might be a false positive.
        """
        return get_cluster_counter_evidence(cluster_id)

    # ========================================================
    # Hypothesis Tools (~8 tools)
    # ========================================================

    @mcp.tool()
    def tool_record_hypothesis(
        title: str,
        observation: str,
        interpretation: str,
        technique_ids: list[str],
        evidence_refs: list[dict[str, Any]],
        causal_links: list[dict[str, Any]] | None = None,
        suggested_by_cluster: str | None = None,
        examiner: str | None = None,
        case_id: str | None = None,
    ) -> dict[str, Any]:
        """Record a new investigation hypothesis.

        Use to formalize your findings. The system will validate against hard gates
        (provenance, confidence, causation, anti-forensic proximity).

        Evidence refs format:
        [{"audit_id": "...", "description": "...", "cluster_id": "..."}]
        """
        return record_hypothesis(
            title, observation, interpretation, technique_ids,
            evidence_refs, causal_links, suggested_by_cluster, examiner, case_id
        )

    @mcp.tool()
    def tool_challenge_hypothesis(
        hypothesis_id: str,
    ) -> dict[str, Any]:
        """Run adversarial review on a hypothesis.

        Use to critically examine a hypothesis against counter-evidence
        and contradictions. This is the 'red team' function.
        """
        return challenge_hypothesis(hypothesis_id)

    @mcp.tool()
    def tool_approve_hypothesis(
        hypothesis_id: str,
        approved_by: str,
    ) -> dict[str, Any]:
        """Explicitly approve a hypothesis.

        Use to finalize a finding. Auto-approval happens at score ≥76
        with MCP provenance and clean anti-forensic window.
        """
        return approve_hypothesis(hypothesis_id, approved_by)

    @mcp.tool()
    def tool_reject_hypothesis(
        hypothesis_id: str,
        rejected_by: str,
        reason: str,
    ) -> dict[str, Any]:
        """Reject a hypothesis.

        Use when evidence does not support the conclusion.
        """
        return reject_hypothesis(hypothesis_id, rejected_by, reason)

    @mcp.tool()
    def tool_list_hypotheses(
        case_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List hypotheses with optional filtering.

        Use to track the investigation state.
        """
        return list_hypotheses(case_id, status, limit)

    @mcp.tool()
    def tool_get_hypothesis_details(
        hypothesis_id: str,
    ) -> dict[str, Any]:
        """Get full details of a hypothesis.

        Use to examine a hypothesis's evidence, confidence, and causal links.
        """
        return get_hypothesis_details(hypothesis_id)

    @mcp.tool()
    def tool_establish_causation(
        from_hypothesis_id: str,
        to_hypothesis_id: str,
        level: str,
        proof_audit_ids: list[str],
        proof_edges: list[str] | None = None,
        notes: str = "",
    ) -> dict[str, Any]:
        """Establish a causal link between two hypotheses.

        Use to build attack chains. Levels: CHAIN, WRITE, NET, TIGHT_TIME, CO_OCCUR, TEMPORAL_ONLY, UNSUPPORTED.
        """
        return establish_causation(
            from_hypothesis_id, to_hypothesis_id, level,
            proof_audit_ids, proof_edges, notes
        )

    @mcp.tool()
    def tool_mark_insufficient_evidence(
        title: str,
        observation: str,
        interpretation: str,
        technique_ids: list[str],
        evidence_refs: list[dict[str, Any]],
        reason: str,
        what_would_resolve: str = "",
        examiner: str | None = None,
        case_id: str | None = None,
    ) -> dict[str, Any]:
        """Mark a hypothesis as insufficient evidence.

        Use when you need more data to reach a conclusion. Registers an evidence gap.
        """
        return mark_insufficient_evidence(
            title, observation, interpretation, technique_ids,
            evidence_refs, reason, what_would_resolve, examiner, case_id
        )

    # ========================================================
    # Graph Tools (~5 tools)
    # ========================================================

    @mcp.tool()
    def tool_query_entity(
        entity_id: str,
    ) -> dict[str, Any]:
        """Query a single entity by ID.

        Use to get details of a specific host, process, file, user, or network entity.
        """
        return query_entity(entity_id)

    @mcp.tool()
    def tool_query_neighbors(
        entity_id: str,
        edge_type: str | None = None,
        direction: str = "both",
    ) -> dict[str, Any]:
        """Query neighbors of an entity.

        Use to find related entities (e.g., what files did this process write?).
        """
        return query_neighbors(entity_id, edge_type, direction)

    @mcp.tool()
    def tool_find_path(
        from_entity_id: str,
        to_entity_id: str,
        max_depth: int = 5,
    ) -> dict[str, Any]:
        """Find paths between two entities.

        Use to trace attack chains (e.g., how did the attacker get from initial access to domain admin?).
        """
        return find_path(from_entity_id, to_entity_id, max_depth)

    @mcp.tool()
    def tool_get_entity_details(
        entity_id: str,
        include_neighbors: bool = True,
    ) -> dict[str, Any]:
        """Get comprehensive entity details including neighbors.

        Use for deep-dive into a specific entity's context.
        """
        return get_entity_details(entity_id, include_neighbors)

    @mcp.tool()
    def tool_search_entities(
        case_id: str,
        entity_type: str | None = None,
        canonical_key_pattern: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Search entities by type or key pattern.

        Use to find entities matching a pattern (e.g., all processes named 'powershell.exe').
        """
        return search_entities(case_id, entity_type, canonical_key_pattern, limit)

    # ========================================================
    # Report Tools (~3 tools)
    # ========================================================

    @mcp.tool()
    def tool_generate_report(
        case_id: str | None = None,
        format: str = "json",
        include_evidence: bool = True,
        include_hypotheses: bool = True,
        include_clusters: bool = True,
        include_timeline: bool = True,
    ) -> dict[str, Any]:
        """Generate a comprehensive investigation report.

        Use to produce the final deliverable. Formats: json, markdown, html.
        """
        return generate_report(
            case_id, format, include_evidence, include_hypotheses,
            include_clusters, include_timeline
        )

    @mcp.tool()
    def tool_get_report_status(
        case_id: str | None = None,
    ) -> dict[str, Any]:
        """Get report readiness status for a case.

        Use to check if the investigation has enough approved hypotheses to report.
        """
        return get_report_status(case_id)

    @mcp.tool()
    def tool_export_evidence(
        case_id: str | None = None,
        evidence_type: str | None = None,
        host: str | None = None,
        format: str = "json",
        output_path: str | None = None,
    ) -> dict[str, Any]:
        """Export evidence to file.

        Use to extract raw evidence for external analysis.
        """
        return export_evidence(case_id, evidence_type, host, format, output_path)

    # ========================================================
    # Case Tools (~5 tools)
    # ========================================================

    @mcp.tool()
    def tool_get_case_status(
        case_id: str | None = None,
    ) -> dict[str, Any]:
        """Get current case status and progress.

        Use to understand the investigation state at a glance.
        """
        return get_case_status(case_id)

    @mcp.tool()
    def tool_get_case_summary(
        case_id: str | None = None,
    ) -> dict[str, Any]:
        """Get executive summary of case findings.

        Use for high-level understanding of what was found.
        """
        return get_case_summary(case_id)

    @mcp.tool()
    def tool_list_hosts(
        case_id: str | None = None,
    ) -> dict[str, Any]:
        """List all hosts in a case with cluster counts.

        Use to identify which hosts have the most suspicious activity.
        """
        return list_hosts(case_id)

    @mcp.tool()
    def tool_get_evidence_gaps(
        case_id: str | None = None,
    ) -> dict[str, Any]:
        """Get all evidence gaps for a case.

        Use to find unanswered questions that need more evidence.
        """
        return get_evidence_gaps(case_id)

    @mcp.tool()
    def tool_get_disturbances(
        case_id: str | None = None,
        host: str | None = None,
    ) -> dict[str, Any]:
        """Get evidence disturbances (anti-forensic windows).

        Use to identify time windows where evidence may have been tampered with.
        """
        return get_disturbances(case_id, host)

    # ========================================================
    # Journal Tools (Layer 6: Persistent Investigation State)
    # ========================================================

    @mcp.tool()
    def tool_journal_checkpoint(
        summary: str,
        next_steps: list[str] | None = None,
        case_id: str | None = None,
        agent_session_id: str | None = None,
    ) -> dict[str, Any]:
        """Record a CHECKPOINT_SUMMARY journal entry.

        Call this before context approaches exhaustion or when a phase of
        the investigation is complete. The next session reads this via
        journal_resume to know where to pick up.
        """
        return journal_checkpoint(summary, next_steps, case_id, agent_session_id)

    @mcp.tool()
    def tool_journal_record_decision(
        summary: str,
        rationale: str,
        hypotheses_considered: list[str] | None = None,
        case_id: str | None = None,
        agent_session_id: str | None = None,
    ) -> dict[str, Any]:
        """Record an INVESTIGATION_DECISION entry capturing reasoning.

        Use at decision points: pivots, hypothesis selection, when ruling
        out paths. The rationale becomes part of the final report.
        """
        return journal_record_decision(
            summary, rationale, hypotheses_considered, case_id, agent_session_id
        )

    @mcp.tool()
    def tool_journal_query(
        limit: int = 20,
        entry_type: str | None = None,
        case_id: str | None = None,
    ) -> dict[str, Any]:
        """Return recent journal entries, newest first."""
        return journal_query(limit, entry_type, case_id)

    @mcp.tool()
    def tool_journal_resume(case_id: str | None = None) -> dict[str, Any]:
        """Build the session-resume digest. First call in any session.

        Returns a compact summary of prior session state, hypothesis counts,
        recent findings, open evidence gaps, and suggested next actions.
        """
        return journal_resume(case_id)

    # ========================================================
    # Correlation + Validation
    # ========================================================

    @mcp.tool()
    def tool_find_root_cause(case_id: str | None = None) -> dict[str, Any]:
        """Walk approved hypotheses backward to identify the root cause.

        Returns the earliest causally-supported event and the kill chain
        derived from approved findings + causal links.
        """
        return find_root_cause_impl(case_id)

    @mcp.tool()
    def tool_validate_case_readiness(case_id: str | None = None) -> dict[str, Any]:
        """End-of-case validation pass.

        Reports DRAFT hypotheses, contradicting causal links, and unresolved
        evidence gaps that block report generation.
        """
        return validate_case_readiness_impl(case_id)

    # FastMCP exposes registered tools via the public iterator; fall back
    # to private attribute only if the public attribute is absent.
    try:
        tool_count = len(list(mcp.list_tools()))  # type: ignore[attr-defined]
    except Exception:
        tool_count = len(getattr(mcp, "_tools", {}))
    logger.info("MCP server created with %d tools", tool_count)
    return mcp


# ============================================================
# Entry Point
# ============================================================

def main() -> None:
    """Run the MCP server."""
    import uvicorn

    mcp = create_mcp_server()
    # FastMCP with streamable HTTP transport
    uvicorn.run(mcp.app, host="0.0.0.0", port=4509)


if __name__ == "__main__":
    main()
