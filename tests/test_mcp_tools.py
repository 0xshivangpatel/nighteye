"""Smoke + unit tests for the production MCP tool modules.

These exercise the *_tools.py modules that are wired into the MCP server,
not the deprecated thin stubs (which were deleted). The MCP server itself
requires fastmcp; we don't import that here so the tests collect even
when fastmcp is absent.
"""

from __future__ import annotations

import importlib

import pytest


PRODUCTION_TOOL_MODULES = [
    "nighteye.mcp.tools.case_tools",
    "nighteye.mcp.tools.cluster_tools",
    "nighteye.mcp.tools.evidence_tools",
    "nighteye.mcp.tools.graph_tools",
    "nighteye.mcp.tools.hypothesis_tools",
    "nighteye.mcp.tools.journal_tools",
    "nighteye.mcp.tools.report_tools",
]

# Tool callables expected to be exported from each module.
EXPECTED_EXPORTS = {
    "nighteye.mcp.tools.case_tools": [
        "get_case_status",
        "get_case_summary",
        "list_hosts",
        "get_evidence_gaps",
        "get_disturbances",
    ],
    "nighteye.mcp.tools.cluster_tools": [
        "list_clusters",
        "get_cluster_details",
        "get_cluster_timeline",
        "get_cluster_artifacts",
        "get_cluster_counter_evidence",
    ],
    "nighteye.mcp.tools.evidence_tools": [
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
    ],
    "nighteye.mcp.tools.graph_tools": [
        "query_entity",
        "query_neighbors",
        "find_path",
        "get_entity_details",
        "search_entities",
    ],
    "nighteye.mcp.tools.hypothesis_tools": [
        "record_hypothesis",
        "challenge_hypothesis",
        "approve_hypothesis",
        "reject_hypothesis",
        "list_hypotheses",
        "get_hypothesis_details",
        "establish_causation",
        "mark_insufficient_evidence",
    ],
    "nighteye.mcp.tools.journal_tools": [
        "journal_checkpoint",
        "journal_record_decision",
        "journal_query",
        "journal_resume",
    ],
    "nighteye.mcp.tools.report_tools": [
        "generate_report",
        "get_report_status",
        "export_evidence",
    ],
}


@pytest.mark.parametrize("module_name", PRODUCTION_TOOL_MODULES)
def test_tool_module_imports(module_name: str) -> None:
    """Each production tool module must import without side effects."""
    importlib.import_module(module_name)


@pytest.mark.parametrize(
    "module_name,expected",
    [(m, e) for m, exports in EXPECTED_EXPORTS.items() for e in exports],
)
def test_expected_tool_callables_exist(module_name: str, expected: str) -> None:
    """Each expected tool function must be importable and callable."""
    mod = importlib.import_module(module_name)
    fn = getattr(mod, expected, None)
    assert fn is not None, f"{module_name} missing expected export: {expected}"
    assert callable(fn), f"{module_name}.{expected} is not callable"


def test_journal_tools_real_persist(nighteye_home, cases_dir) -> None:
    """Journal MCP tool wrappers must round-trip through SQLite, not return fakes."""
    from nighteye.case import init_case
    from nighteye.mcp.tools.journal_tools import (
        journal_checkpoint,
        journal_query,
        journal_record_decision,
        journal_resume,
    )

    case = init_case(name="journal-test", examiner="alice", cases_dir=cases_dir)

    cp = journal_checkpoint(
        summary="Phase 1 complete",
        next_steps=["investigate cluster X"],
        case_id=case.case_id,
    )
    assert cp["success"] is True
    assert cp["entry_id"].startswith("jnl-")

    dec = journal_record_decision(
        summary="Pivot to lateral movement",
        rationale="Found suspicious 4624 events",
        case_id=case.case_id,
    )
    assert dec["success"] is True

    q = journal_query(case_id=case.case_id)
    assert q["success"] is True
    assert len(q["entries"]) >= 2

    summaries = [e["summary"] for e in q["entries"]]
    assert "Phase 1 complete" in summaries
    assert "Pivot to lateral movement" in summaries

    digest = journal_resume(case_id=case.case_id)
    assert digest["success"] is True
    assert digest["case_id"] == case.case_id
    # checkpoint stored next_steps in details
    assert digest["last_session_end"]["summary"] == "Phase 1 complete"
    assert digest["next_suggested_actions"] == ["investigate cluster X"]
