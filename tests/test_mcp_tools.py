"""Tests for MCP server tools."""

from nighteye.mcp.tools.case import case_status
from nighteye.mcp.tools.triage import triage_clusters, profile_host
from nighteye.mcp.tools.cluster import query_clusters, expand_cluster
from nighteye.mcp.tools.hypothesis import record_hypothesis, challenge_hypothesis, mark_insufficient, record_evidence_gap, establish_causation
from nighteye.mcp.tools.journal import journal_checkpoint, journal_decision, journal_query, journal_resume
from nighteye.mcp.tools.report import find_root_cause, generate_report, save_report

def test_imports_and_signatures() -> None:
    # Just asserting the functions are importable and callable
    assert callable(case_status)
    assert callable(triage_clusters)
    assert callable(profile_host)
    assert callable(query_clusters)
    assert callable(expand_cluster)
    assert callable(record_hypothesis)
    assert callable(challenge_hypothesis)
    assert callable(mark_insufficient)
    assert callable(record_evidence_gap)
    assert callable(establish_causation)
    assert callable(journal_checkpoint)
    assert callable(journal_decision)
    assert callable(journal_query)
    assert callable(journal_resume)
    assert callable(find_root_cause)
    assert callable(generate_report)
    assert callable(save_report)
