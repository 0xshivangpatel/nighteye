"""Regression tests for the case_id case-sensitivity bug.

Background
==========
On 2026-05-02 a SIFT pipeline run successfully indexed 26.4 million
documents but the normalize/graph/cluster stages all reported zero work
because they were composing wildcards as ``f"case-{case_id}-*"`` while
OpenSearch had auto-lowercased the actual index names. The wildcard
``case-INC-2026-...-*`` therefore matched nothing.

The fix introduces ``case_index_pattern()`` in ``ingest.ecs`` and threads
it through every call site.
"""

from __future__ import annotations

from nighteye.ingest.ecs import (
    case_index_pattern,
    make_index_name,
)


# ============================================================
# Helper itself
# ============================================================


def test_case_index_pattern_lowercases_case_id() -> None:
    """Mixed-case case IDs must produce lowercase patterns."""
    assert case_index_pattern("INC-2026-001") == "case-inc-2026-001-*"


def test_case_index_pattern_default_suffix_is_wildcard() -> None:
    assert case_index_pattern("ABC123") == "case-abc123-*"


def test_case_index_pattern_lowercases_suffix() -> None:
    assert case_index_pattern("INC-001", "EVTX-DC01") == "case-inc-001-evtx-dc01"


def test_case_index_pattern_preserves_wildcards_in_suffix() -> None:
    assert case_index_pattern("INC-001", "canonical-*") == "case-inc-001-canonical-*"


def test_case_index_pattern_handles_double_wildcards() -> None:
    assert case_index_pattern("INC-001", "*-DC01") == "case-inc-001-*-dc01"


def test_case_index_pattern_replaces_spaces_with_dashes() -> None:
    assert case_index_pattern("Case With Space") == "case-case-with-space-*"


def test_case_index_pattern_matches_make_index_name_output() -> None:
    """The wildcard must match what make_index_name actually creates.
    This is the core invariant — break this and the SIFT bug returns."""
    case_id = "INC-2026-0502193028"
    actual_index = make_index_name(case_id, "evtx", "DC01")
    pattern = case_index_pattern(case_id)
    # Strip the trailing '*' for prefix comparison.
    prefix = pattern[:-1]
    assert actual_index.startswith(prefix), (
        f"Index name {actual_index!r} does not start with pattern prefix "
        f"{prefix!r} — wildcard would not match this index in list_indices()."
    )


def test_make_index_name_round_trips_through_pattern() -> None:
    """For every artifact + host, make_index_name and case_index_pattern
    must agree on lowercasing. Catches accidental drift between them."""
    case_id = "Inc-Mixed-Case-2026"
    for artifact, host in [
        ("evtx", "DC01"),
        ("MFT", "win-7-32"),
        ("hayabusa", "WKSTN-01"),
        ("canonical", "host with space"),
    ]:
        idx = make_index_name(case_id, artifact, host)
        pat = case_index_pattern(case_id)
        prefix = pat[:-1]
        assert idx.startswith(prefix), (
            f"Mismatch: index={idx!r}, pattern_prefix={prefix!r}"
        )


# ============================================================
# All caller modules use the helper, not raw f-strings
# ============================================================


def test_canonical_engine_imports_helper() -> None:
    from nighteye.canonical import engine

    assert hasattr(engine, "case_index_pattern"), (
        "canonical.engine must import case_index_pattern (regression: previously"
        " used f-string with mixed-case case_id)"
    )


def test_constructors_base_imports_helper() -> None:
    from nighteye.constructors import base

    assert hasattr(base, "case_index_pattern"), (
        "constructors.base must import case_index_pattern"
    )


def test_graph_imports_helper() -> None:
    from nighteye.graph import graph

    assert hasattr(graph, "case_index_pattern"), (
        "graph.graph must import case_index_pattern"
    )


def test_evidence_tools_imports_helper() -> None:
    from nighteye.mcp.tools import evidence_tools

    assert hasattr(evidence_tools, "case_index_pattern"), (
        "mcp.tools.evidence_tools must import case_index_pattern"
    )


def test_no_source_module_uses_raw_case_id_wildcard() -> None:
    """Static-grep gate: no source module under src/nighteye should use
    the raw ``f"case-{case_id}..."`` pattern that started the bug."""
    import re
    from pathlib import Path

    # Walk the package source tree.
    pkg_root = Path(__file__).parent.parent / "src" / "nighteye"
    assert pkg_root.is_dir(), f"Package root not found: {pkg_root}"

    bad_pattern = re.compile(
        r'(?:f["\']case-\{case_id\})|(?:["\']case-["\'] *\+ *case_id)',
    )
    offenders: list[str] = []
    for py_file in pkg_root.rglob("*.py"):
        if "__pycache__" in py_file.parts:
            continue
        text = py_file.read_text(encoding="utf-8", errors="ignore")
        for lineno, line in enumerate(text.splitlines(), start=1):
            # Allow comments and docstring-style references.
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if "``" in line or '"""' in line or "'''" in line:
                # Heuristic: skip docstring lines.
                continue
            if bad_pattern.search(line):
                offenders.append(f"{py_file.relative_to(pkg_root)}:{lineno}: {line.strip()}")
    assert not offenders, (
        "Found raw case_id wildcard interpolation. Use case_index_pattern() "
        "instead. Offenders:\n  " + "\n  ".join(offenders)
    )
