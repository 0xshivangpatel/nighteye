"""Markdown Report Generator.

Compiles the approved hypotheses, root cause analysis, and timeline
into a polished Markdown document for human consumption.
"""

from __future__ import annotations

import datetime
import json

from nighteye.case import get_active_case, get_case_dir
from nighteye.correlation.root_cause import find_root_cause
from nighteye.validation.end_of_case import validate_case_readiness
from nighteye.db import connect

__all__ = ["generate_markdown_report"]


def generate_markdown_report() -> str:
    """Generate the final case report in Markdown format."""
    case = get_active_case()
    if not case:
        return "Error: No active case"

    validation = validate_case_readiness()
    root_cause = find_root_cause()

    date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = [
        f"# NightEye Investigation Report: {case.case_name}",
        f"**Case ID:** {case.id}",
        f"**Examiner:** {case.examiner}",
        f"**Generated:** {date_str}",
        "",
        "## Executive Summary",
        "The NightEye autonomous agent has concluded its investigation. "
        "Below are the finalized, verified findings.",
        "",
        "### Validation Status",
        f"- Ready for Report: {validation.get('ready_for_report', 'N/A')}",
        f"- Status: {validation.get('status', 'UNKNOWN')}",
    ]

    blockers = validation.get("blockers", [])
    warnings = validation.get("warnings", [])

    if blockers:
        report.append("\n### Blockers")
        for b in blockers:
            report.append(f"- **BLOCKED:** {b}")

    if warnings:
        report.append("\n### Warnings")
        for w in warnings:
            report.append(f"- {w}")

    # Root cause
    report.extend([
        "",
        "## Root Cause Analysis",
    ])

    if root_cause.get("found"):
        root = root_cause.get("root", {})
        report.extend([
            f"- **Root Hypothesis:** {root.get('hypothesis_id', 'N/A')} — {root.get('title', 'N/A')}",
            f"- **Techniques:** {', '.join(root.get('technique_ids', []))}",
            f"- **Confidence:** {root.get('confidence_tier', 'N/A')}",
        ])

        kill_chain = root_cause.get("kill_chain", [])
        if kill_chain:
            report.append("\n### Kill Chain")
            for step in kill_chain:
                link_info = step.get("link_level_to_next", "")
                link_str = f" → [{link_info}]" if link_info else ""
                report.append(
                    f"- **{step['hypothesis_id']}**: {step['title']} "
                    f"({', '.join(step.get('technique_ids', []))}{link_str})"
                )
    else:
        report.append(f"- {root_cause.get('reason', 'No root cause found.')}")

    gaps = root_cause.get("gaps", [])
    if gaps:
        report.append("\n### Root Cause Gaps")
        for g in gaps:
            report.append(f"- {g}")

    # Approved hypotheses
    report.extend([
        "",
        "## Approved Hypotheses",
    ])

    with connect(case.graph_db, read_only=True) as conn:
        approved = conn.execute(
            """
            SELECT hypothesis_id, title, observation, interpretation,
                   technique_ids, confidence_score, confidence_tier, approved_at
            FROM hypotheses
            WHERE case_id = ? AND status = 'APPROVED'
            ORDER BY staged_at ASC
            """,
            (case.id,),
        ).fetchall()

        if approved:
            for row in approved:
                tids = []
                try:
                    tids = json.loads(row["technique_ids"]) if row["technique_ids"] else []
                except (TypeError, ValueError):
                    pass

                report.append(
                    f"- **[{row['hypothesis_id']}]** {row['title']} "
                    f"({' / '.join(tids) if tids else 'no techniques'}) — "
                    f"**{row['confidence_tier']}** (score: {row['confidence_score']})"
                )
        else:
            report.append("- No approved hypotheses yet.")

        # Evidence gaps
        gaps_rows = conn.execute(
            """
            SELECT gap_id, question, what_would_resolve, blocks_hypothesis
            FROM evidence_gaps
            WHERE case_id = ? AND resolved_at IS NULL
            ORDER BY registered_at DESC
            """,
            (case.id,),
        ).fetchall()

        if gaps_rows:
            report.extend([
                "",
                "## Evidence Gaps",
            ])
            for g in gaps_rows:
                report.append(
                    f"- **[{g['gap_id']}]** {g['question']}"
                    f" — Resolve with: {g['what_would_resolve']}"
                )

    report.extend([
        "",
        "---",
        "*Report generated autonomously by NightEye.*",
    ])

    return "\n".join(report)
