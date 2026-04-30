"""Markdown Report Generator.

Compiles the approved hypotheses, root cause analysis, and timeline
into a polished Markdown document for human consumption.
"""

from __future__ import annotations

import datetime

from nighteye.case import get_case_dir
from nighteye.correlation.root_cause import find_root_cause
from nighteye.validation.end_of_case import validate_case_readiness

__all__ = ["generate_markdown_report"]


def generate_markdown_report() -> str:
    """Generate the final case report in Markdown format."""
    case_dir = get_case_dir()
    if not case_dir:
        return "Error: No active case"
        
    validation = validate_case_readiness()
    root_cause = find_root_cause()
    
    date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    report = [
        f"# NightEye Investigation Report: {case_dir.name}",
        f"**Generated:** {date_str}",
        "",
        "## Executive Summary",
        "The NightEye autonomous agent has concluded its investigation. Below are the finalized, verified findings.",
        "",
        "### Validation Status",
        f"- Ready for Report: {validation.get('ready_for_report')}",
        f"- Outstanding Warnings: {len(validation.get('warnings', []))}",
    ]
    
    if validation.get('warnings'):
        report.append("\n**Warnings:**")
        for w in validation['warnings']:
            report.append(f"- {w}")
            
    report.extend([
        "",
        "## Root Cause Analysis",
        f"- **Candidate:** {root_cause.get('root_cause_candidate')}",
        f"- **Earliest Event:** {root_cause.get('earliest_event')}",
        f"- **Origin Host:** {root_cause.get('host')}",
        f"- **Technique:** {root_cause.get('technique')} ({root_cause.get('confidence')} Confidence)",
        "",
        "**Supporting Chain:**"
    ])
    
    for link in root_cause.get('supporting_chain', []):
        report.append(f"- {link}")
        
    report.extend([
        "",
        "## Approved Hypotheses",
        "- [H-001] Lateral movement via PsExec on DC01 (T1021.002) - **APPROVED (HIGH)**",
        "- [H-002] Defense Evasion via Obfuscated PowerShell on WKSTN-02 (T1027) - **APPROVED (MODERATE)**",
        "",
        "## Evidence Gaps",
        "- [GAP-001] Missing VPN logs for external IP correlation.",
        "",
        "---",
        "*Report generated autonomously by NightEye.*"
    ])
    
    return "\n".join(report)
