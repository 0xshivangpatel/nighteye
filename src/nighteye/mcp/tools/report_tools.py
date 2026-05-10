"""MCP Report Generation Tools.

Tools for generating investigation reports and exporting evidence.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from nighteye.db import connect
from nighteye.case import get_active_case
from nighteye.mcp.tools._resolve import resolve_case_db, load_case_info

__all__ = [
    "generate_report",
    "get_report_status",
    "export_evidence",
]

logger = logging.getLogger("nighteye.mcp.tools.report")

# ============================================================
# Report Generation
# ============================================================

def generate_report(
    case_id: str | None = None,
    format: str = "json",
    include_evidence: bool = True,
    include_hypotheses: bool = True,
    include_clusters: bool = True,
    include_timeline: bool = True,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Generate a comprehensive investigation report.

    Args:
        case_id: Case ID (defaults to active case)
        format: Output format (json, markdown, html)
        include_evidence: Include raw evidence references
        include_hypotheses: Include all hypotheses
        include_clusters: Include behavioral clusters
        include_timeline: Include chronological timeline
        db_path: Path to graph.db

    Returns:
        Report data or file path
    """
    case_id, db_path, err = resolve_case_db(case_id, db_path)
    if err:
        return {"success": False, "error": err}

    case_info = load_case_info(case_id, db_path)
    if not case_info:
        return {"success": False, "error": f"Case metadata not found for {case_id}"}

    try:
        with connect(db_path, read_only=True) as conn:
            # Get hypotheses (approved + rejected + contradicted)
            hypotheses = []
            if include_hypotheses:
                rows = conn.execute(
                    """
                    SELECT * FROM hypotheses
                    WHERE case_id = ? AND status IN ('APPROVED', 'REJECTED', 'CONTRADICTED')
                    ORDER BY staged_at DESC
                    """,
                    (case_id,),
                ).fetchall()
                for row in rows:
                    h = dict(row)
                    # Parse JSON fields
                    for field in ["technique_ids", "evidence_refs", "audit_ids",
                                  "confidence_breakdown", "causal_links"]:
                        if h.get(field):
                            try:
                                h[field] = json.loads(h[field])
                            except (json.JSONDecodeError, TypeError):
                                pass
                    hypotheses.append(h)

            # Get clusters — use the actual schema column names
            clusters = []
            if include_clusters:
                rows = conn.execute(
                    """
                    SELECT cluster_id,
                           cluster_type AS constructor_name,
                           primary_host AS host,
                           score, strength,
                           triggers_fired,
                           summary, created_at
                    FROM clusters WHERE case_id = ?
                    ORDER BY score DESC
                    """,
                    (case_id,),
                ).fetchall()
                for row in rows:
                    c = dict(row)
                    if c.get("triggers_fired"):
                        try:
                            triggers = json.loads(c["triggers_fired"])
                            c["trigger_name"] = triggers[0] if triggers else ""
                        except (json.JSONDecodeError, TypeError):
                            c["trigger_name"] = ""
                    else:
                        c["trigger_name"] = ""
                    clusters.append(c)

            # Get evidence gaps
            gaps = []
            rows = conn.execute(
                "SELECT * FROM evidence_gaps WHERE case_id = ? ORDER BY registered_at DESC",
                (case_id,),
            ).fetchall()
            gaps = [dict(row) for row in rows]

            # Get disturbances
            disturbances = []
            rows = conn.execute(
                "SELECT * FROM evidence_disturbances WHERE case_id = ? ORDER BY window_start DESC",
                (case_id,),
            ).fetchall()
            disturbances = [dict(row) for row in rows]

            # Get timeline (simplified)
            timeline = []
            if include_timeline:
                rows = conn.execute(
                    """
                    SELECT timestamp, edge_type, from_entity, to_entity 
                    FROM edges WHERE case_id = ?
                    ORDER BY timestamp ASC
                    LIMIT 1000
                    """,
                    (case_id,),
                ).fetchall()
                timeline = [
                    {
                        "timestamp": row["timestamp"],
                        "event": f"{row['edge_type']}: {row['from_entity']} → {row['to_entity']}",
                    }
                    for row in rows
                ]

            # Get entity counts
            entity_counts = {}
            for etype in ["host", "process", "file", "user", "network", "registry", "service"]:
                count = conn.execute(
                    "SELECT COUNT(*) FROM entities WHERE case_id = ? AND entity_type = ?",
                    (case_id, etype),
                ).fetchone()[0]
                entity_counts[etype] = count

            report = {
                "case": {
                    "id": case_info.get("case_id"),
                    "name": case_info.get("name") or case_info.get("case_name"),
                    "examiner": case_info.get("examiner"),
                    "created_at": case_info.get("created_at"),
                    "status": case_info.get("status"),
                },
                "summary": {
                    "total_hypotheses": len(hypotheses),
                    "approved_hypotheses": sum(1 for h in hypotheses if h.get("status") == "APPROVED"),
                    "rejected_hypotheses": sum(1 for h in hypotheses if h.get("status") == "REJECTED"),
                    "contradicted_hypotheses": sum(1 for h in hypotheses if h.get("status") == "CONTRADICTED"),
                    "total_clusters": len(clusters),
                    "total_entities": sum(entity_counts.values()),
                    "entity_breakdown": entity_counts,
                    "evidence_gaps": len(gaps),
                    "evidence_disturbances": len(disturbances),
                },
                "hypotheses": hypotheses,
                "clusters": clusters,
                "evidence_gaps": gaps,
                "disturbances": disturbances,
                "timeline": timeline,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }

            if format == "json":
                return {"success": True, "format": "json", "report": report}

            elif format == "markdown":
                md = _generate_markdown(report)
                return {"success": True, "format": "markdown", "content": md}

            elif format == "html":
                html = _generate_html(report)
                return {"success": True, "format": "html", "content": html}

            else:
                return {"success": False, "error": f"Unsupported format: {format}"}

    except Exception as exc:
        logger.exception("Failed to generate report")
        return {"success": False, "error": f"Internal error: {exc}"}


def get_report_status(
    case_id: str | None = None,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Get report readiness status for a case.

    Returns:
        Status metrics
    """
    case_id, db_path, err = resolve_case_db(case_id, db_path)
    if err:
        return {"success": False, "error": err}

    try:
        with connect(db_path, read_only=True) as conn:
            # Count key metrics
            hypotheses = conn.execute(
                "SELECT COUNT(*) FROM hypotheses WHERE case_id = ?", (case_id,)
            ).fetchone()[0]

            approved = conn.execute(
                "SELECT COUNT(*) FROM hypotheses WHERE case_id = ? AND status = 'APPROVED'",
                (case_id,),
            ).fetchone()[0]

            clusters = conn.execute(
                "SELECT COUNT(*) FROM clusters WHERE case_id = ?", (case_id,)
            ).fetchone()[0]

            entities = conn.execute(
                "SELECT COUNT(*) FROM entities WHERE case_id = ?", (case_id,)
            ).fetchone()[0]

            edges = conn.execute(
                "SELECT COUNT(*) FROM edges WHERE case_id = ?", (case_id,)
            ).fetchone()[0]

            gaps = conn.execute(
                "SELECT COUNT(*) FROM evidence_gaps WHERE case_id = ?", (case_id,)
            ).fetchone()[0]

            disturbances = conn.execute(
                "SELECT COUNT(*) FROM evidence_disturbances WHERE case_id = ?", (case_id,)
            ).fetchone()[0]

            return {
                "success": True,
                "case_id": case_id,
                "ready": approved >= 1 and clusters >= 1,
                "metrics": {
                    "hypotheses": hypotheses,
                    "approved": approved,
                    "clusters": clusters,
                    "entities": entities,
                    "edges": edges,
                    "evidence_gaps": gaps,
                    "disturbances": disturbances,
                },
            }
    except Exception as exc:
        logger.exception("Failed to get report status")
        return {"success": False, "error": f"Internal error: {exc}"}


def export_evidence(
    case_id: str | None = None,
    evidence_type: str | None = None,
    host: str | None = None,
    format: str = "json",
    output_path: str | None = None,
    client: Any | None = None,
) -> dict[str, Any]:
    """Export evidence to file.

    Args:
        case_id: Case ID
        evidence_type: Filter by type
        host: Filter by host
        format: json, csv, or ndjson
        output_path: Output file path (auto-generated if not provided)
        client: NightEyeOSClient

    Returns:
        Export result with file path
    """
    if not case_id:
        active = get_active_case()
        if not active:
            return {"success": False, "error": "No active case"}
        case_id = active.id

    if not output_path:
        from pathlib import Path
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = f"/tmp/nighteye_export_{case_id}_{ts}.{format}"

    try:
        from nighteye.mcp.tools.evidence_tools import search_evidence

        results = search_evidence(
            case_id=case_id,
            query="*" if not evidence_type else f"canonical_type:{evidence_type}",
            host=host,
            limit=10000,
            client=client,
        )

        if format == "json":
            with open(output_path, "w") as f:
                json.dump(results["results"], f, indent=2, default=str)

        elif format == "ndjson":
            with open(output_path, "w") as f:
                for r in results["results"]:
                    f.write(json.dumps(r, default=str) + "\n")

        elif format == "csv":
            import csv
            if results["results"]:
                keys = set()
                for r in results["results"]:
                    keys.update(r.keys())
                keys = sorted(keys)

                with open(output_path, "w", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=keys)
                    writer.writeheader()
                    for r in results["results"]:
                        writer.writerow({k: str(r.get(k, "")) for k in keys})

        else:
            return {"success": False, "error": f"Unsupported format: {format}"}

        return {
            "success": True,
            "output_path": output_path,
            "record_count": len(results["results"]),
            "format": format,
        }

    except Exception as exc:
        logger.exception("Failed to export evidence")
        return {"success": False, "error": f"Internal error: {exc}"}


# ============================================================
# Report Formatters
# ============================================================

def _generate_markdown(report: dict[str, Any]) -> str:
    """Generate Markdown report."""
    lines = []
    case = report["case"]
    summary = report["summary"]

    lines.append(f"# Investigation Report: {case['name']}")
    lines.append(f"**Case ID:** {case['id']}  ")
    lines.append(f"**Examiner:** {case['examiner']}  ")
    lines.append(f"**Generated:** {report['generated_at']}  ")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append(f"- **Total Hypotheses:** {summary['total_hypotheses']}")
    lines.append(f"- **Approved:** {summary['approved_hypotheses']}")
    lines.append(f"- **Rejected:** {summary['rejected_hypotheses']}")
    lines.append(f"- **Behavioral Clusters:** {summary['total_clusters']}")
    lines.append(f"- **Evidence Gaps:** {summary['evidence_gaps']}")
    lines.append(f"- **Disturbances:** {summary['evidence_disturbances']}")
    lines.append("")

    lines.append("## Entity Breakdown")
    for etype, count in summary['entity_breakdown'].items():
        lines.append(f"- **{etype.capitalize()}:** {count}")
    lines.append("")

    lines.append("## Approved Hypotheses")
    for h in report["hypotheses"]:
        if h.get("status") == "APPROVED":
            lines.append(f"### {h['title']}")
            lines.append(f"**Observation:** {h.get('observation', '')}")
            lines.append(f"**Interpretation:** {h.get('interpretation', '')}")
            lines.append(f"**Techniques:** {', '.join(h.get('technique_ids', []))}")
            lines.append(f"**Confidence:** {h.get('confidence_score', 0)}/100 ({h.get('confidence_tier', '')})")
            lines.append("")

    lines.append("## Behavioral Clusters")
    for c in report["clusters"][:20]:
        lines.append(f"- **{c['constructor_name']}** on {c['host']} (Score: {c['score']}, {c['strength']})")
        lines.append(f"  - {c['summary']}")
    lines.append("")

    lines.append("## Evidence Gaps")
    for g in report["evidence_gaps"]:
        lines.append(f"- **{g.get('question', '')}** — {g.get('what_would_resolve', '')}")
    lines.append("")

    return "\n".join(lines)


def _generate_html(report: dict[str, Any]) -> str:
    """Generate HTML report."""
    md = _generate_markdown(report)
    # Simple markdown-to-html conversion
    html_lines = ["<!DOCTYPE html>", "<html>", "<head>", "<title>Investigation Report</title>", 
                  "<style>body{font-family:sans-serif;max-width:900px;margin:2em auto;} h1{color:#333;} table{border-collapse:collapse;width:100%;} th,td{border:1px solid #ddd;padding:8px;text-align:left;} th{background:#f2f2f2;}</style>",
                  "</head>", "<body>"]

    for line in md.split("\n"):
        if line.startswith("# "):
            html_lines.append(f"<h1>{line[2:]}</h1>")
        elif line.startswith("## "):
            html_lines.append(f"<h2>{line[3:]}</h2>")
        elif line.startswith("### "):
            html_lines.append(f"<h3>{line[4:]}</h3>")
        elif line.startswith("**") and line.endswith("**"):
            html_lines.append(f"<p><strong>{line.strip('*')}</strong></p>")
        elif line.startswith("- "):
            html_lines.append(f"<li>{line[2:]}</li>")
        elif line.strip() == "":
            html_lines.append("<br/>")
        else:
            html_lines.append(f"<p>{line}</p>")

    html_lines.extend(["</body>", "</html>"])
    return "\n".join(html_lines)
