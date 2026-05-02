"""JSON Report Exporter.

Exports the finalized report and case metadata as a structured JSON
document for ingestion into external systems (e.g. SIEMs, ticketing systems).
"""

from __future__ import annotations

import json

from nighteye.case import get_active_case, get_case_dir
from nighteye.correlation.root_cause import find_root_cause
from nighteye.db import connect

__all__ = ["export_json_report"]


def export_json_report() -> str:
    """Export the case report as JSON, querying real approved hypotheses."""
    case = get_active_case()
    root_cause = find_root_cause()

    payload: dict = {
        "report_type": "NightEye_Final",
        "case_id": case.id if case else None,
        "root_cause": root_cause,
        "hypotheses_approved": [],
        "hypotheses_total": 0,
        "clusters_total": 0,
    }

    if case:
        with connect(case.graph_db, read_only=True) as conn:
            approved = conn.execute(
                """
                SELECT hypothesis_id, title, observation, interpretation,
                       technique_ids, confidence_score, confidence_tier,
                       approved_at, staged_at
                FROM hypotheses
                WHERE case_id = ? AND status = 'APPROVED'
                ORDER BY staged_at ASC
                """,
                (case.id,),
            ).fetchall()

            for row in approved:
                tids = []
                try:
                    tids = json.loads(row["technique_ids"]) if row["technique_ids"] else []
                except (TypeError, ValueError):
                    pass

                payload["hypotheses_approved"].append({
                    "id": row["hypothesis_id"],
                    "title": row["title"],
                    "observation": row["observation"],
                    "interpretation": row["interpretation"],
                    "technique_ids": tids,
                    "confidence_score": row["confidence_score"],
                    "confidence_tier": row["confidence_tier"],
                    "approved_at": row["approved_at"],
                })

            total = conn.execute(
                "SELECT COUNT(*) FROM hypotheses WHERE case_id = ?",
                (case.id,),
            ).fetchone()
            payload["hypotheses_total"] = total[0] if total else 0

            clusters = conn.execute(
                "SELECT COUNT(*) FROM clusters WHERE case_id = ?",
                (case.id,),
            ).fetchone()
            payload["clusters_total"] = clusters[0] if clusters else 0

    return json.dumps(payload, indent=2, default=str)
