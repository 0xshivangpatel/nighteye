"""MCP Case Management Tools.

Tools for querying case status, hosts, and evidence gaps.
"""

from __future__ import annotations

import logging
from typing import Any

from nighteye.db import connect
from nighteye.mcp.tools._resolve import resolve_case_db, load_case_info

__all__ = [
    "get_case_status",
    "get_case_summary",
    "list_hosts",
    "get_evidence_gaps",
    "get_disturbances",
]

logger = logging.getLogger("nighteye.mcp.tools.case")

# ============================================================
# Case Query Tools
# ============================================================

def get_case_status(
    case_id: str | None = None,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Get current case status and progress.

    Returns:
        Case status with counts
    """
    case_id, db_path, err = resolve_case_db(case_id, db_path)
    if err:
        return {"success": False, "error": err}

    case_info = load_case_info(case_id, db_path)
    if not case_info:
        return {"success": False, "error": f"Case metadata not found for {case_id}"}

    try:
        with connect(db_path, read_only=True) as conn:
            hosts = conn.execute(
                "SELECT COUNT(DISTINCT primary_host) FROM clusters WHERE case_id = ?",
                (case_id,),
            ).fetchone()[0]

            clusters = conn.execute(
                "SELECT COUNT(*) FROM clusters WHERE case_id = ?", (case_id,)
            ).fetchone()[0]

            hypotheses = conn.execute(
                "SELECT COUNT(*) FROM hypotheses WHERE case_id = ?", (case_id,)
            ).fetchone()[0]

            approved = conn.execute(
                "SELECT COUNT(*) FROM hypotheses WHERE case_id = ? AND status = 'APPROVED'",
                (case_id,),
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
                "case": {
                    "id": case_info["case_id"],
                    "name": case_info["name"],
                    "examiner": case_info["examiner"],
                    "created_at": case_info["created_at"],
                    "status": case_info["status"],
                },
                "progress": {
                    "hosts": hosts,
                    "clusters": clusters,
                    "hypotheses": hypotheses,
                    "approved": approved,
                    "entities": entities,
                    "edges": edges,
                    "evidence_gaps": gaps,
                    "disturbances": disturbances,
                },
                "readiness": {
                    "can_report": approved >= 1,
                    "needs_more_evidence": gaps > 0 and approved < 3,
                    "anti_forensic_concern": disturbances > 0,
                },
            }
    except Exception as exc:
        logger.exception("Failed to get case status")
        return {"success": False, "error": f"Internal error: {exc}"}


def get_case_summary(
    case_id: str | None = None,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Get executive summary of case findings."""
    case_id, db_path, err = resolve_case_db(case_id, db_path)
    if err:
        return {"success": False, "error": err}

    try:
        with connect(db_path, read_only=True) as conn:
            clusters = conn.execute(
                """
                SELECT cluster_type, primary_host, score, summary
                FROM clusters WHERE case_id = ? AND score >= 40
                ORDER BY score DESC LIMIT 10
                """,
                (case_id,),
            ).fetchall()

            hypotheses = conn.execute(
                """
                SELECT title, interpretation, technique_ids, confidence_score
                FROM hypotheses WHERE case_id = ? AND status = 'APPROVED'
                ORDER BY confidence_score DESC
                """,
                (case_id,),
            ).fetchall()

            disturbances = conn.execute(
                """
                SELECT host, window_start, window_end, disturbance_type
                FROM evidence_disturbances WHERE case_id = ?
                ORDER BY window_start DESC
                """,
                (case_id,),
            ).fetchall()

            has_ransomware = any("Impact" in c["cluster_type"] for c in clusters)
            has_lateral = any("Lateral" in c["cluster_type"] for c in clusters)
            has_persistence = any("Persistence" in c["cluster_type"] for c in clusters)
            has_c2 = any("Beaconing" in c["cluster_type"] for c in clusters)

            assessment = "No significant threats detected"
            if has_ransomware:
                assessment = "RANSOMWARE/IMPACT activity detected — critical"
            elif has_lateral and has_c2:
                assessment = "Active APT-style intrusion with C2 and lateral movement"
            elif has_lateral:
                assessment = "Lateral movement detected — active intrusion"
            elif has_c2:
                assessment = "Command and control beaconing detected"
            elif has_persistence:
                assessment = "Persistence mechanisms detected — possible foothold"

            return {
                "success": True,
                "case_id": case_id,
                "assessment": assessment,
                "critical_findings": [
                    {
                        "type": "cluster",
                        "constructor": c["cluster_type"],
                        "host": c["primary_host"],
                        "score": c["score"],
                        "summary": c["summary"],
                    }
                    for c in clusters
                ],
                "approved_conclusions": [
                    {
                        "title": h["title"],
                        "interpretation": h["interpretation"],
                        "techniques": (h["technique_ids"] or "").split(",") if h["technique_ids"] else [],
                        "confidence": h["confidence_score"],
                    }
                    for h in hypotheses
                ],
                "anti_forensic_indicators": [
                    {
                        "host": d["host"],
                        "window": f"{d['window_start']} to {d['window_end']}",
                        "type": d["disturbance_type"],
                    }
                    for d in disturbances
                ],
            }
    except Exception as exc:
        logger.exception("Failed to get case summary")
        return {"success": False, "error": f"Internal error: {exc}"}


def list_hosts(
    case_id: str | None = None,
    db_path: str | None = None,
) -> dict[str, Any]:
    """List all hosts in a case with cluster counts."""
    case_id, db_path, err = resolve_case_db(case_id, db_path)
    if err:
        return {"success": False, "error": err}

    try:
        with connect(db_path, read_only=True) as conn:
            rows = conn.execute(
                """
                SELECT primary_host AS host,
                       COUNT(*) AS cluster_count,
                       MAX(time_end) AS last_activity,
                       SUM(CASE WHEN score >= 40 THEN 1 ELSE 0 END) AS high_score_clusters
                FROM clusters WHERE case_id = ?
                GROUP BY primary_host
                ORDER BY cluster_count DESC
                """,
                (case_id,),
            ).fetchall()

            hosts = [
                {
                    "name": row["host"],
                    "cluster_count": row["cluster_count"],
                    "high_score_clusters": row["high_score_clusters"],
                    "last_activity": row["last_activity"],
                }
                for row in rows
            ]

            return {
                "success": True,
                "total_hosts": len(hosts),
                "hosts": hosts,
            }
    except Exception as exc:
        logger.exception("Failed to list hosts")
        return {"success": False, "error": f"Internal error: {exc}"}


def get_evidence_gaps(
    case_id: str | None = None,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Get all evidence gaps for a case."""
    case_id, db_path, err = resolve_case_db(case_id, db_path)
    if err:
        return {"success": False, "error": err}

    try:
        with connect(db_path, read_only=True) as conn:
            rows = conn.execute(
                """
                SELECT gap_id, question, what_would_resolve, blocks_hypothesis,
                       registered_at, registered_by
                FROM evidence_gaps WHERE case_id = ?
                ORDER BY registered_at DESC
                """,
                (case_id,),
            ).fetchall()

            gaps = [
                {
                    "id": row["gap_id"],
                    "question": row["question"],
                    "what_would_resolve": row["what_would_resolve"],
                    "blocks_hypothesis": row["blocks_hypothesis"],
                    "registered_at": row["registered_at"],
                    "registered_by": row["registered_by"],
                }
                for row in rows
            ]

            return {
                "success": True,
                "total_gaps": len(gaps),
                "gaps": gaps,
            }
    except Exception as exc:
        logger.exception("Failed to get evidence gaps")
        return {"success": False, "error": f"Internal error: {exc}"}


def get_disturbances(
    case_id: str | None = None,
    host: str | None = None,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Get evidence disturbances (anti-forensic windows)."""
    case_id, db_path, err = resolve_case_db(case_id, db_path)
    if err:
        return {"success": False, "error": err}

    try:
        with connect(db_path, read_only=True) as conn:
            sql = """
                SELECT disturbance_id, host, window_start, window_end,
                       disturbance_type, detected_by, details, created_at
                FROM evidence_disturbances WHERE case_id = ?
            """
            params: list[Any] = [case_id]

            if host:
                sql += " AND host = ?"
                params.append(host)

            sql += " ORDER BY window_start DESC"

            rows = conn.execute(sql, params).fetchall()

            disturbances = [
                {
                    "id": row["disturbance_id"],
                    "host": row["host"],
                    "window_start": row["window_start"],
                    "window_end": row["window_end"],
                    "type": row["disturbance_type"],
                    "detected_by": row["detected_by"],
                    "details": row["details"],
                    "created_at": row["created_at"],
                }
                for row in rows
            ]

            return {
                "success": True,
                "total_disturbances": len(disturbances),
                "disturbances": disturbances,
            }
    except Exception as exc:
        logger.exception("Failed to get disturbances")
        return {"success": False, "error": f"Internal error: {exc}"}
