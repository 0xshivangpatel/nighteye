"""End-of-case reconciliation.

Real validation pass over the SQLite Evidence Graph. Reports:
  - Hypotheses still in DRAFT (block report)
  - Hypotheses with invalid/missing MITRE mappings
  - Hypotheses with contradicting causal links (A→B and B→A)
  - Open evidence gaps marked blocks_report
  - APPROVED hypotheses missing from the HMAC ledger (if available)
  - Approved + contradicted pairs that weren't reconciled

Returns a structured dict the agent and portal both consume.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from nighteye.case import get_active_case, get_case_dir
from nighteye.db import connect

__all__ = ["validate_case_readiness"]

logger = logging.getLogger("nighteye.validation.end_of_case")

# Minimal MITRE technique ID pattern: T#### or T####.### (sub-technique)
_MITRE_RE_PARTS = ("T", )


def _resolve_case(case_id: str | None) -> tuple[str, str] | None:
    if case_id:
        try:
            case_dir = get_case_dir(case_id)
        except Exception:
            return None
        return case_id, str(case_dir / "graph.db")
    info = get_active_case()
    if not info:
        return None
    return info.case_id, info.graph_db


def _is_valid_technique_id(tid: str) -> bool:
    if not isinstance(tid, str) or not tid.startswith("T"):
        return False
    rest = tid[1:]
    if not rest:
        return False
    # T<digits> or T<digits>.<digits>
    parts = rest.split(".")
    return all(p.isdigit() for p in parts) and 1 <= len(parts) <= 2


def validate_case_readiness(case_id: str | None = None) -> dict[str, Any]:
    """Real end-of-case validation. Returns structured findings."""
    resolved = _resolve_case(case_id)
    if not resolved:
        return {
            "success": False,
            "error": "No active case. Initialize one or pass case_id.",
        }
    cid, db_path = resolved

    warnings: list[str] = []
    blockers: list[str] = []

    with connect(db_path, read_only=True) as conn:
        hypotheses = conn.execute(
            """
            SELECT hypothesis_id, status, technique_ids, causal_links,
                   suggested_by_cluster, contradicted_by, hmac_signature
            FROM hypotheses WHERE case_id = ?
            """,
            (cid,),
        ).fetchall()

        gaps = conn.execute(
            """
            SELECT gap_id, question, blocks_report
            FROM evidence_gaps
            WHERE case_id = ? AND resolved_at IS NULL
            """,
            (cid,),
        ).fetchall()

        clusters_strong = conn.execute(
            "SELECT COUNT(*) FROM clusters WHERE case_id = ? AND strength = 'STRONG'",
            (cid,),
        ).fetchone()[0]
        clusters_total = conn.execute(
            "SELECT COUNT(*) FROM clusters WHERE case_id = ?", (cid,)
        ).fetchone()[0]

    # Status counts
    status_counts: dict[str, int] = {}
    for r in hypotheses:
        status_counts[r["status"]] = status_counts.get(r["status"], 0) + 1

    draft_count = status_counts.get("DRAFT", 0)
    if draft_count > 0:
        blockers.append(
            f"{draft_count} hypothesis/hypotheses still in DRAFT — review or "
            "explicitly approve/reject before report."
        )

    # MITRE mapping check (only for APPROVED ones — DRAFT is permitted to be partial)
    missing_mitre: list[str] = []
    invalid_mitre: list[tuple[str, str]] = []
    for r in hypotheses:
        if r["status"] != "APPROVED":
            continue
        try:
            tids = json.loads(r["technique_ids"]) if r["technique_ids"] else []
        except (TypeError, ValueError):
            tids = []
        if not tids:
            missing_mitre.append(r["hypothesis_id"])
            continue
        for tid in tids:
            if not _is_valid_technique_id(tid):
                invalid_mitre.append((r["hypothesis_id"], tid))
    if missing_mitre:
        warnings.append(
            f"{len(missing_mitre)} APPROVED hypotheses without MITRE technique IDs: "
            + ", ".join(missing_mitre[:5])
            + (" …" if len(missing_mitre) > 5 else "")
        )
    if invalid_mitre:
        warnings.append(
            f"{len(invalid_mitre)} invalid MITRE technique ID(s): "
            + ", ".join(f"{h}={t}" for h, t in invalid_mitre[:5])
        )

    # Detect contradicting causal links: A→B and B→A both present.
    edges: dict[tuple[str, str], str] = {}
    for r in hypotheses:
        try:
            links = json.loads(r["causal_links"]) if r["causal_links"] else []
        except (TypeError, ValueError):
            links = []
        for link in links:
            target = link.get("target_hypothesis")
            level = link.get("level", "UNSUPPORTED")
            if not target:
                continue
            edges[(r["hypothesis_id"], target)] = level

    contradictions: list[tuple[str, str]] = []
    for (src, dst), _level in list(edges.items()):
        if (dst, src) in edges:
            pair = tuple(sorted([src, dst]))
            if pair not in [tuple(sorted([a, b])) for a, b in contradictions]:
                contradictions.append((src, dst))
    if contradictions:
        blockers.append(
            f"{len(contradictions)} contradicting causal link pair(s): "
            + ", ".join(f"{a}↔{b}" for a, b in contradictions[:5])
        )

    # Approved-but-contradicted: any APPROVED hypothesis whose
    # contradicted_by points to another APPROVED hypothesis.
    by_id = {r["hypothesis_id"]: r for r in hypotheses}
    contradicted_pairs: list[tuple[str, str]] = []
    for r in hypotheses:
        if r["status"] != "APPROVED":
            continue
        cb = r["contradicted_by"]
        if cb and cb in by_id and by_id[cb]["status"] == "APPROVED":
            contradicted_pairs.append((r["hypothesis_id"], cb))
    if contradicted_pairs:
        blockers.append(
            f"{len(contradicted_pairs)} APPROVED hypothesis/hypotheses contradict "
            f"another APPROVED hypothesis: "
            + ", ".join(f"{a}↔{b}" for a, b in contradicted_pairs[:5])
        )

    # HMAC ledger coverage: every APPROVED hypothesis should have a signature.
    missing_hmac = [
        r["hypothesis_id"]
        for r in hypotheses
        if r["status"] == "APPROVED" and not r["hmac_signature"]
    ]
    if missing_hmac:
        warnings.append(
            f"{len(missing_hmac)} APPROVED hypotheses without HMAC signatures: "
            + ", ".join(missing_hmac[:5])
        )

    # Evidence gaps marked blocks_report
    blocking_gaps = [g for g in gaps if g["blocks_report"]]
    if blocking_gaps:
        blockers.append(
            f"{len(blocking_gaps)} unresolved evidence gap(s) marked as blocking: "
            + ", ".join(g["gap_id"] for g in blocking_gaps[:5])
        )
    elif gaps:
        warnings.append(
            f"{len(gaps)} unresolved evidence gap(s) (non-blocking)."
        )

    # Coverage hint: have we even surfaced anything?
    if status_counts.get("APPROVED", 0) == 0:
        if clusters_strong > 0 or clusters_total > 0:
            warnings.append(
                f"No APPROVED hypotheses yet despite {clusters_strong} STRONG and "
                f"{clusters_total} total clusters."
            )
        else:
            warnings.append(
                "No clusters and no approved hypotheses — has ingest + clustering run?"
            )

    ready = not blockers
    return {
        "success": True,
        "case_id": cid,
        "ready_for_report": ready,
        "status": "PASS" if ready else "FAIL",
        "blockers": blockers,
        "warnings": warnings,
        "counts": {
            "hypotheses_total": sum(status_counts.values()),
            "by_status": status_counts,
            "evidence_gaps_open": len(gaps),
            "evidence_gaps_blocking": len(blocking_gaps),
            "clusters_total": clusters_total,
            "clusters_strong": clusters_strong,
            "missing_mitre": len(missing_mitre),
            "invalid_mitre": len(invalid_mitre),
            "missing_hmac_signatures": len(missing_hmac),
            "contradiction_pairs": len(contradictions),
            "approved_contradicted": len(contradicted_pairs),
        },
    }
