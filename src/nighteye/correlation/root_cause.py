"""Root-cause correlation.

Walks approved hypotheses backward through causal_links to identify the
earliest causally-supported event in the investigation. Produces a
MITRE-aligned kill chain when possible.

Algorithm:
  1. Load all APPROVED hypotheses for the case ordered by staged_at ASC.
  2. The earliest is the initial candidate root.
  3. For each candidate, follow `causal_links` from other hypotheses
     pointing TO this one (i.e., evidence of a precursor). The strongest
     link (CHAIN > WRITE > NET > TIGHT_TIME > CO_OCCUR > TEMPORAL_ONLY)
     wins.
  4. Recurse until no further precursor is found.
  5. Build the chain in chronological order. Tag each step with its
     MITRE technique IDs for kill-chain rendering.

If no APPROVED hypotheses exist yet the response notes that explicitly
rather than inventing a result.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from nighteye.case import get_active_case, get_case_dir
from nighteye.db import connect

__all__ = ["find_root_cause"]

logger = logging.getLogger("nighteye.correlation.root_cause")

# Strength order for causal levels. Higher index = stronger.
_LEVEL_ORDER = [
    "UNSUPPORTED",
    "TEMPORAL_ONLY",
    "CO_OCCUR",
    "TIGHT_TIME",
    "NET",
    "WRITE",
    "CHAIN",
]
_LEVEL_RANK = {lvl: i for i, lvl in enumerate(_LEVEL_ORDER)}


def _resolve_case(case_id: str | None) -> tuple[str, str] | None:
    """Resolve case_id and DB path. Returns None if no case is available."""
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


def _load_approved(conn: Any, case_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT hypothesis_id, title, observation, interpretation,
               technique_ids, staged_at, approved_at, suggested_by_cluster,
               causal_links, confidence_score, confidence_tier
        FROM hypotheses
        WHERE case_id = ? AND status = 'APPROVED'
        ORDER BY staged_at ASC
        """,
        (case_id,),
    ).fetchall()

    out: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        try:
            d["technique_ids"] = json.loads(r["technique_ids"]) if r["technique_ids"] else []
        except (TypeError, ValueError):
            d["technique_ids"] = []
        try:
            d["causal_links"] = json.loads(r["causal_links"]) if r["causal_links"] else []
        except (TypeError, ValueError):
            d["causal_links"] = []
        out.append(d)
    return out


def _build_incoming_index(
    hypotheses: list[dict[str, Any]],
) -> dict[str, list[tuple[str, str]]]:
    """For each hypothesis_id, return (source_hyp_id, level) of incoming links.

    A causal link on hypothesis A targeting B means "A → B" (A causes B).
    The incoming index maps B → list of (A, level).
    """
    incoming: dict[str, list[tuple[str, str]]] = {h["hypothesis_id"]: [] for h in hypotheses}
    for h in hypotheses:
        src = h["hypothesis_id"]
        for link in h.get("causal_links") or []:
            target = link.get("target_hypothesis")
            level = link.get("level", "UNSUPPORTED")
            if target and target in incoming:
                incoming[target].append((src, level))
    return incoming


def _walk_back(
    start_id: str,
    by_id: dict[str, dict[str, Any]],
    incoming: dict[str, list[tuple[str, str]]],
) -> list[dict[str, Any]]:
    """Walk back via strongest incoming causal link until exhausted."""
    chain: list[dict[str, Any]] = [by_id[start_id]]
    visited: set[str] = {start_id}
    current = start_id
    while True:
        candidates = [
            (src, level)
            for src, level in incoming.get(current, [])
            if src not in visited
            and _LEVEL_RANK.get(level, 0) > _LEVEL_RANK["UNSUPPORTED"]
        ]
        if not candidates:
            break
        candidates.sort(
            key=lambda c: (
                -_LEVEL_RANK.get(c[1], 0),
                by_id[c[0]].get("staged_at", ""),
            )
        )
        best_src, best_level = candidates[0]
        chain.insert(0, {**by_id[best_src], "_link_level_to_next": best_level})
        visited.add(best_src)
        current = best_src
    return chain


def find_root_cause(case_id: str | None = None) -> dict[str, Any]:
    """Identify the root cause and emit a MITRE-aligned kill chain."""
    resolved = _resolve_case(case_id)
    if not resolved:
        return {
            "success": False,
            "error": "No active case. Initialize one or pass case_id.",
        }
    cid, db_path = resolved

    with connect(db_path, read_only=True) as conn:
        hypotheses = _load_approved(conn, cid)

    if not hypotheses:
        return {
            "success": True,
            "found": False,
            "case_id": cid,
            "reason": "No APPROVED hypotheses yet — root cause cannot be derived.",
            "kill_chain": [],
            "gaps": [
                "Approve at least one hypothesis before requesting root cause."
            ],
        }

    by_id = {h["hypothesis_id"]: h for h in hypotheses}
    incoming = _build_incoming_index(hypotheses)

    earliest = hypotheses[0]
    chain = _walk_back(earliest["hypothesis_id"], by_id, incoming)

    technique_chain: list[str] = []
    for h in chain:
        technique_chain.extend(h.get("technique_ids") or [])

    found_precursor = chain[0]["hypothesis_id"] != earliest["hypothesis_id"]

    return {
        "success": True,
        "found": True,
        "case_id": cid,
        "root": {
            "hypothesis_id": chain[0]["hypothesis_id"],
            "title": chain[0]["title"],
            "staged_at": chain[0]["staged_at"],
            "technique_ids": chain[0].get("technique_ids", []),
            "confidence_tier": chain[0].get("confidence_tier"),
        },
        "kill_chain": [
            {
                "hypothesis_id": h["hypothesis_id"],
                "title": h["title"],
                "staged_at": h.get("staged_at"),
                "technique_ids": h.get("technique_ids", []),
                "confidence_tier": h.get("confidence_tier"),
                "link_level_to_next": h.get("_link_level_to_next"),
            }
            for h in chain
        ],
        "technique_chain": technique_chain,
        "precursor_found_via_causal_links": found_precursor,
        "approved_count": len(hypotheses),
        "gaps": (
            []
            if found_precursor
            else [
                "Earliest approved hypothesis has no causal link from a "
                "precursor. Consider establish_causation() to link prior "
                "evidence (e.g. initial access)."
            ]
        ),
    }
