"""Post-cleanup hypothesis deduplication.

Rolls up auto-seeded DRAFT hypotheses that share the same (cluster_type,
host, trigger-set) into a single umbrella hypothesis whose evidence_refs
list every contributing cluster. Prevents the agent's queue from being
flooded with hundreds of structurally-identical hypotheses across
adjacent time windows.

Two hypotheses dedupe together if they:
  - are both DRAFT and have never been challenged
  - were auto-seeded (have suggested_by_cluster set)
  - belong to the same (cluster_type, primary_host)
  - have the SAME set of triggers (order-insensitive)

The earliest-staged hypothesis in each group survives. Its evidence_refs
gets extended to include every other cluster_id in the group, its
observation is rewritten to call out the N occurrences and the
overall time span, and the others are deleted.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from nighteye.db import connect

logger = logging.getLogger("nighteye.constructors.dedup")

__all__ = ["run_hypothesis_dedup"]


def run_hypothesis_dedup(db_path: str, case_id: str) -> dict[str, int]:
    """Roll up structurally-identical auto-seeded DRAFT hypotheses.

    Returns stats: groups_collapsed, hypotheses_removed, umbrellas_kept.
    """
    stats = {"groups_collapsed": 0, "hypotheses_removed": 0,
             "umbrellas_kept": 0}

    with connect(db_path) as conn:
        rows = conn.execute(
            """SELECT h.hypothesis_id, h.suggested_by_cluster,
                      h.staged_at, h.title, h.observation,
                      h.evidence_refs, h.audit_ids,
                      c.cluster_type, c.primary_host,
                      c.triggers_fired, c.time_start, c.time_end, c.score
               FROM hypotheses h
               JOIN clusters c ON c.cluster_id = h.suggested_by_cluster
               WHERE h.case_id = ?
                 AND h.status = 'DRAFT'
                 AND h.challenged_at IS NULL
                 AND h.suggested_by_cluster IS NOT NULL
               ORDER BY h.staged_at ASC""",
            (case_id,),
        ).fetchall()

        # Group by (cluster_type, primary_host, sorted-triggers tuple)
        groups: dict[tuple, list[dict]] = {}
        for r in rows:
            d = dict(r)
            try:
                trigs = sorted(json.loads(d.get("triggers_fired") or "[]"))
            except Exception:
                trigs = []
            key = (d.get("cluster_type") or "",
                   d.get("primary_host") or "",
                   tuple(trigs))
            groups.setdefault(key, []).append(d)

        for (ctype, host, trigs), members in groups.items():
            if len(members) < 2:
                continue
            # Earliest staged survives; we extend its evidence_refs.
            primary = members[0]
            losers = members[1:]
            stats["groups_collapsed"] += 1
            stats["hypotheses_removed"] += len(losers)
            stats["umbrellas_kept"] += 1

            # Merge evidence_refs lists. Each ref carries a cluster_id;
            # we accumulate them and also bundle in a tally so the agent
            # knows how many windows backed this finding.
            existing_refs = _load_json(primary.get("evidence_refs"))
            extra_refs = []
            time_starts: list[str] = []
            time_ends: list[str] = []
            scores: list[int] = []
            cluster_ids = [primary["suggested_by_cluster"]]
            if primary.get("time_start"):
                time_starts.append(primary["time_start"])
            if primary.get("time_end"):
                time_ends.append(primary["time_end"])
            if primary.get("score") is not None:
                scores.append(int(primary["score"]))
            for m in losers:
                cid = m["suggested_by_cluster"]
                cluster_ids.append(cid)
                extra_refs.append({
                    "audit_id": f"rollup-{cid[:16]}",
                    "cluster_id": cid,
                    "description": "additional cluster matching the same "
                                   "(host, type, triggers) signature",
                })
                if m.get("time_start"):
                    time_starts.append(m["time_start"])
                if m.get("time_end"):
                    time_ends.append(m["time_end"])
                if m.get("score") is not None:
                    scores.append(int(m["score"]))

            # Update primary hypothesis: extended refs, summary,
            # and a rollup note in the observation.
            new_refs = (existing_refs or []) + extra_refs
            span_start = min(time_starts) if time_starts else ""
            span_end = max(time_ends) if time_ends else ""
            mean_score = sum(scores) // len(scores) if scores else 0
            new_obs = (
                f"Rollup of {len(members)} clusters with identical "
                f"(host={host}, type={ctype}, triggers={list(trigs)}) "
                f"signature spanning {span_start or '?'} → {span_end or '?'} "
                f"(mean cluster score {mean_score}). "
                f"Investigate as a single behavioural pattern rather than "
                f"per-window. Individual cluster IDs available via "
                f"evidence_refs."
            )

            conn.execute(
                "UPDATE hypotheses SET observation = ?, "
                "evidence_refs = ?, modified_at = staged_at "
                "WHERE hypothesis_id = ?",
                (new_obs, json.dumps(new_refs), primary["hypothesis_id"]),
            )

            # Delete losers
            placeholders = ",".join("?" * len(losers))
            conn.execute(
                f"DELETE FROM hypotheses WHERE hypothesis_id IN ({placeholders})",
                tuple(m["hypothesis_id"] for m in losers),
            )

            logger.info(
                "Rolled up %d → 1 on %s [%s] {%s}",
                len(members), host, ctype, ",".join(list(trigs)[:3]),
            )

        conn.commit()

    return stats


def _load_json(s: Any) -> list:
    if not s:
        return []
    if isinstance(s, list):
        return s
    try:
        v = json.loads(s)
        return v if isinstance(v, list) else []
    except (json.JSONDecodeError, TypeError):
        return []
