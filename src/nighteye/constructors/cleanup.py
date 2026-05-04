"""Post-clustering cleanup: deduplication, hypothesis seeding, journal checkpoint.

After behavioral clustering produces thousands of low-confidence clusters
for common Windows events (service installs, scheduled tasks), this module:

1. Collapses identical low-confidence clusters into per-host aggregate summaries
2. Keeps individual clusters for actionable findings (MODERATE+, high-value triggers)
3. Generates draft hypothesis stubs for MODERATE/STRONG clusters
4. Seeds the journal so the MCP investigation loop has a starting point

References:
    - docs/ARCHITECTURE.md § 8 (Post-Clustering)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from nighteye.db import connect, execute_with_retry
from nighteye.constructors.scoring import ClusterTier

__all__ = ["run_cluster_cleanup"]

logger = logging.getLogger("nighteye.constructors.cleanup")

# Triggers that fire on benign Windows activity — these get collapsed
_NOISE_TRIGGERS: frozenset[str] = frozenset({
    "new_service_remote",
    "service_install",
    "service_remote_install",
    "scheduled_task_remote",
    "scheduled_task_creation",
    # Expand as needed
})

# Triggers that should ALWAYS be kept as individual clusters
# regardless of tier — these indicate real attacker activity
_KEEP_TRIGGERS: frozenset[str] = frozenset({
    "lsass_access_or_dump",
    "process_masquerading",
    "psexec_usage",
    "amsi_bypass",
    "etw_tamper",
    "edr_disable",
    "process_injection",
    "uac_bypass",
    "pass_the_hash_ticket",
    "shadow_copy_deletion",
    "ransomware_extension_pattern",
    "cloud_upload_tool",
})


def run_cluster_cleanup(db_path: str, case_id: str, examiner: str = "nighteye") -> dict[str, int]:
    """Run post-clustering cleanup.

    Returns stats dict with counts of actions taken.
    """
    stats = {
        "clusters_collapsed": 0,
        "clusters_kept": 0,
        "aggregates_created": 0,
        "hypotheses_seeded": 0,
    }

    conn = connect(db_path)
    try:
        # ----------------------------------------------------------------
        # Phase 1: Identify noise clusters to collapse
        # ----------------------------------------------------------------
        noise_ids: list[str] = []
        keep_rows: list[dict[str, Any]] = []

        cursor = conn.execute(
            """
            SELECT cluster_id, cluster_type, strength, score, primary_host,
                   triggers_fired, supporting_signals, time_start, time_end,
                   member_canonical_ids, mitre_tactic, technique_ids, summary
            FROM clusters
            WHERE case_id = ?
            """,
            (case_id,),
        )

        for row in cursor:
            triggers = json.loads(row["triggers_fired"] or "[]")
            score = row["score"] or 0
            strength = row["strength"] or "WEAK"

            # Keep all MODERATE+ and STRONG clusters
            if strength not in ("WEAK", "NOISE"):
                keep_rows.append(dict(row))
                continue

            # Keep clusters with high-value triggers regardless of score
            if any(t in _KEEP_TRIGGERS for t in triggers):
                keep_rows.append(dict(row))
                continue

            # Check if ALL triggers in this cluster are noise triggers
            if triggers and all(t in _NOISE_TRIGGERS for t in triggers):
                noise_ids.append(row["cluster_id"])
            else:
                keep_rows.append(dict(row))

        logger.info(
            "Cleanup: %d noise clusters to collapse, %d to keep",
            len(noise_ids),
            len(keep_rows),
        )

        # ----------------------------------------------------------------
        # Phase 2: Collapse noise clusters into per-host aggregates
        # ----------------------------------------------------------------
        # Group noise clusters by (host, constructor_type)
        aggregates: dict[tuple[str, str], dict[str, Any]] = {}

        if noise_ids:
            # Fetch full details for noise clusters to build aggregates
            placeholders = ",".join("?" for _ in noise_ids)
            cursor = conn.execute(
                f"""
                SELECT cluster_type, primary_host, time_start, time_end, score
                FROM clusters
                WHERE cluster_id IN ({placeholders})
                """,
                noise_ids,
            )

            for row in cursor:
                key = (row["primary_host"] or "unknown", row["cluster_type"])
                if key not in aggregates:
                    aggregates[key] = {
                        "host": row["primary_host"],
                        "type": row["cluster_type"],
                        "count": 0,
                        "time_start": row["time_start"],
                        "time_end": row["time_end"],
                        "min_score": 100,
                        "max_score": 0,
                    }
                agg = aggregates[key]
                agg["count"] += 1
                ts = row["time_start"] or ""
                if ts and ts < (agg["time_start"] or "z"):
                    agg["time_start"] = ts
                te = row["time_end"] or ""
                if te and te > (agg["time_end"] or ""):
                    agg["time_end"] = te
                if row["score"]:
                    agg["min_score"] = min(agg["min_score"], row["score"])
                    agg["max_score"] = max(agg["max_score"], row["score"])

            # Delete the noise clusters
            for noise_id in noise_ids:
                conn.execute(
                    "DELETE FROM clusters WHERE cluster_id = ?", (noise_id,)
                )
            stats["clusters_collapsed"] = len(noise_ids)

            # Insert aggregate entries
            now = datetime.now(timezone.utc).isoformat()
            for (host, ctype), agg in aggregates.items():
                agg_id = f"aggregate-{case_id}-{host}-{ctype}"
                execute_with_retry(
                    conn,
                    """
                    INSERT OR REPLACE INTO clusters (
                        cluster_id, case_id, cluster_type, strength, score,
                        triggers_fired, supporting_signals, counter_signals,
                        counter_evidence_details, contradicting_clusters,
                        member_canonical_ids, primary_host, primary_user,
                        secondary_hosts, time_start, time_end,
                        technique_ids, mitre_tactic, summary, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        agg_id,
                        case_id,
                        ctype,
                        "WEAK",
                        agg["min_score"],
                        json.dumps([f"aggregated-{agg['count']}-events"]),
                        json.dumps([]),
                        json.dumps([]),
                        json.dumps([]),
                        json.dumps([]),
                        json.dumps([]),
                        host,
                        "multiple",
                        json.dumps([]),
                        agg["time_start"],
                        agg["time_end"],
                        json.dumps([]),
                        "",
                        f"Aggregated {agg['count']} low-confidence {ctype} events "
                        f"(score range {agg['min_score']}-{agg['max_score']}). "
                        f"These are common Windows administrative activities "
                        f"and are unlikely to be attacker-controlled.",
                        now,
                    ),
                )
                stats["aggregates_created"] += 1

        stats["clusters_kept"] = len(keep_rows)
        conn.commit()

        # ----------------------------------------------------------------
        # Phase 3: Seed hypotheses for ACTIONABLE clusters
        # ----------------------------------------------------------------
        now = datetime.now(timezone.utc).isoformat()
        # Select ALL clusters — filter in Python because sqlite
        # json_each IN(?) with multiple values is tricky.
        cursor = conn.execute(
            """
            SELECT cluster_id, cluster_type, strength, score, primary_host,
                   triggers_fired, supporting_signals, time_start, mitre_tactic,
                   technique_ids, summary
            FROM clusters
            WHERE case_id = ?
            """,
            (case_id,),
        )

        for row in cursor:
            cluster_id = row["cluster_id"]
            strength = row["strength"] or ""
            cluster_id_str = cluster_id or ""

            # Determine if this cluster is "actionable" (deserves a hypothesis)
            is_moderate_plus = strength in ("MODERATE", "STRONG")
            is_aggregate = "aggregate-" in cluster_id_str
            triggers = json.loads(row["triggers_fired"] or "[]")
            has_keep_trigger = any(t in _KEEP_TRIGGERS for t in triggers)

            # Skip aggregate entries — they represent collapsed noise,
            # not actionable findings.
            if is_aggregate:
                continue

            # Only seed hypotheses for MODERATE+ clusters or clusters
            # with high-value keep triggers
            if not (is_moderate_plus or has_keep_trigger):
                continue

            # Skip if hypothesis already exists for this cluster
            existing = conn.execute(
                "SELECT 1 FROM hypotheses WHERE suggested_by_cluster = ?",
                (cluster_id,),
            ).fetchone()
            if existing:
                continue

            trigger_str = ", ".join(triggers[:3])

            # Auto-generate a draft hypothesis
            hypothesis_id = f"hyp-{case_id}-{cluster_id}"
            title = f"{row['cluster_type']}: {trigger_str} on {row['primary_host']}"
            observation = (
                f"Cluster {cluster_id} contains {trigger_str} activity "
                f"on host {row['primary_host']} at {row['time_start']}. "
                f"Score: {row['score']}/{row['strength']}."
            )
            interpretation = (
                f"Auto-generated draft from clustering result. "
                f"The {row['cluster_type']} trigger {trigger_str} suggests "
                f"potential adversary activity. Further investigation required."
            )

            # Map cluster strength to hypothesis confidence tier
            tier_map = {"STRONG": "HIGH", "MODERATE": "MEDIUM", "WEAK": "LOW"}
            conf_tier = tier_map.get(row["strength"] or "WEAK", "LOW")

            execute_with_retry(
                conn,
                """
                INSERT OR IGNORE INTO hypotheses (
                    hypothesis_id, case_id, examiner, title, observation, interpretation,
                    technique_ids, status, staged_at, modified_at, suggested_by_cluster,
                    confidence_score, confidence_tier,
                    evidence_refs, audit_ids, confidence_breakdown,
                    provenance_tier, content_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    hypothesis_id,
                    case_id,
                    examiner,
                    title,
                    observation,
                    interpretation,
                    row["technique_ids"] or "[]",
                    "DRAFT",
                    now,
                    now,
                    cluster_id,
                    row["score"] or 0,
                    conf_tier,
                    "[]",        # evidence_refs
                    "[]",        # audit_ids
                    "{}",        # confidence_breakdown
                    "NONE",      # provenance_tier (stub — no audit trail yet)
                    f"auto-{hypothesis_id}",  # content_hash
                ),
            )
            stats["hypotheses_seeded"] += 1

        conn.commit()

        # ----------------------------------------------------------------
        # Phase 4: Seed journal with a checkpoint
        # ----------------------------------------------------------------
        existing_journal = conn.execute(
            "SELECT 1 FROM journal WHERE case_id = ?", (case_id,)
        ).fetchone()

        if not existing_journal:
            execute_with_retry(
                conn,
                """
                INSERT INTO journal (
                    entry_id, case_id, timestamp, entry_type, summary, details
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    f"ckpt-{case_id}-post-cluster",
                    case_id,
                    now,
                    "CHECKPOINT_SUMMARY",
                    f"Post-clustering cleanup: {stats['clusters_kept']} clusters retained, "
                    f"{stats['hypotheses_seeded']} hypotheses seeded",
                    json.dumps({
                        "phase": "post-clustering",
                        "clusters_total": stats["clusters_collapsed"] + stats["clusters_kept"],
                        "clusters_collapsed": stats["clusters_collapsed"],
                        "aggregates_created": stats["aggregates_created"],
                        "hypotheses_seeded": stats["hypotheses_seeded"],
                    }),
                ),
            )

        conn.commit()
    finally:
        conn.close()

    return stats
