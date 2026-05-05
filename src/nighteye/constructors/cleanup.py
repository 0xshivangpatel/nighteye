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
from nighteye.models import EvidenceRef

# Trigger → MITRE technique mapping (per-trigger, not per-constructor)
_TRIGGER_TECHNIQUES: dict[str, list[str]] = {
    "sam_hive_copy": ["T1003.002"],
    "lsass_access_or_dump": ["T1003.001"],
    "ntds_dump": ["T1003.003"],
    "process_masquerading": ["T1036"],
    "amsi_bypass": ["T1562.001"],
    "etw_tamper": ["T1562.006"],
    "edr_disable": ["T1562.001"],
    "process_injection": ["T1055"],
    "uac_bypass": ["T1548.002"],
    "service_install": ["T1543.003"],
    "scheduled_task_creation": ["T1053.005"],
    "registry_run_key": ["T1547.001"],
    "startup_folder": ["T1547.001"],
    "dll_search_order_hijacking": ["T1574.001"],
    "cloud_upload_tool": ["T1567.002"],
    "ransom_note_pattern": ["T1486"],
    "archive_creation_unusual_path": ["T1560"],
    "shadow_copy_deletion": ["T1490"],
    "psexec_usage": ["T1569.002"],
    "pass_the_hash_ticket": ["T1550.002"],
    "new_service_remote": ["T1543.003"],
    "service_remote_install": ["T1543.003"],
    "scheduled_task_remote": ["T1053.005"],
}

__all__ = ["run_cluster_cleanup"]

logger = logging.getLogger("nighteye.constructors.cleanup")

# Triggers that fire on benign Windows activity — these get collapsed
def _get_trigger_techniques(trigger_name: str) -> list[str]:
    """Map a single trigger name to its specific MITRE technique IDs."""
    # Exact match
    if trigger_name in _TRIGGER_TECHNIQUES:
        return _TRIGGER_TECHNIQUES[trigger_name]
    # Substring match for compound triggers
    for key, techs in _TRIGGER_TECHNIQUES.items():
        if key in trigger_name or trigger_name in key:
            return techs
    return []


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
# regardless of tier — these indicate real attacker activity.
# Use substring matching: a trigger matches if ANY keep pattern
# appears as a substring of the trigger name.
_KEEP_TRIGGER_PATTERNS: list[str] = [
    "lsass_access", "sam_hive", "psexec", "amsi_bypass",
    "etw_tamper", "edr_disable", "process_injection",
    "process_masquerad", "uac_bypass", "pass_the_hash",
    "shadow_copy", "ransom",  # catches ransom_note_pattern and ransomware_extension_pattern
    "cloud_upload", "archive_creation",  # catches archive_creation_unusual_path
    "ntds_dump", "kerberoast",
]


def _is_keep_trigger(trigger_name: str) -> bool:
    """Check if a trigger name matches any keep pattern via substring match."""
    return any(pattern in trigger_name for pattern in _KEEP_TRIGGER_PATTERNS)


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
            if any(_is_keep_trigger(t) for t in triggers):
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
                   technique_ids, summary, member_canonical_ids
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
            has_keep_trigger = any(_is_keep_trigger(t) for t in triggers)

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
            conf_score = row["score"] or 0

            # Proper confidence breakdown so Hypothesis model preserves tier
            conf_breakdown = json.dumps({
                "score": conf_score,
                "tier": conf_tier,
                "rationale": f"Auto-seeded from cluster {cluster_id} "
                             f"({row['cluster_type']}, {row['strength']})",
                "factor_contributions": {},
            })

            # Create audit entry so provenance gate passes
            audit_id = f"auto-seed-{cluster_id[:16]}"
            execute_with_retry(
                conn,
                """
                INSERT OR IGNORE INTO audit (audit_id, case_id, tool_group, tool_name, parameters, result_summary, duration_ms, examiner, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_id,
                    case_id,
                    "hypothesis",
                    "auto-seed",
                    json.dumps({"cluster_id": cluster_id, "trigger": trigger_str}),
                    f"Seeded from cluster {cluster_id} (score {conf_score}, tier {conf_tier})",
                    0,
                    examiner,
                    now,
                ),
            )

            # Build evidence refs with real audit ID and cluster ID
            member_ids = json.loads(row["member_canonical_ids"] or "[]") if "member_canonical_ids" in dict(row) else []
            evidence_refs = [
                EvidenceRef(audit_id=audit_id, cluster_id=cluster_id,
                           description=f"Cluster {cluster_id}: {trigger_str}",
                           canonical_event_ids=member_ids)
            ]

            # Map MITRE techniques per-trigger by matching trigger name to technique
            trigger_techniques = _get_trigger_techniques(triggers[0] if triggers else "")
            technique_ids = trigger_techniques or (json.loads(row["technique_ids"] or "[]")[:2])

            # Call record_hypothesis (exercises all 4 gates: provenance, confidence, causation, anti-forensic)
            try:
                from nighteye.hypothesis_lifecycle import record_hypothesis as _record
                hypothesis = _record(
                    db_conn=conn,
                    case_id=case_id,
                    examiner=examiner,
                    title=title,
                    observation=observation,
                    interpretation=interpretation,
                    technique_ids=technique_ids,
                    evidence_refs=evidence_refs,
                    suggested_by_cluster=cluster_id,
                )
                actual_status = hypothesis.status.value
                # Write MCP-style HYPOTHESIS_RECORDED journal entry
                execute_with_retry(
                    conn,
                    """INSERT INTO journal (entry_id, case_id, timestamp, entry_type,
                       summary, details, agent_session_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (f"hyprec-{case_id}-{hypothesis_id[-16:]}",
                     case_id, now, "HYPOTHESIS_RECORDED",
                     f"Recorded hypothesis: {title[:80]}",
                     json.dumps({"hypothesis_id": hypothesis_id, "status": actual_status,
                                 "confidence_score": conf_score, "confidence_tier": conf_tier,
                                 "suggested_by_cluster": cluster_id}),
                     "auto-investigation-v1"),
                )
            except ValueError as gate_err:
                # Gate rejected — record as insufficient evidence
                actual_status = "INSUFFICIENT_EVIDENCE"
                logger.warning("  Gate rejected %s: %s", hypothesis_id[:40], gate_err)
                execute_with_retry(
                    conn,
                    """
                    INSERT OR IGNORE INTO hypotheses (
                        hypothesis_id, case_id, examiner, title, observation, interpretation,
                        technique_ids, status, staged_at, modified_at,
                        confidence_score, confidence_tier,
                        evidence_refs, audit_ids, confidence_breakdown,
                        provenance_tier, content_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        hypothesis_id, case_id, examiner, title, observation, interpretation,
                        json.dumps(technique_ids),
                        "INSUFFICIENT_EVIDENCE", now, now,
                        conf_score, conf_tier,
                        json.dumps([{"audit_id": audit_id, "cluster_id": cluster_id}]),
                        json.dumps([audit_id]),
                        conf_breakdown, "NONE",
                        f"auto-{hypothesis_id}",
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
