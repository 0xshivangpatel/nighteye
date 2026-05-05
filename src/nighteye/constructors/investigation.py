"""Layer 5 — Recursive AI Investigation auto-runner.

After clustering and cleanup produce draft hypotheses, this module:
1. Challenges each DRAFT hypothesis (adversarial review)
2. Approves hypotheses that pass challenge with SUPPORTED verdict
3. Runs root-cause correlation on approved hypotheses
4. Seeds journal with investigation trail

Designed to run non-interactively as a pipeline step.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from nighteye.db import connect, execute_with_retry
from nighteye.hypothesis_lifecycle import (
    challenge_hypothesis,
    approve_hypothesis,
    reject_hypothesis,
)
from nighteye.correlation.root_cause import find_root_cause

__all__ = ["run_investigation_phase"]

logger = logging.getLogger("nighteye.investigation")


def run_investigation_phase(db_path: str, case_id: str, examiner: str) -> dict[str, int]:
    """Auto-run the Layer 5 investigation on all DRAFT hypotheses.

    Returns stats dict.
    """
    stats = {
        "challenged": 0,
        "approved": 0,
        "rejected": 0,
        "root_cause_steps": 0,
    }

    conn = connect(db_path)
    try:
        # ----------------------------------------------------------------
        # Phase 1: Challenge all DRAFT hypotheses
        # ----------------------------------------------------------------
        rows = conn.execute(
            """
            SELECT hypothesis_id, confidence_tier, title
            FROM hypotheses
            WHERE case_id = ? AND status = 'DRAFT' AND challenged_at IS NULL
            ORDER BY confidence_tier DESC
            """,
            (case_id,),
        ).fetchall()

        for row in rows:
            hid = row["hypothesis_id"]
            tier = row["confidence_tier"]
            title = row["title"] or hid

            try:
                result = challenge_hypothesis(conn, hid)
                stats["challenged"] += 1
                verdict = result.get("verdict", "UNKNOWN") if isinstance(result, dict) else "UNKNOWN"
                logger.info("  Challenged %s [%s] → %s", hid[:40], tier, verdict)
            except Exception as exc:
                logger.warning("  Challenge failed for %s: %s", hid[:40], exc)

        conn.commit()

        # ----------------------------------------------------------------
        # Phase 2: Approve SUPPORTED + MEDIUM/HIGH hypotheses
        # ----------------------------------------------------------------
        approved_rows = conn.execute(
            """
            SELECT hypothesis_id, confidence_tier, challenge_verdict
            FROM hypotheses
            WHERE case_id = ? AND status = 'DRAFT'
              AND challenge_verdict = 'SUPPORTED'
            """,
            (case_id,),
        ).fetchall()

        for row in approved_rows:
            hid = row["hypothesis_id"]
            try:
                approve_hypothesis(conn, hid, examiner)
                stats["approved"] += 1
                logger.info("  Approved %s", hid[:40])
            except Exception as exc:
                logger.warning("  Approve failed for %s: %s", hid[:40], exc)

        conn.commit()

        # ----------------------------------------------------------------
        # Phase 3: Find root cause (kill chain)
        # ----------------------------------------------------------------
        now = datetime.now(timezone.utc).isoformat()
        if stats["approved"] > 0:
            try:
                root_result = find_root_cause(case_id)
                steps = root_result.get("kill_chain", []) if isinstance(root_result, dict) else []
                stats["root_cause_steps"] = len(steps)

                execute_with_retry(
                    conn,
                    """
                    INSERT INTO journal (
                        entry_id, case_id, timestamp, entry_type, summary, details
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f"rc-{case_id}-{now[:10]}",
                        case_id,
                        now,
                        "ROOT_CAUSE_ATTEMPTED",
                        f"Root cause analysis: {stats['root_cause_steps']} steps in kill chain",
                        json.dumps(root_result) if isinstance(root_result, dict) else "{}",
                    ),
                )
                conn.commit()
                logger.info("  Root cause: %d steps", stats["root_cause_steps"])
            except Exception as exc:
                logger.warning("  Root cause failed: %s", exc)

        # ----------------------------------------------------------------
        # Phase 4: Investigation decision journal entry
        # ----------------------------------------------------------------
        execute_with_retry(
            conn,
            """
            INSERT INTO journal (
                entry_id, case_id, timestamp, entry_type, summary, details
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                f"inv-{case_id}-{now[:10]}",
                case_id,
                now,
                "INVESTIGATION_DECISION",
                f"Auto-investigation: {stats['challenged']} challenged, "
                f"{stats['approved']} approved, {stats['rejected']} rejected, "
                f"{stats['root_cause_steps']} root-cause steps",
                json.dumps(stats),
            ),
        )
        conn.commit()

    finally:
        conn.close()

    return stats
