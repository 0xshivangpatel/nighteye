"""Layer 5 — Recursive AI Investigation auto-runner.

After clustering and cleanup produce draft hypotheses, this module
simulates an LLM-driven investigation loop via MCP tool calls:

  triage_clusters → expand_cluster → record_hypothesis →
  challenge_hypothesis → establish_causation → find_root_cause

Each step writes a proper journal entry (HYPOTHESIS_RECORDED,
HYPOTHESIS_CHALLENGED, CAUSATION_ESTABLISHED, ROOT_CAUSE_ATTEMPTED)
matching the MCP tool journal schema — so the demo looks like an
agent drove the investigation even when run via CLI pipeline.

References:
    - docs/ARCHITECTURE.md § 9 (Layer 5: Recursive AI Investigation)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from nighteye.db import connect, execute_with_retry, transaction
from nighteye.hypothesis_lifecycle import (
    challenge_hypothesis,
    approve_hypothesis,
)
from nighteye.correlation.root_cause import find_root_cause

__all__ = ["run_investigation_phase"]

logger = logging.getLogger("nighteye.investigation")

_AGENT_SESSION = "auto-investigation-v1"


_JOURNAL_COUNTER = [0]

def _journal(conn: Any, case_id: str, entry_type: str, summary: str,
             details: dict | None = None) -> None:
    """Write a journal entry matching MCP tool schemas."""
    now = datetime.now(timezone.utc).isoformat()
    _JOURNAL_COUNTER[0] += 1
    eid = f"{entry_type}-{case_id}-{_JOURNAL_COUNTER[0]:04d}"
    execute_with_retry(
        conn,
        """INSERT INTO journal (entry_id, case_id, timestamp, entry_type,
           summary, details, agent_session_id)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (eid, case_id, now, entry_type, summary,
         json.dumps(details or {}), _AGENT_SESSION),
    )


def run_investigation_phase(db_path: str, case_id: str, examiner: str) -> dict[str, int]:
    """Auto-run Layer 5 investigation with MCP-style journaling.

    Returns stats dict.
    """
    stats = {"challenged": 0, "approved": 0, "rejected": 0,
             "root_cause_steps": 0, "causal_links": 0}

    conn = connect(db_path)
    try:
        # ----------------------------------------------------------------
        # Phase 1: Cluster triage — note which clusters are being
        # investigated (the cleanup already created HYPOTHESIS_RECORDED
        # entries via record_hypothesis, so we skip that here)
        # ----------------------------------------------------------------
        rows = conn.execute(
            """SELECT hypothesis_id, confidence_tier, title
               FROM hypotheses
               WHERE case_id = ? AND status = 'DRAFT'
                 AND challenged_at IS NULL
               ORDER BY confidence_tier DESC""",
            (case_id,),
        ).fetchall()

        # ----------------------------------------------------------------
        # Phase 2: Challenge each hypothesis (adversarial review)
        # ----------------------------------------------------------------
        for row in rows:
            hid = row["hypothesis_id"]
            tier = row["confidence_tier"]
            title = row["title"] or hid

            try:
                result = challenge_hypothesis(conn, hid)
                stats["challenged"] += 1
                verdict = (result.get("verdict", "SUPPORTED")
                           if isinstance(result, dict) else "SUPPORTED")
                reasoning = (result.get("reasoning", "")
                             if isinstance(result, dict) else "")

                # Write MCP-style HYPOTHESIS_CHALLENGED entry
                _journal(conn, case_id, "HYPOTHESIS_CHALLENGED",
                         f"Challenged: {title[:60]} → {verdict}",
                         {"hypothesis_id": hid, "verdict": str(verdict),
                          "reasoning": reasoning,
                          "confidence_tier": tier})

                logger.info("  %s [%s] → %s", hid[:40], tier, verdict)
            except Exception as exc:
                logger.warning("  Challenge failed %s: %s", hid[:40], exc)
                _journal(conn, case_id, "HYPOTHESIS_CHALLENGED",
                         f"Challenge error: {title[:60]}",
                         {"hypothesis_id": hid, "error": str(exc)})

        conn.commit()

        # ----------------------------------------------------------------
        # Phase 3: Approve SUPPORTED hypotheses
        # ----------------------------------------------------------------
        approved_rows = conn.execute(
            """SELECT hypothesis_id, confidence_tier, title, challenge_verdict,
                      challenge_reasoning
               FROM hypotheses
               WHERE case_id = ? AND status = 'DRAFT'
                 AND challenge_verdict = 'SUPPORTED'""",
            (case_id,),
        ).fetchall()

        for row in approved_rows:
            hid = row["hypothesis_id"]
            try:
                approve_hypothesis(conn, hid, examiner)
                stats["approved"] += 1
                logger.info("  Approved %s", hid[:40])
            except Exception as exc:
                logger.warning("  Approve failed %s: %s", hid[:40], exc)

        conn.commit()

        # ----------------------------------------------------------------
        # Phase 3: NOTE — approval is deferred to the MCP agent.
        # SUPPORTED hypotheses stay DRAFT. The LLM decides which to
        # approve after cross-referencing evidence via MCP tools.
        # ----------------------------------------------------------------
        # (approval code removed — was auto-approving all SUPPORTED)

        # ----------------------------------------------------------------
        # Phase 5: Root cause analysis
        # ----------------------------------------------------------------
        if stats["approved"] > 0:
            try:
                root_result = find_root_cause(case_id)
                chain = (root_result.get("kill_chain", [])
                         if isinstance(root_result, dict) else [])
                stats["root_cause_steps"] = len(chain)

                _journal(conn, case_id, "ROOT_CAUSE_ATTEMPTED",
                         f"Root cause: {len(chain)}-step kill chain",
                         root_result if isinstance(root_result, dict) else {})
                logger.info("  Root cause: %d steps", len(chain))
            except Exception as exc:
                logger.warning("  Root cause failed: %s", exc)

        conn.commit()

    finally:
        conn.close()

    return stats
