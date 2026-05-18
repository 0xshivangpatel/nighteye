"""Per-hypothesis autonomous investigation loop.

Loads a DRAFT hypothesis, hands it to the chosen LLM backend, lets the
model call MCP tools until it hits a terminal decision (approve / reject
/ insufficient) or exhausts its budget.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nighteye.agent.backends import LLMBackend, QuotaExhausted, TurnResult, build_backend
from nighteye.agent.prompts import SYSTEM_PROMPT, build_user_prompt
from nighteye.agent.tools import (
    TERMINAL_TOOLS,
    TOOL_SPECS,
    build_dispatch,
    execute_tool,
)
from nighteye.mcp.tools import hypothesis_tools

logger = logging.getLogger("nighteye.agent.investigator")

DEFAULT_BUDGET_CALLS = 25
DEFAULT_BUDGET_SECONDS = 300


@dataclass
class InvestigationResult:
    hypothesis_id: str
    verdict: str            # APPROVED | REJECTED | INSUFFICIENT | BUDGET_EXHAUSTED | ERROR
    tool_calls: int
    elapsed_sec: float
    final_confidence: int | None = None
    error: str | None = None


def investigate_hypothesis(
    hypothesis_id: str,
    case_id: str,
    db_path: str,
    backend: LLMBackend,
    budget_calls: int = DEFAULT_BUDGET_CALLS,
    budget_seconds: int = DEFAULT_BUDGET_SECONDS,
) -> InvestigationResult:
    """Run one hypothesis through the agent loop."""
    t_start = time.time()
    dispatch = build_dispatch(case_id, db_path)

    # Bootstrap context: load the hypothesis directly so we can render the
    # opening prompt without burning a tool call.
    try:
        hyp_envelope = hypothesis_tools.get_hypothesis_details(
            hypothesis_id=hypothesis_id, db_path=db_path,
        )
    except Exception as exc:
        return InvestigationResult(
            hypothesis_id=hypothesis_id, verdict="ERROR",
            tool_calls=0, elapsed_sec=0.0, error=str(exc),
        )
    # MCP wrapper returns {"success": ..., "hypothesis": {...}} — unwrap.
    if isinstance(hyp_envelope, dict) and hyp_envelope.get("success"):
        hyp_info = dict(hyp_envelope.get("hypothesis") or {})
        # Inject the canonical id the bootstrap was called with so the
        # user prompt always has it, even if the schema uses 'id' internally.
        hyp_info.setdefault("hypothesis_id", hypothesis_id)
    else:
        # Loader failed; still hand the agent the ID so it can retry.
        hyp_info = {"hypothesis_id": hypothesis_id,
                    "title": "(load failed)", "observation": "", "interpretation": ""}

    suggested_cluster = _peek_suggested_cluster(db_path, hypothesis_id)
    system = SYSTEM_PROMPT.format(
        budget_calls=budget_calls,
        budget_seconds=budget_seconds,
    )
    messages: list[dict] = [
        {"role": "user", "content": build_user_prompt(hyp_info, suggested_cluster)},
    ]

    tool_call_count = 0
    final_confidence: int | None = None
    stall_nudges = 0
    MAX_STALL_NUDGES = 2

    while True:
        if time.time() - t_start > budget_seconds:
            logger.warning("Budget exhausted (time) for %s", hypothesis_id)
            return InvestigationResult(
                hypothesis_id=hypothesis_id, verdict="BUDGET_EXHAUSTED",
                tool_calls=tool_call_count,
                elapsed_sec=time.time() - t_start,
                final_confidence=final_confidence,
            )
        if tool_call_count >= budget_calls:
            logger.warning("Budget exhausted (calls) for %s", hypothesis_id)
            return InvestigationResult(
                hypothesis_id=hypothesis_id, verdict="BUDGET_EXHAUSTED",
                tool_calls=tool_call_count,
                elapsed_sec=time.time() - t_start,
                final_confidence=final_confidence,
            )

        turn: TurnResult = backend.run_turn(
            system=system, messages=messages, tools=TOOL_SPECS,
        )

        # Persist the assistant's turn back into the transcript.
        messages.append({"role": "assistant", "content": turn.raw_content})

        if not turn.tool_calls:
            # Model emitted only text — nudge it to commit. After
            # MAX_STALL_NUDGES we give up and write a real INSUFFICIENT
            # decision to the DB so the hypothesis doesn't remain DRAFT.
            stall_nudges += 1
            if stall_nudges <= MAX_STALL_NUDGES:
                logger.info("[%s] no tool call — nudging to commit "
                            "(nudge %d/%d)",
                            hypothesis_id, stall_nudges, MAX_STALL_NUDGES)
                messages.append({
                    "role": "user",
                    "content": (
                        "You ended that turn without calling a tool. Make "
                        "your final decision now. Call ONE of: "
                        "`approve_hypothesis(hypothesis_id, approved_by)`, "
                        "`reject_hypothesis(hypothesis_id, rejected_by, reason)`, "
                        "or `mark_insufficient_evidence(hypothesis_id, reason)`. "
                        "If the evidence is ambiguous, that is exactly what "
                        "`mark_insufficient_evidence` is for — call it with "
                        "your reason. Do not narrate; just call the tool."
                    ),
                })
                continue
            # Forcibly write an INSUFFICIENT decision so the hypothesis
            # doesn't remain DRAFT after the budget is spent.
            logger.warning("[%s] model would not commit; forcing "
                           "mark_insufficient_evidence", hypothesis_id)
            try:
                dispatch["mark_insufficient_evidence"](
                    hypothesis_id=hypothesis_id,
                    reason="Agent ended turn without explicit decision "
                           "after stall nudges; auto-flagged.",
                )
            except Exception as exc:
                logger.warning("Forced mark_insufficient failed: %s", exc)
            return InvestigationResult(
                hypothesis_id=hypothesis_id, verdict="INSUFFICIENT",
                tool_calls=tool_call_count,
                elapsed_sec=time.time() - t_start,
                final_confidence=final_confidence,
                error="model stalled; auto-marked insufficient",
            )

        tool_results: list[dict] = []
        terminal_hit: str | None = None
        for call in turn.tool_calls:
            tool_call_count += 1
            result_str = execute_tool(dispatch, call.name, call.input)
            tool_failed = '"error"' in result_str[:120]
            logger.info("[%s] (%d/%d) tool=%s%s",
                        hypothesis_id, tool_call_count, budget_calls,
                        call.name, "  [FAILED]" if tool_failed else "")
            if tool_failed:
                logger.warning("  args=%r  result=%s",
                               call.input, result_str[:300])
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": call.id,
                "content": result_str,
                "is_error": tool_failed,
            })
            if call.name == "journal_checkpoint":
                conf = call.input.get("confidence")
                if isinstance(conf, int):
                    final_confidence = conf
            if call.name in TERMINAL_TOOLS and not tool_failed:
                # Only a successful terminal call ends the loop. A failed
                # decision call should let the model retry.
                terminal_hit = call.name

        messages.append({"role": "user", "content": tool_results})

        if terminal_hit:
            verdict = {
                "approve_hypothesis": "APPROVED",
                "reject_hypothesis": "REJECTED",
                "mark_insufficient_evidence": "INSUFFICIENT",
            }[terminal_hit]
            return InvestigationResult(
                hypothesis_id=hypothesis_id, verdict=verdict,
                tool_calls=tool_call_count,
                elapsed_sec=time.time() - t_start,
                final_confidence=final_confidence,
            )


def _peek_suggested_cluster(db_path: str, hypothesis_id: str) -> str | None:
    """Return the cluster_id from the first evidence_ref, if any."""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT evidence_refs FROM hypotheses WHERE hypothesis_id = ?",
            (hypothesis_id,),
        ).fetchone()
        conn.close()
        if not row:
            return None
        import json as _json
        refs = _json.loads(row["evidence_refs"] or "[]")
        for ref in refs:
            cid = ref.get("cluster_id")
            if cid:
                return cid
    except Exception:
        return None
    return None


def run_batch(
    case_id: str,
    db_path: str,
    hypothesis_ids: list[str],
    backend: LLMBackend,
    budget_calls: int = DEFAULT_BUDGET_CALLS,
    budget_seconds: int = DEFAULT_BUDGET_SECONDS,
) -> list[InvestigationResult]:
    """Investigate a batch of hypotheses sequentially.

    Sequential (not parallel) by design: the SQLite graph DB is the source
    of truth for journal/decision writes and we want clean single-writer
    semantics. Parallel runs would also fight for the OS scroll budget.
    """
    results: list[InvestigationResult] = []
    for i, hid in enumerate(hypothesis_ids, 1):
        logger.info("─── Investigating %d/%d: %s ───",
                    i, len(hypothesis_ids), hid)
        try:
            r = investigate_hypothesis(
                hypothesis_id=hid, case_id=case_id, db_path=db_path,
                backend=backend, budget_calls=budget_calls,
                budget_seconds=budget_seconds,
            )
        except QuotaExhausted as exc:
            # Provider quota is gone — every remaining hypothesis would
            # fail identically. Abort the whole batch with one clear
            # message so the operator sees the reset window instead of
            # 58 spurious INSUFFICIENT verdicts.
            logger.error(
                "QUOTA EXHAUSTED on backend %s — aborting batch at "
                "%d/%d. Provider message: %s",
                backend.name, i, len(hypothesis_ids), str(exc)[:200],
            )
            results.append(InvestigationResult(
                hypothesis_id=hid, verdict="QUOTA_EXHAUSTED",
                tool_calls=0, elapsed_sec=0.0, error=str(exc)[:400],
            ))
            break
        except Exception as exc:
            logger.exception("Investigation failed for %s", hid)
            r = InvestigationResult(
                hypothesis_id=hid, verdict="ERROR",
                tool_calls=0, elapsed_sec=0.0, error=str(exc),
            )
            results.append(r)
            continue
        results.append(r)
        logger.info("  → %s in %.0fs (%d tool calls, conf=%s)",
                    r.verdict, r.elapsed_sec, r.tool_calls, r.final_confidence)
    return results


def select_hypotheses(
    db_path: str,
    case_id: str,
    explicit_ids: list[str] | None = None,
    tier: str | None = None,
    only_new_since: str | None = None,
    only_drafts: bool = True,
) -> list[str]:
    """Resolve a CLI selection into hypothesis IDs to investigate."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        if explicit_ids:
            placeholders = ",".join("?" * len(explicit_ids))
            rows = conn.execute(
                f"SELECT hypothesis_id FROM hypotheses "
                f"WHERE case_id = ? AND hypothesis_id IN ({placeholders}) "
                f"ORDER BY confidence_tier DESC",
                (case_id, *explicit_ids),
            ).fetchall()
        else:
            sql = ["SELECT hypothesis_id FROM hypotheses WHERE case_id = ?"]
            params: list[Any] = [case_id]
            if only_drafts:
                sql.append("AND status = 'DRAFT'")
            if tier:
                placeholders = ",".join("?" * len(tier.split(",")))
                sql.append(f"AND confidence_tier IN ({placeholders})")
                params.extend(tier.split(","))
            if only_new_since:
                sql.append("AND staged_at >= ?")
                params.append(only_new_since)
            sql.append("ORDER BY confidence_tier DESC, staged_at DESC")
            rows = conn.execute(" ".join(sql), params).fetchall()
        return [r["hypothesis_id"] for r in rows]
    finally:
        conn.close()
