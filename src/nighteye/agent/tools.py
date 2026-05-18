"""Agent tool registry.

Curates the subset of MCP tools the autonomous investigator can call,
exposes each as a JSON-Schema tool spec for the Anthropic SDK, and
dispatches calls to the underlying Python functions.

The agent always operates against a single active case; case_id and
db_path are injected automatically so the model never has to pass them.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from nighteye.mcp.tools import (
    cluster_tools,
    evidence_tools,
    graph_tools,
    hypothesis_tools,
    journal_tools,
)

logger = logging.getLogger("nighteye.agent.tools")


# Each spec mirrors Anthropic's tool-use schema.
TOOL_SPECS: list[dict[str, Any]] = [
    # ── Discovery: load hypothesis + cluster context ────────────────
    {
        "name": "get_hypothesis_details",
        "description": (
            "Load a hypothesis: title, observation, interpretation, "
            "technique IDs, cited evidence, current confidence."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hypothesis_id": {"type": "string"},
            },
            "required": ["hypothesis_id"],
        },
    },
    {
        "name": "get_cluster_details",
        "description": "Load full details of the cluster that seeded the hypothesis (triggers, members, score).",
        "input_schema": {
            "type": "object",
            "properties": {"cluster_id": {"type": "string"}},
            "required": ["cluster_id"],
        },
    },
    {
        "name": "get_cluster_timeline",
        "description": "Chronological event sequence inside a cluster.",
        "input_schema": {
            "type": "object",
            "properties": {"cluster_id": {"type": "string"}},
            "required": ["cluster_id"],
        },
    },
    {
        "name": "get_cluster_artifacts",
        "description": (
            "Raw evidence documents (from OpenSearch) backing a cluster's "
            "events. No filtering args — returns the full set; truncate "
            "your reasoning if needed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"cluster_id": {"type": "string"}},
            "required": ["cluster_id"],
        },
    },
    {
        "name": "get_cluster_counter_evidence",
        "description": (
            "Pre-computed counter-evidence on a cluster: known-benign signals, "
            "alternative explanations, exculpating context."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"cluster_id": {"type": "string"}},
            "required": ["cluster_id"],
        },
    },
    # ── Pro / contra evidence search ────────────────────────────────
    {
        "name": "search_evidence",
        "description": (
            "Free-text search across canonical events. Use this to look for "
            "BOTH supporting and contradicting evidence — search for benign "
            "explanations too (scheduled tasks, admin tools, known-good IPs)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Keywords or phrase"},
                "evidence_type": {
                    "type": "string",
                    "description": "Optional: PROCESS_EXECUTION | NETWORK | AUTH | REGISTRY | PREFETCH | ALERT",
                },
                "host": {"type": "string", "description": "Optional host filter"},
                "limit": {"type": "integer", "default": 25},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_host_timeline",
        "description": "All canonical events on a host within a time window. Use for context around a hypothesis time anchor.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "start_time": {"type": "string", "description": "ISO-8601"},
                "end_time": {"type": "string", "description": "ISO-8601"},
                "limit": {"type": "integer", "default": 100},
            },
            "required": ["host"],
        },
    },
    {
        "name": "get_process_tree",
        "description": "Process parent/child lineage on a host. Use to verify (or break) suspicious-lineage claims.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "root_pid": {"type": "integer"},
                "start_time": {"type": "string"},
                "end_time": {"type": "string"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "get_network_connections",
        "description": "Network connections (host, remote IP, time window).",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "remote_ip": {"type": "string"},
                "start_time": {"type": "string"},
                "end_time": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
            },
        },
    },
    {
        "name": "get_authentication_events",
        "description": "Authentication events on a host (logon/logoff/failed).",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "user": {"type": "string"},
                "start_time": {"type": "string"},
                "end_time": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
            },
        },
    },
    {
        "name": "get_registry_changes",
        "description": "Registry modifications on a host (key, time window).",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "registry_key": {"type": "string"},
                "start_time": {"type": "string"},
                "end_time": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
            },
        },
    },
    # ── Graph queries ────────────────────────────────────────────────
    {
        "name": "query_neighbors",
        "description": "Get entities connected to a given entity (process, file, user, IP, host).",
        "input_schema": {
            "type": "object",
            "properties": {
                "entity_id": {"type": "string"},
                "edge_type": {"type": "string"},
                "direction": {"type": "string", "enum": ["out", "in", "both"], "default": "both"},
                "limit": {"type": "integer", "default": 25},
            },
            "required": ["entity_id"],
        },
    },
    {
        "name": "get_entity_details",
        "description": "Full details of one entity including its top neighbors.",
        "input_schema": {
            "type": "object",
            "properties": {
                "entity_id": {"type": "string"},
                "include_neighbors": {"type": "boolean", "default": True},
            },
            "required": ["entity_id"],
        },
    },
    # ── Decisions (terminal — call exactly one when investigation done) ─
    {
        "name": "approve_hypothesis",
        "description": (
            "TERMINAL. Approve the hypothesis when the weight of evidence "
            "supports it AND you have actively searched for and ruled out "
            "benign explanations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hypothesis_id": {"type": "string"},
                "approved_by": {"type": "string", "description": "Agent identifier"},
            },
            "required": ["hypothesis_id", "approved_by"],
        },
    },
    {
        "name": "reject_hypothesis",
        "description": (
            "TERMINAL. Reject when contradicting/benign evidence outweighs "
            "the original signal."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hypothesis_id": {"type": "string"},
                "rejected_by": {"type": "string"},
                "reason": {"type": "string", "description": "What evidence overturned it"},
            },
            "required": ["hypothesis_id", "rejected_by", "reason"],
        },
    },
    {
        "name": "mark_insufficient_evidence",
        "description": (
            "TERMINAL. Mark as INSUFFICIENT_EVIDENCE when neither side is "
            "decisive after thorough search."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "hypothesis_id": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["hypothesis_id", "reason"],
        },
    },
    # ── Journal (running reasoning trail) ────────────────────────────
    {
        "name": "journal_record_decision",
        "description": (
            "REQUIRED before any terminal decision. Records the final "
            "rationale (multi-sentence) plus the hypotheses considered. "
            "This is what the human reviewer reads to audit the decision."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string", "description": "One-line verdict"},
                "rationale": {"type": "string", "description": "Full multi-sentence reasoning"},
                "hypotheses_considered": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Hypothesis IDs you weighed (including the one being decided)",
                },
            },
            "required": ["summary", "rationale"],
        },
    },
    {
        "name": "journal_checkpoint",
        "description": (
            "Record a reasoning step with running confidence. Include "
            "`confidence` (0-100 int) and `delta` (signed int change from "
            "the previous checkpoint) in next_steps as JSON for the "
            "reasoning-graph UI."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "confidence": {"type": "integer", "description": "0-100 running confidence"},
                "delta": {"type": "integer", "description": "Signed change since previous checkpoint"},
                "reasoning": {"type": "string", "description": "Why this evidence shifted confidence"},
                "evidence_refs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "IDs/indices of evidence supporting this step",
                },
            },
            "required": ["summary", "confidence", "delta", "reasoning"],
        },
    },
]


# Terminal tools that end the per-hypothesis loop.
TERMINAL_TOOLS = {"approve_hypothesis", "reject_hypothesis", "mark_insufficient_evidence"}


def _dispatch_journal_checkpoint(case_id: str, db_path: str, **kwargs: Any) -> dict[str, Any]:
    """Pack the agent's structured checkpoint into the existing journal_checkpoint shape.

    `journal_tools.journal_checkpoint` resolves its own DB from case_id —
    do NOT pass db_path to it (the underlying wrapper has no such kwarg).
    """
    payload = {
        "confidence": kwargs.get("confidence"),
        "delta": kwargs.get("delta"),
        "reasoning": kwargs.get("reasoning", ""),
        "evidence_refs": kwargs.get("evidence_refs", []),
    }
    return journal_tools.journal_checkpoint(
        summary=kwargs.get("summary", ""),
        next_steps=[json.dumps(payload)],
        case_id=case_id,
        agent_session_id="auto-investigator-v1",
    )


def build_dispatch(case_id: str, db_path: str) -> dict[str, Callable[..., Any]]:
    """Build the {tool_name: callable} dispatch table for a given case.

    The injection wrappers introspect each function's accepted kwargs so we
    don't pass `db_path` to a tool that only accepts `case_id` (or vice
    versa). Without this guard, the underlying TypeError aborts the call.
    """
    import inspect

    def _injecting(fn):
        sig = inspect.signature(fn)
        accepts = set(sig.parameters.keys())
        accepts_var_kw = any(
            p.kind == inspect.Parameter.VAR_KEYWORD
            for p in sig.parameters.values()
        )

        def wrapper(**kwargs):
            if accepts_var_kw or "case_id" in accepts:
                kwargs.setdefault("case_id", case_id)
            if accepts_var_kw or "db_path" in accepts:
                kwargs.setdefault("db_path", db_path)
            return fn(**kwargs)

        return wrapper

    _with_case_db = _injecting
    _with_db_only = _injecting

    return {
        # Hypothesis discovery + decisions
        "get_hypothesis_details": _with_db_only(hypothesis_tools.get_hypothesis_details),
        "approve_hypothesis":     _with_db_only(hypothesis_tools.approve_hypothesis),
        "reject_hypothesis":      _with_db_only(hypothesis_tools.reject_hypothesis),
        # The MCP `mark_insufficient_evidence` creates a NEW hypothesis with
        # INSUFFICIENT_EVIDENCE status — wrong shape for an agent terminal
        # decision, which should flip the EXISTING DRAFT it's working on.
        # Mutate the existing row in place instead.
        "mark_insufficient_evidence": lambda **k: _mark_existing_insufficient(
            db_path=db_path,
            hypothesis_id=k["hypothesis_id"],
            reason=k.get("reason", "Insufficient evidence after agent review"),
        ),
        # Cluster context
        "get_cluster_details":          _with_db_only(cluster_tools.get_cluster_details),
        "get_cluster_timeline":         _with_db_only(cluster_tools.get_cluster_timeline),
        "get_cluster_artifacts":        _with_db_only(cluster_tools.get_cluster_artifacts),
        "get_cluster_counter_evidence": _with_db_only(cluster_tools.get_cluster_counter_evidence),
        # Evidence search
        "search_evidence":             _with_case_db(evidence_tools.search_evidence),
        "get_host_timeline":           _with_case_db(evidence_tools.get_host_timeline),
        "get_process_tree":            _with_case_db(evidence_tools.get_process_tree),
        "get_network_connections":     _with_case_db(evidence_tools.get_network_connections),
        "get_authentication_events":   _with_case_db(evidence_tools.get_authentication_events),
        "get_registry_changes":        _with_case_db(evidence_tools.get_registry_changes),
        # Graph
        "query_neighbors":     _with_db_only(graph_tools.query_neighbors),
        "get_entity_details":  _with_db_only(graph_tools.get_entity_details),
        # Journal
        "journal_checkpoint": lambda **k: _dispatch_journal_checkpoint(case_id, db_path, **k),
        "journal_record_decision": lambda **k: journal_tools.journal_record_decision(
            summary=k.get("summary", ""),
            rationale=k.get("rationale", ""),
            hypotheses_considered=k.get("hypotheses_considered"),
            case_id=case_id,
            agent_session_id="auto-investigator-v1",
        ),
    }


_TOOL_ARG_WHITELIST: dict[str, set[str]] = {
    spec["name"]: set(spec["input_schema"].get("properties", {}).keys())
    for spec in TOOL_SPECS
}


def _mark_existing_insufficient(
    db_path: str, hypothesis_id: str, reason: str,
) -> dict[str, Any]:
    """Flip an existing DRAFT hypothesis to INSUFFICIENT_EVIDENCE.

    The MCP `mark_insufficient_evidence` tool creates a brand-new
    hypothesis with that status — useful for examiner-authored
    insufficient findings, but wrong for an agent terminal decision
    which should mutate the DRAFT it was investigating.
    """
    from datetime import datetime, timezone
    from nighteye.db import connect

    now = datetime.now(timezone.utc).isoformat()
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT status FROM hypotheses WHERE hypothesis_id = ?",
            (hypothesis_id,),
        ).fetchone()
        if row is None:
            return {"success": False,
                    "error": f"Hypothesis not found: {hypothesis_id}"}
        if row["status"] in ("APPROVED", "REJECTED"):
            return {"success": False,
                    "error": f"Cannot mark insufficient — already {row['status']}"}
        conn.execute(
            """UPDATE hypotheses
                  SET status = 'INSUFFICIENT_EVIDENCE',
                      rejection_reason = ?,
                      modified_at = ?,
                      challenged_at = COALESCE(challenged_at, ?)
                WHERE hypothesis_id = ?""",
            (reason, now, now, hypothesis_id),
        )
    return {"success": True, "hypothesis_id": hypothesis_id,
            "status": "INSUFFICIENT_EVIDENCE", "reason": reason}


def execute_tool(
    dispatch: dict[str, Callable[..., Any]],
    name: str,
    args: dict[str, Any],
) -> str:
    """Execute a tool by name; return JSON-string result safe for tool_result.

    Tolerates extra hallucinated kwargs by filtering against the schema
    whitelist for each tool — models occasionally pass `confidence`,
    `rationale`, etc. to `approve_hypothesis`; without filtering, the
    underlying function raises TypeError and the call is wasted.
    """
    fn = dispatch.get(name)
    if fn is None:
        return json.dumps({"error": f"unknown tool: {name}"})

    allowed = _TOOL_ARG_WHITELIST.get(name)
    if allowed is not None:
        extras = [k for k in args.keys()
                  if k not in allowed and k not in {"case_id", "db_path"}]
        if extras:
            logger.debug("Tool %s: dropping unknown args %s", name, extras)
        args = {k: v for k, v in args.items()
                if k in allowed and k not in {"case_id", "db_path"}}
    else:
        args = {k: v for k, v in args.items()
                if k not in {"case_id", "db_path"}}

    try:
        result = fn(**args)
    except TypeError as exc:
        return json.dumps({"error": f"bad arguments to {name}: {exc}"})
    except Exception as exc:
        logger.warning("Tool %s raised: %s", name, exc)
        return json.dumps({"error": str(exc)})
    try:
        return json.dumps(result, default=str)[:50_000]
    except Exception:
        return json.dumps({"result_repr": repr(result)[:50_000]})
