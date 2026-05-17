"""LLM backends for the autonomous investigator.

Two implementations share a single contract:

    backend.run_turn(messages, tools) -> TurnResult

where `TurnResult` carries the assistant message and a list of tool_use
blocks (each with id, name, input). The investigator loop is identical
regardless of which backend is in play.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("nighteye.agent.backends")


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class TurnResult:
    text: str                          # assistant's freeform text this turn
    tool_calls: list[ToolCall]         # tool_use blocks (possibly empty)
    stop_reason: str                   # "tool_use" | "end_turn" | other
    raw_content: list[dict] = field(default_factory=list)  # for re-feeding


def detect_backend(preference: str = "auto") -> str:
    """Pick which backend to use.

    preference: "auto" | "api" | "cli"
    Returns: "api" or "cli". Raises if neither is available.
    """
    if preference == "api":
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("--backend api requires ANTHROPIC_API_KEY env var")
        return "api"
    if preference == "cli":
        if not shutil.which("claude"):
            raise RuntimeError("--backend cli requires `claude` on PATH")
        return "cli"
    # auto
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "api"
    if shutil.which("claude"):
        return "cli"
    raise RuntimeError(
        "No backend available: set ANTHROPIC_API_KEY or install Claude Code CLI"
    )


def build_backend(preference: str, model: str | None = None) -> "LLMBackend":
    kind = detect_backend(preference)
    if kind == "api":
        return ApiBackend(model=model or "claude-opus-4-7")
    return CliBackend(model=model)


class LLMBackend:
    name: str

    def run_turn(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict],
    ) -> TurnResult:
        raise NotImplementedError


# ─────────────────────────────────────────────────────────────────────
# API backend — direct anthropic SDK
# ─────────────────────────────────────────────────────────────────────

class ApiBackend(LLMBackend):
    name = "api"

    def __init__(self, model: str = "claude-opus-4-7"):
        import anthropic  # imported lazily so CLI-only users don't need the SDK
        self.client = anthropic.Anthropic()
        self.model = model

    def run_turn(self, system, messages, tools) -> TurnResult:
        resp = self.client.messages.create(
            model=self.model,
            system=system,
            messages=messages,
            tools=tools,
            max_tokens=4096,
        )
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        raw_content: list[dict] = []
        for block in resp.content:
            d = block.model_dump() if hasattr(block, "model_dump") else dict(block)
            raw_content.append(d)
            if d.get("type") == "text":
                text_parts.append(d.get("text", ""))
            elif d.get("type") == "tool_use":
                tool_calls.append(ToolCall(
                    id=d["id"], name=d["name"], input=d.get("input", {}),
                ))
        return TurnResult(
            text="\n".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=resp.stop_reason or "unknown",
            raw_content=raw_content,
        )


# ─────────────────────────────────────────────────────────────────────
# CLI backend — claude --print with MCP server config
# ─────────────────────────────────────────────────────────────────────
#
# The Claude Code CLI in --print mode runs a single turn at a time. We
# emulate the tool-use loop by:
#   1) feeding the transcript as one combined prompt
#   2) parsing the model's reply for our sentinel-formatted tool requests
#
# A purely JSON tool-call protocol is more reliable than asking the CLI
# to speak the SDK's native tool_use blocks, since `claude --print` is
# free-form text. We ask the model to wrap each tool call in a strict
# fenced JSON block beginning with `<<TOOL_CALL>>`.

_CLI_TOOL_SENTINEL_OPEN = "<<TOOL_CALL>>"
_CLI_TOOL_SENTINEL_CLOSE = "<<END_TOOL_CALL>>"


_CLI_PROTOCOL_GUIDE = f"""\
# Tool-use protocol (CLI backend)

You do NOT have direct tool access through this transport. Instead, when you
want to call a tool, emit a single line `{_CLI_TOOL_SENTINEL_OPEN}` followed
by a JSON object on the next line containing {{"name": <tool_name>,
"input": <args>}}, then `{_CLI_TOOL_SENTINEL_CLOSE}` on its own line. You
may include one tool call per turn. The harness will run it and feed the
result back in the next turn. When you are ready to make a terminal
decision (approve/reject/insufficient), use the same protocol with that
tool name — do not narrate the decision in prose.
"""


class CliBackend(LLMBackend):
    name = "cli"

    def __init__(self, model: str | None = None):
        self.model = model
        self.cli = shutil.which("claude")
        if not self.cli:
            raise RuntimeError("claude CLI not found on PATH")

    def run_turn(self, system, messages, tools) -> TurnResult:
        # Render transcript as a single prompt: system + tool catalog +
        # protocol guide + interleaved user/assistant turns. The CLI is
        # stateless per --print call.
        tool_catalog = "\n".join(
            f"- {t['name']}: {t['description']}" for t in tools
        )
        rendered = [
            "## System",
            system,
            "",
            "## Available tools",
            tool_catalog,
            "",
            _CLI_PROTOCOL_GUIDE,
            "",
            "## Conversation so far",
        ]
        for m in messages:
            role = m["role"]
            content = m["content"]
            if isinstance(content, str):
                rendered.append(f"### {role}\n{content}\n")
            else:
                # Render structured content (tool_result, tool_use re-feeds)
                for block in content:
                    if block.get("type") == "tool_result":
                        rendered.append(
                            f"### tool_result (id={block.get('tool_use_id')})\n"
                            f"{block.get('content','')}\n"
                        )
                    elif block.get("type") == "text":
                        rendered.append(f"### {role}\n{block.get('text','')}\n")

        prompt = "\n".join(rendered)
        cmd = [self.cli, "--print"]
        if self.model:
            cmd += ["--model", self.model]
        result = subprocess.run(
            cmd, input=prompt, capture_output=True, text=True, timeout=300,
        )
        out = (result.stdout or "").strip()
        text, tc = _parse_cli_response(out)
        return TurnResult(
            text=text,
            tool_calls=tc,
            stop_reason="tool_use" if tc else "end_turn",
            raw_content=[{"type": "text", "text": text}]
                        + [{"type": "tool_use", "id": c.id, "name": c.name,
                            "input": c.input} for c in tc],
        )


def _parse_cli_response(text: str) -> tuple[str, list[ToolCall]]:
    """Extract <<TOOL_CALL>> ... <<END_TOOL_CALL>> blocks from CLI output."""
    out_calls: list[ToolCall] = []
    remaining = text
    while True:
        i = remaining.find(_CLI_TOOL_SENTINEL_OPEN)
        if i < 0:
            break
        j = remaining.find(_CLI_TOOL_SENTINEL_CLOSE, i)
        if j < 0:
            break
        block = remaining[i + len(_CLI_TOOL_SENTINEL_OPEN):j].strip()
        # tolerate fenced ```json wrappers
        if block.startswith("```"):
            block = block.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        try:
            obj = json.loads(block)
            out_calls.append(ToolCall(
                id=f"cli-{uuid.uuid4().hex[:8]}",
                name=obj.get("name", ""),
                input=obj.get("input", {}) or {},
            ))
        except json.JSONDecodeError as exc:
            logger.warning("CLI tool block invalid JSON: %s | %s", exc, block[:200])
        # Remove this block from the text so what's left is freeform
        remaining = remaining[:i] + remaining[j + len(_CLI_TOOL_SENTINEL_CLOSE):]
    return remaining.strip(), out_calls
