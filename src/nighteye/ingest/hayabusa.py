"""Hayabusa integration — runs Hayabusa on EVTX evidence and parses alerts.

Detects if Hayabusa is installed, executes it against an EVTX directory
or file, parses the resulting JSON alerts, and maps them to ECS.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterator

from nighteye.ingest.ecs import build_ecs_doc

__all__ = [
    "is_hayabusa_available",
    "run_hayabusa",
    "parse_hayabusa_alert",
]

logger = logging.getLogger("nighteye.ingest.hayabusa")


def is_hayabusa_available() -> bool:
    """Check if Hayabusa is installed and available in PATH."""
    return shutil.which("hayabusa") is not None or shutil.which("hayabusa.exe") is not None


def run_hayabusa(
    evidence_path: Path,
    host_name: str,
    case_id: str,
) -> Iterator[dict[str, Any]]:
    """Run Hayabusa and yield ECS-mapped alerts.

    Args:
        evidence_path: Path to the EVTX file or directory.
        host_name: Resolved host name for these events.
        case_id: The case ID.

    Yields:
        ECS alert documents ready for OpenSearch.
    """
    exe = shutil.which("hayabusa") or shutil.which("hayabusa.exe")
    if not exe:
        logger.warning("Hayabusa not found in PATH. Skipping Hayabusa alerts.")
        return

    with tempfile.TemporaryDirectory(prefix="nighteye_hayabusa_") as tmpdir:
        out_file = Path(tmpdir) / "alerts.jsonl"

        # hayabusa json-timeline -d <dir> -L -o <out.jsonl>
        # --no-wizard: skip the interactive scan-profile prompt (would
        #              otherwise panic with "not a terminal" under subprocess).
        # --clobber:   overwrite an existing output file rather than abort.
        # --ISO-8601:  consistent timestamp format.
        # -L:          emit JSONL (one record per line). Without this Hayabusa
        #              writes multi-line indented JSON objects concatenated
        #              together, which neither a JSONL nor an array parser
        #              can read.
        target_flag = "-f" if evidence_path.is_file() else "-d"
        cmd = [
            exe,
            "json-timeline",
            target_flag, str(evidence_path),
            "-L",
            "-o", str(out_file),
            "-q",
            "--no-wizard",
            "--clobber",
            "--ISO-8601",
        ]

        logger.info("Running Hayabusa on %s...", evidence_path.name)
        logger.debug("Command: %s", " ".join(cmd))

        # Hayabusa looks for its config files relative to cwd ("rules/config/...")
        # so it must run from the rule pack root. The bundled rule pack is
        # installed by setup.sh under /opt/hayabusa.
        haya_cwd = "/opt/hayabusa" if Path("/opt/hayabusa/rules").is_dir() else None

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1200,  # 20 min timeout for large directories
                cwd=haya_cwd,
            )
            # Hayabusa often exits non-zero if it found errors in some files,
            # but still generates the output for others.
            if result.returncode != 0 and not out_file.exists():
                logger.error("Hayabusa failed: %s", result.stderr)
                return
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.error("Hayabusa execution failed: %s", exc)
            return

        if not out_file.exists():
            logger.info("No Hayabusa alerts generated for %s.", evidence_path.name)
            return

        # Parse the JSON output. Hayabusa v3 json-timeline writes JSONL (one
        # record per line) by default — even when the file as a whole *looks*
        # like an array. Trying line-by-line first is the safe order; array
        # parse is only a fallback for older versions that still wrap output
        # in `[ ... ]`.
        source_file = str(evidence_path)
        alert_count = 0
        try:
            with open(out_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                return

            # JSONL path (Hayabusa 3.x default with --ISO-8601)
            jsonl_ok = False
            for line in content.splitlines():
                line = line.strip().rstrip(",")
                if not line or line in ("[", "]"):
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    jsonl_ok = False
                    break
                jsonl_ok = True
                doc = parse_hayabusa_alert(item, host_name, source_file, case_id)
                if doc:
                    alert_count += 1
                    yield doc

            # Fallback: whole-file JSON array (older Hayabusa)
            if not jsonl_ok and content.startswith("["):
                data = json.loads(content)
                for item in data:
                    doc = parse_hayabusa_alert(item, host_name, source_file, case_id)
                    if doc:
                        alert_count += 1
                        yield doc

            logger.info("Parsed %d Hayabusa alerts for %s", alert_count, host_name)

        except Exception as exc:
            preview = content[:200].replace("\n", "\\n") if "content" in locals() else ""
            logger.error("Failed to parse Hayabusa output: %s | head=%r",
                         exc, preview)


def parse_hayabusa_alert(
    alert: dict[str, Any],
    host_name: str,
    source_file: str,
    case_id: str,
) -> dict[str, Any] | None:
    """Map a raw Hayabusa JSON alert to an ECS document."""
    # Hayabusa 3.x uses PascalCase with no spaces (RuleTitle, EventID, Level).
    # Older versions used "Rule Title" / "Event ID" / "Rule Level".
    timestamp = alert.get("Timestamp") or alert.get("datetime") or alert.get("date")
    rule_title = (alert.get("RuleTitle") or alert.get("Rule Title")
                  or alert.get("rule_title") or alert.get("title", ""))
    rule_level = (alert.get("Level") or alert.get("Rule Level")
                  or alert.get("level", ""))
    event_id = (alert.get("EventID") or alert.get("Event ID")
                or alert.get("event_id") or "")
    computer = alert.get("Computer") or alert.get("computer", "")
    details = alert.get("Details") or alert.get("details", "")

    if not rule_title:
        return None

    if not host_name:
        host_name = computer

    # Extract user if available in details (heuristic)
    user_name = ""
    if isinstance(details, dict):
        user_name = details.get("UserName") or details.get("SubjectUserName", "")

    # OpenSearch dynamic mapping locks the alert.details field type to the
    # first doc indexed. Hayabusa emits dicts for some rules and bare strings
    # for others (e.g. "Logoff" → string) — second-type docs are rejected
    # with a mapper_parsing_exception. JSON-stringify so the mapping stays
    # consistent across rule types.
    if isinstance(details, (dict, list)):
        details_str = json.dumps(details, default=str)
    else:
        details_str = str(details) if details else ""

    # ECS Document
    doc = build_ecs_doc(
        timestamp=str(timestamp) if timestamp else None,
        host_name=host_name,
        event_code=str(event_id) if event_id else "",
        event_action="sigma-alert",
        event_category="intrusion_detection",
        user_name=user_name,
        nighteye_source_file=source_file,
        nighteye_audit_id=f"hayabusa-{case_id}",
        nighteye_parser="hayabusa",
        nighteye_canonical_type="ALERT",
        extra={
            "rule.name": rule_title,
            "rule.level": rule_level,
            "alert.details": details_str,
        },
    )
    
    # Mark as an alert in ECS
    doc["event"]["kind"] = "alert"
    
    return doc
