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
        out_file = Path(tmpdir) / "alerts.json"

        # hayabusa json-timeline -d <dir> -o <out.json>
        # or for file: -f <file>
        # --no-wizard: skip the interactive scan-profile prompt; without
        #              this, hayabusa panics with "not a terminal" when
        #              stdin is captured by subprocess.
        # --clobber:   overwrite an existing output file rather than abort.
        # --ISO-8601:  consistent timestamp format for our parser.
        target_flag = "-f" if evidence_path.is_file() else "-d"
        cmd = [
            exe,
            "json-timeline",
            target_flag, str(evidence_path),
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

        # Parse the JSON output
        source_file = str(evidence_path)
        alert_count = 0
        try:
            with open(out_file, "r", encoding="utf-8") as f:
                # Hayabusa JSON output can be an array or JSONL depending on version.
                # We'll try JSONL first, then fallback to parsing as full array.
                content = f.read().strip()
                if not content:
                    return

                if content.startswith("["):
                    # JSON array
                    data = json.loads(content)
                    for item in data:
                        doc = parse_hayabusa_alert(item, host_name, source_file, case_id)
                        if doc:
                            alert_count += 1
                            yield doc
                else:
                    # JSON Lines
                    for line in content.splitlines():
                        if line.strip():
                            item = json.loads(line)
                            doc = parse_hayabusa_alert(item, host_name, source_file, case_id)
                            if doc:
                                alert_count += 1
                                yield doc

            logger.info("Parsed %d Hayabusa alerts for %s", alert_count, host_name)

        except Exception as exc:
            logger.error("Failed to parse Hayabusa output: %s", exc)


def parse_hayabusa_alert(
    alert: dict[str, Any],
    host_name: str,
    source_file: str,
    case_id: str,
) -> dict[str, Any] | None:
    """Map a raw Hayabusa JSON alert to an ECS document."""
    # Handle both v2 and v3 JSON structures
    timestamp = alert.get("Timestamp") or alert.get("datetime") or alert.get("date")
    rule_title = alert.get("Rule Title") or alert.get("rule_title") or alert.get("title", "")
    rule_level = alert.get("Rule Level") or alert.get("level", "")
    event_id = alert.get("Event ID") or alert.get("event_id") or ""
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
            "alert.details": details,
        },
    )
    
    # Mark as an alert in ECS
    doc["event"]["kind"] = "alert"
    
    return doc
