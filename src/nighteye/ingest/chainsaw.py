"""Chainsaw integration — runs Chainsaw on EVTX evidence and parses alerts.

Detects if Chainsaw is installed, executes it against an EVTX directory
or file using Sigma rules, parses the JSON alerts, and maps them to ECS.
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
    "is_chainsaw_available",
    "run_chainsaw",
    "parse_chainsaw_alert",
]

logger = logging.getLogger("nighteye.ingest.chainsaw")


def is_chainsaw_available() -> bool:
    """Check if Chainsaw is installed and available in PATH."""
    return shutil.which("chainsaw") is not None or shutil.which("chainsaw.exe") is not None


def run_chainsaw(
    evidence_path: Path,
    host_name: str,
    case_id: str,
    rules_path: str | None = None,
    mapping_path: str | None = None,
) -> Iterator[dict[str, Any]]:
    """Run Chainsaw and yield ECS-mapped alerts.

    Args:
        evidence_path: Path to the EVTX file or directory.
        host_name: Resolved host name for these events.
        case_id: The case ID.
        rules_path: Sigma rules directory. Defaults to /opt/chainsaw/sigma
            (where setup.sh installs SigmaHQ rules).
        mapping_path: Chainsaw mapping YAML. Defaults to the
            sigma-event-logs-all.yml shipped alongside chainsaw.

    Yields:
        ECS alert documents ready for OpenSearch.
    """
    exe = shutil.which("chainsaw") or shutil.which("chainsaw.exe")
    if not exe:
        logger.warning("Chainsaw not found in PATH. Skipping Chainsaw alerts.")
        return

    # Resolve the bundled rule + mapping paths installed by setup.sh
    if rules_path is None:
        rules_path = "/opt/chainsaw/sigma" if Path("/opt/chainsaw/sigma").is_dir() else "sigma/"
    if mapping_path is None:
        candidates = [
            "/opt/chainsaw/mappings/sigma-event-logs-all.yml",
            "/opt/chainsaw/mappings/sigma-event-logs-legacy.yml",
        ]
        mapping_path = next((p for p in candidates if Path(p).is_file()), "mapping.yaml")

    with tempfile.TemporaryDirectory(prefix="nighteye_chainsaw_") as tmpdir:
        out_file = Path(tmpdir) / "alerts.json"

        # chainsaw hunt <dir> -s <rules> --mapping <mapping> --json -o <out.json>
        cmd = [
            exe,
            "hunt",
            str(evidence_path),
            "-s", rules_path,
            "--mapping", mapping_path,
            "--json",
            "-o", str(out_file),
        ]

        logger.info("Running Chainsaw on %s...", evidence_path.name)
        logger.debug("Command: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1200,  # 20 min timeout
            )
            if result.returncode != 0 and not out_file.exists():
                logger.error("Chainsaw failed: %s", result.stderr)
                return
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.error("Chainsaw execution failed: %s", exc)
            return

        if not out_file.exists():
            logger.info("No Chainsaw alerts generated for %s.", evidence_path.name)
            return

        # Parse the JSON array output
        source_file = str(evidence_path)
        alert_count = 0
        try:
            with open(out_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return

                data = json.loads(content)
                for item in data:
                    doc = parse_chainsaw_alert(item, host_name, source_file, case_id)
                    if doc:
                        alert_count += 1
                        yield doc

            logger.info("Parsed %d Chainsaw alerts for %s", alert_count, host_name)

        except Exception as exc:
            logger.error("Failed to parse Chainsaw output: %s", exc)


def parse_chainsaw_alert(
    alert: dict[str, Any],
    host_name: str,
    source_file: str,
    case_id: str,
) -> dict[str, Any] | None:
    """Map a raw Chainsaw JSON alert to an ECS document."""
    
    timestamp = alert.get("timestamp")
    document = alert.get("document", {})
    event_data = document.get("Event", {}).get("EventData", {})
    system = document.get("Event", {}).get("System", {})
    
    rule_title = alert.get("name", "")
    rule_level = alert.get("level", "")
    rule_author = alert.get("author", "")
    
    event_id = system.get("EventID", "")
    computer = system.get("Computer", "")
    
    if not rule_title:
        return None

    if not host_name:
        host_name = computer

    user_name = event_data.get("TargetUserName") or event_data.get("SubjectUserName", "")
    
    # ECS Document
    doc = build_ecs_doc(
        timestamp=str(timestamp) if timestamp else None,
        host_name=host_name,
        event_code=str(event_id) if event_id else "",
        event_action="sigma-alert",
        event_category="intrusion_detection",
        user_name=str(user_name) if user_name else "",
        nighteye_source_file=source_file,
        nighteye_audit_id=f"chainsaw-{case_id}",
        nighteye_parser="chainsaw",
        nighteye_canonical_type="ALERT",
        extra={
            "rule.name": rule_title,
            "rule.level": rule_level,
            "rule.author": rule_author,
            "alert.document": document,
        },
    )
    
    # Mark as an alert in ECS
    doc["event"]["kind"] = "alert"
    
    return doc
