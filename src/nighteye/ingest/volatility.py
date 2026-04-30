"""Volatility 3 integration — runs memory forensics plugins and parses output.

Detects if Volatility 3 (`vol` or `vol.py`) is installed, executes critical
plugins against memory dumps, and maps the JSON output into ECS documents.
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
    "is_volatility_available",
    "run_volatility",
    "parse_volatility_record",
]

logger = logging.getLogger("nighteye.ingest.volatility")

# Core plugins to run automatically on Windows memory dumps
_DEFAULT_PLUGINS = [
    "windows.pslist.PsList",
    "windows.cmdline.CmdLine",
    "windows.netscan.NetScan",
    "windows.malfind.Malfind",
]


def is_volatility_available() -> bool:
    """Check if Volatility 3 is available in PATH."""
    return shutil.which("vol") is not None or shutil.which("vol.py") is not None or shutil.which("vol.exe") is not None


def _get_vol_exe() -> str | None:
    return shutil.which("vol") or shutil.which("vol.py") or shutil.which("vol.exe")


def run_volatility(
    evidence_path: Path,
    host_name: str,
    case_id: str,
    plugins: list[str] | None = None,
) -> Iterator[dict[str, Any]]:
    """Run Volatility 3 plugins and yield ECS-mapped documents.

    Args:
        evidence_path: Path to the memory dump.
        host_name: Resolved host name.
        case_id: Case ID.
        plugins: List of Volatility 3 plugins to run (default: core windows).

    Yields:
        ECS documents.
    """
    exe = _get_vol_exe()
    if not exe:
        logger.warning("Volatility 3 not found in PATH. Skipping memory analysis.")
        return

    plugins_to_run = plugins or _DEFAULT_PLUGINS

    for plugin in plugins_to_run:
        yield from _run_volatility_plugin(
            exe, evidence_path, plugin, host_name, case_id
        )


def _run_volatility_plugin(
    exe: str,
    evidence_path: Path,
    plugin: str,
    host_name: str,
    case_id: str,
) -> Iterator[dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix=f"nighteye_vol_{plugin}_") as tmpdir:
        # Volatility 3 command to output JSON
        # Format: vol -f <file> -r json -o <outdir> <plugin>
        cmd = [
            exe,
            "-f", str(evidence_path),
            "-r", "json",
            "-o", tmpdir,
            plugin,
        ]

        logger.info("Running Volatility 3 plugin %s on %s...", plugin, evidence_path.name)
        logger.debug("Command: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,  # Memory analysis can take a long time (60 mins)
            )
            if result.returncode != 0:
                logger.error("Volatility plugin %s failed: %s", plugin, result.stderr[:500])
                # Note: some plugins fail gracefully, so we still check for output
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.error("Volatility execution failed for %s: %s", plugin, exc)
            return

        # Find the generated JSON file (volatility names it based on the plugin and timestamp)
        out_files = list(Path(tmpdir).glob("*.json"))
        if not out_files:
            logger.warning("No Volatility JSON output found for %s", plugin)
            return

        for out_file in out_files:
            try:
                with open(out_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    
                source_file = str(evidence_path)
                
                # Volatility JSON output is a list of rows, or a dict wrapping rows depending on version
                rows = data if isinstance(data, list) else data.get("rows", [])
                
                for row in rows:
                    doc = parse_volatility_record(row, plugin, host_name, source_file, case_id)
                    if doc:
                        yield doc
                        
            except Exception as exc:
                logger.error("Failed to parse Volatility output from %s: %s", out_file.name, exc)


def parse_volatility_record(
    record: dict[str, Any],
    plugin: str,
    host_name: str,
    source_file: str,
    case_id: str,
) -> dict[str, Any] | None:
    """Map a Volatility 3 JSON row to an ECS document based on the plugin."""
    
    # Volatility output format varies heavily by plugin. We do our best to map
    # the common fields. Some versions return a list of values, others return a dict.
    # Assuming dict-based JSON output where keys are the column names.
    
    if isinstance(record, list):
        # We need headers to parse lists effectively. If Volatility returns lists without
        # headers in this JSON format, we skip it. Modern `vol -r json` outputs dicts.
        return None

    # Normalize keys to lowercase for easier matching
    rec = {k.lower(): v for k, v in record.items()}

    # Base ECS properties
    timestamp = None
    process_name = ""
    pid = None
    ppid = None
    command_line = ""
    event_action = f"volatility-{plugin.split('.')[-1].lower()}"
    event_category = "process"
    
    extra: dict[str, Any] = {"volatility.plugin": plugin}

    # Extract common Process fields
    if "imagefilename" in rec:
        process_name = str(rec["imagefilename"])
    elif "process" in rec:
        process_name = str(rec["process"])
        
    if "pid" in rec:
        try:
            pid = int(rec["pid"])
        except (ValueError, TypeError):
            pass
            
    if "ppid" in rec:
        try:
            ppid = int(rec["ppid"])
        except (ValueError, TypeError):
            pass
            
    # Extract Plugin-specific fields
    if "pslist" in plugin.lower():
        # PsList specific
        timestamp = rec.get("create time") or rec.get("createtime")
        if "exit time" in rec and rec["exit time"]:
            extra["volatility.exit_time"] = rec["exit time"]
            
    elif "cmdline" in plugin.lower():
        # CmdLine specific
        command_line = str(rec.get("args") or rec.get("cmdline", ""))
        
    elif "netscan" in plugin.lower():
        # NetScan specific
        event_category = "network"
        timestamp = rec.get("created")
        extra["volatility.local_addr"] = rec.get("localaddr")
        extra["volatility.local_port"] = rec.get("localport")
        extra["volatility.foreign_addr"] = rec.get("foreignaddr")
        extra["volatility.foreign_port"] = rec.get("foreignport")
        extra["volatility.state"] = rec.get("state")
        extra["volatility.protocol"] = rec.get("proto")
        
    elif "malfind" in plugin.lower():
        # Malfind specific
        event_category = "malware"
        extra["volatility.start_vpn"] = rec.get("start vpn")
        extra["volatility.end_vpn"] = rec.get("end vpn")
        extra["volatility.protection"] = rec.get("protection")
        extra["volatility.commitcharge"] = rec.get("commitcharge")
        # Hexdump / Assembly could be massive, truncate if present
        if "hexdump" in rec:
            extra["volatility.hexdump"] = str(rec["hexdump"])[:500]
            
    # Merge all unmapped Volatility fields into `extra`
    for k, v in record.items():
        if k.lower() not in ("imagefilename", "process", "pid", "ppid", "create time", "createtime"):
            extra[f"volatility.{k.lower()}"] = v

    if not process_name and not pid and "netscan" not in plugin.lower():
        return None

    return build_ecs_doc(
        timestamp=str(timestamp) if timestamp else None,
        host_name=host_name,
        event_code=plugin,
        event_action=event_action,
        event_category=event_category,
        process_name=process_name,
        process_pid=pid,
        process_parent_pid=ppid,
        process_command_line=command_line,
        nighteye_source_file=source_file,
        nighteye_audit_id=f"volatility-{case_id}",
        nighteye_parser="volatility3",
        nighteye_canonical_type="MEMORY_ARTIFACT",
        extra=extra,
    )
