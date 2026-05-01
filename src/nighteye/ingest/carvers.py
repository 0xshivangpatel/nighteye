"""Carvers module — executes bstrings and 1768.py for artifact recovery.

Detects if Eric Zimmerman's bstrings and Didier Stevens' 1768.py are available.
Executes them against memory dumps or suspicious files to extract IPs, URLs,
and Cobalt Strike beacon configurations.
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
    "run_bstrings",
    "run_1768",
]

logger = logging.getLogger("nighteye.ingest.carvers")


def run_bstrings(
    evidence_path: Path,
    host_name: str,
    case_id: str,
) -> Iterator[dict[str, Any]]:
    """Run bstrings to carve IPs and URLs.
    
    Yields ECS documents.
    """
    exe = shutil.which("bstrings") or shutil.which("bstrings.exe")
    if not exe:
        logger.warning("bstrings not found. Skipping string carving.")
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        out_csv = Path(tmpdir) / "strings.csv"
        # We search for IPv4 and URLs
        cmd = [
            exe,
            "-f", str(evidence_path),
            "--ipv4", "--url",
            "--csv", tmpdir,
        ]

        logger.info("Running bstrings on %s...", evidence_path.name)
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            # Find the output CSV (bstrings prefixes with timestamp)
            out_files = list(Path(tmpdir).glob("*.csv"))
            if not out_files:
                return
                
            import csv
            with open(out_files[0], "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    match_value = row.get("Hit", "")
                    match_type = row.get("Type", "")
                    offset = row.get("Offset", "")
                    
                    if not match_value:
                        continue
                        
                    yield build_ecs_doc(
                        host_name=host_name,
                        event_code="bstrings_match",
                        event_action="string-carving",
                        event_category="artifact",
                        nighteye_source_file=str(evidence_path),
                        nighteye_audit_id=f"bstrings-{case_id}",
                        nighteye_parser="bstrings",
                        nighteye_canonical_type="MEMORY_ARTIFACT",
                        extra={
                            "artifact.type": "extracted_string",
                            "artifact.pattern_type": match_type,
                            "artifact.value": match_value,
                            "artifact.offset": offset,
                        }
                    )
        except Exception as exc:
            logger.error("bstrings failed: %s", exc)


def run_1768(
    evidence_path: Path,
    host_name: str,
    case_id: str,
) -> Iterator[dict[str, Any]]:
    """Run 1768.py to parse Cobalt Strike beacons.
    
    Yields ECS documents for any recovered configuration.
    """
    exe = shutil.which("1768.py") or shutil.which("1768")
    if not exe:
        # Check if Python is running a local 1768.py script
        if Path("/opt/1768/1768.py").exists():
            exe = "python3 /opt/1768/1768.py"
        else:
            logger.warning("1768.py not found. Skipping CS beacon parsing.")
            return

    cmd = f"{exe} -j {evidence_path}"
    
    logger.info("Running 1768.py on %s...", evidence_path.name)
    try:
        # We need shell=True if exe is a command string with spaces
        result = subprocess.run(cmd.split() if not " " in exe else cmd, shell=True if " " in exe else False, capture_output=True, text=True, timeout=120)
        
        if not result.stdout.strip():
            return
            
        try:
            data = json.loads(result.stdout)
            
            # 1768.py returns a list of beacon configs
            if not isinstance(data, list):
                data = [data]
                
            for beacon in data:
                # Extract C2 info
                c2_domains = beacon.get("domains", [])
                c2_ports = beacon.get("port", [])
                watermark = beacon.get("watermark")
                
                yield build_ecs_doc(
                    host_name=host_name,
                    event_code="cobalt_strike_beacon",
                    event_action="beacon-parsing",
                    event_category="malware",
                    nighteye_source_file=str(evidence_path),
                    nighteye_audit_id=f"1768-{case_id}",
                    nighteye_parser="1768.py",
                    nighteye_canonical_type="MEMORY_ARTIFACT",
                    extra={
                        "artifact.type": "cobalt_strike_config",
                        "malware.family": "cobalt_strike",
                        "malware.watermark": str(watermark),
                        "network.c2_domains": c2_domains,
                        "network.c2_ports": c2_ports,
                        "beacon.raw_config": json.dumps(beacon),
                    }
                )
                
        except json.JSONDecodeError:
            logger.debug("No valid JSON from 1768.py, probably no beacon found.")
            
    except Exception as exc:
        logger.error("1768.py failed: %s", exc)
