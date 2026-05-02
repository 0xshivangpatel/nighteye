"""Demo Script for NightEye Portal.

Creates a sample case with data and starts the portal.
"""

import os
import sqlite3
import json
from pathlib import Path
from unittest.mock import MagicMock
from nighteye.case import init_case, set_active_case
from nighteye.canonical.engine import run_normalization_pass
from nighteye.graph.graph import build_graph_from_canonical
from nighteye.constructors.base import run_all_constructors
from nighteye.mcp.tools.hypothesis_tools import record_hypothesis
from nighteye.portal.app import create_portal_app
import uvicorn

def setup_demo_data():
    print("[Demo] Setting up demo case...")
    case_id = "demo-case-001"
    
    # Mock OpenSearch Client
    mock_os_client = MagicMock()
    mock_os_client.list_indices.side_effect = lambda pattern: (
        ["case-demo-case-001-raw"] if "raw" in pattern else ["case-demo-case-001-canonical-WKSTN-01"] if "canonical" in pattern else []
    )
    
    def mock_scroll(index, **kwargs):
        if "canonical" in index:
            return [[
                {
                    "_source": {
                        "event_id": "can-1", "case_id": case_id, "host_name": "WKSTN-01",
                        "@timestamp": "2026-05-01T10:00:00Z", "canonical_type": "AUTHENTICATION",
                        "user": "attacker", "raw_data": {"winlog": {"event_data": {"LogonType": "10"}}}
                    }
                },
                {
                    "_source": {
                        "event_id": "can-2", "case_id": case_id, "host_name": "WKSTN-01",
                        "@timestamp": "2026-05-01T10:05:00Z", "canonical_type": "REGISTRY_MODIFICATION",
                        "registry_key": "HKCU\\Software\\...\\Run\\Malware", "target_file": "C:\\temp\\payload.exe"
                    }
                }
            ]]
        return [[
            {"_source": {"@timestamp": "2026-05-01T10:00:00Z", "host": {"name": "WKSTN-01"}}}
        ]]
    mock_os_client.scroll_search_iter.side_effect = mock_scroll

    # 1. Init Case
    try:
        case = init_case(name="Demo Investigation", examiner="Demo-User", case_id=case_id)
    except:
        # If already exists, just load it
        from nighteye.case import default_cases_dir, set_active_case, get_active_case
        case_dir = default_cases_dir() / case_id
        set_active_case(case_dir)
        case = get_active_case()

    # 2. Pipeline
    print("[Demo] Running pipeline...")
    run_normalization_pass(mock_os_client, case.case_id)
    build_graph_from_canonical(mock_os_client, case.case_id, case.graph_db)
    run_all_constructors(mock_os_client, case.case_id, case.graph_db)

    # 3. Hypotheses
    print("[Demo] Recording hypotheses...")
    with sqlite3.connect(case.graph_db) as conn:
        conn.row_factory = sqlite3.Row
        clusters = conn.execute("SELECT * FROM clusters").fetchall()
        for cluster in clusters:
            record_hypothesis(
                title=f"Potential {cluster['cluster_type']} Detected",
                observation=f"Multiple signals triggered on {cluster['primary_host']}",
                interpretation="Behavioral indicators suggest malicious activity.",
                technique_ids=["T1021.001"] if "Lateral" in cluster["cluster_type"] else ["T1547.001"],
                evidence_refs=[{
                    "cluster_id": cluster["cluster_id"],
                    "audit_id": "nighteye-demo-audit-001",
                    "description": "Cluster detected by behavioral engine"
                }],
                case_id=case_id,
                examiner="Demo-User"
            )

    print(f"[Demo] Setup complete. Case: {case.id}")
    return case

if __name__ == "__main__":
    case = setup_demo_data()
    print("[Demo] Starting portal on http://localhost:4511")
    app = create_portal_app()
    uvicorn.run(app, host="127.0.0.1", port=4511)
