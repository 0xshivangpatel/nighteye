"""Triage MCP Tools."""

from nighteye.mcp.server import mcp

@mcp.tool()
def triage_clusters() -> list[dict]:
    """Get the highest confidence behavioral clusters across the entire case.
    
    This is the primary entrypoint for investigations. It returns a summarized
    list of all STRONG and MODERATE confidence threat clusters detected by the
    NightEye constructor engine.
    
    Returns:
        List of cluster summaries including cluster_id, tier, score, and description.
    """
    # In a full implementation, this queries SQLite `clusters` table
    # where tier IN ('STRONG', 'MODERATE')
    return [
        {
            "cluster_id": "cluster-stub-001",
            "tier": "MODERATE",
            "score": 65,
            "summary": "Lateral movement pattern detected on DC01. Network logon (Type 3) by stark\\admin from 10.0.0.5."
        }
    ]

@mcp.tool()
def profile_host(host_name: str) -> dict:
    """Get a forensic profile of a specific host.
    
    Returns context about the host's OS, role (e.g. Domain Controller),
    and a summary of threat clusters associated with it.
    
    Args:
        host_name: The name of the host (e.g., 'DC01').
    """
    return {
        "host_name": host_name,
        "profile": "Domain Controller (stub)",
        "cluster_count": 1,
    }
