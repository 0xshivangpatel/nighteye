"""Cluster MCP Tools."""

from nighteye.mcp.server import mcp

@mcp.tool()
def query_clusters(min_strength: str = "WEAK", limit: int = 50) -> list[dict]:
    """Query behavioral clusters with specific filters.
    
    Use this to dig into lower-confidence (WEAK) clusters when investigating
    a specific host or hunting for stealthy behavior that didn't cross the
    auto-triage threshold.
    
    Args:
        min_strength: The minimum tier to return (STRONG, MODERATE, WEAK, NOISE).
        limit: Maximum number of clusters to return.
    """
    return []

@mcp.tool()
def expand_cluster(cluster_id: str) -> dict:
    """Get the full details of a behavioral cluster.
    
    Returns the complete chain of CanonicalEvents that make up the cluster,
    along with all evaluated supporting signals and pre-computed counter-evidence.
    This is essential for challenging or validating a hypothesis.
    
    Args:
        cluster_id: The ID of the cluster to expand.
    """
    return {
        "cluster_id": cluster_id,
        "error": "Database lookup stubbed for v2",
    }
