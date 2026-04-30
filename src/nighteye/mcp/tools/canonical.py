"""Canonical Event MCP Tools."""

from nighteye.mcp.server import mcp

@mcp.tool()
def expand_canonical(event_id: str) -> dict:
    """Expand a CanonicalEvent to its raw OpenSearch ECS document.
    
    Use this when you need deep, raw telemetry (e.g., full Sysmon XML,
    raw raw Event Data, full memory strings) that isn't captured in the
    standardized CanonicalEvent schema.
    
    Args:
        event_id: The ID of the CanonicalEvent.
    """
    return {
        "event_id": event_id,
        "error": "OpenSearch lookup stubbed for v2",
    }
