"""Case Management MCP Tools."""

from nighteye.mcp.server import mcp
from nighteye.case import get_case_dir

@mcp.tool()
def case_status() -> dict:
    """Get the status of the current active case.
    
    Returns basic information about the case ID, storage locations,
    and timestamps.
    """
    case_dir = get_case_dir()
    if not case_dir:
        return {"error": "No active case"}
    
    return {
        "case_id": case_dir.name,
        "path": str(case_dir),
    }

@mcp.tool()
def evidence_register() -> dict:
    """List all registered evidence data sources for the current case.
    
    Returns an overview of the raw evidence that was ingested.
    """
    # In a full implementation, this would query OpenSearch or SQLite
    return {
        "status": "Available in full release. Case indices contain raw data."
    }
