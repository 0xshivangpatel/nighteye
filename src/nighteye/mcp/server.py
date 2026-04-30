"""NightEye MCP Server implementation.

Provides the FastMCP server that exposes NightEye forensic capabilities
to AI Agents (e.g. Claude).

References:
    - docs/BUILD_PLAN.md § D13
"""

from __future__ import annotations

import logging
from mcp.server.fastmcp import FastMCP

from nighteye.case import get_case_dir

logger = logging.getLogger("nighteye.mcp.server")

# Instantiate the FastMCP server
mcp = FastMCP("NightEye")


def start_server(port: int = 4509, transport: str = "sse") -> None:
    """Start the NightEye MCP server."""
    case_dir = get_case_dir()
    if not case_dir:
        logger.error("No active case found. Run `nighteye case activate <id>` first.")
        raise RuntimeError("No active case")
        
    logger.info("Starting NightEye MCP Server on port %d for case %s (transport: %s)", port, case_dir.name, transport)
    mcp.settings.port = port
    
    # Import tools to register them
    import nighteye.mcp.tools.case
    import nighteye.mcp.tools.triage
    import nighteye.mcp.tools.cluster
    import nighteye.mcp.tools.canonical
    import nighteye.mcp.tools.hypothesis
    import nighteye.mcp.tools.journal
    
    # Run the server
    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport="sse")
