"""MCP Server and tools (Layer 5 interface).

Import create_mcp_server lazily to avoid requiring fastmcp at import time.
"""


def create_mcp_server():
    """Create and configure the NightEye MCP server (lazy import)."""
    from nighteye.mcp.server import create_mcp_server as _create

    return _create()


__all__ = ["create_mcp_server"]
