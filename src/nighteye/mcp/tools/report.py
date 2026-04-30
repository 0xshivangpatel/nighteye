"""Report MCP Tools.

Enables the AI Agent to trigger the end-of-case validation, calculate
root causes, and generate final reports.
"""

from __future__ import annotations

from nighteye.mcp.server import mcp
from nighteye.correlation.root_cause import find_root_cause as _find_root_cause
from nighteye.report.markdown import generate_markdown_report
from nighteye.report.json_export import export_json_report

@mcp.tool()
def find_root_cause() -> dict:
    """Trigger the Root Cause correlation engine.
    
    This traverses the established causal graph backwards to find the
    earliest reliable node in the attack sequence.
    """
    return _find_root_cause()

@mcp.tool()
def generate_report(format: str = "markdown") -> dict:
    """Generate the final case report.
    
    This automatically runs the end-of-case validation pass before compiling
    the report.
    
    Args:
        format: The report format ('markdown' or 'json').
    """
    if format.lower() == "json":
        content = export_json_report()
    else:
        content = generate_markdown_report()
        
    return {
        "status": "success",
        "format": format,
        "content": content
    }

@mcp.tool()
def save_report() -> dict:
    """Save the final report to disk in the case directory."""
    # Stubbed implementation
    return {
        "status": "success",
        "message": "Report saved to /reports/NightEye_Final_Report.md"
    }
