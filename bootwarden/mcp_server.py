"""BOOTWARDEN MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from bootwarden.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "bootwarden[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'bootwarden[mcp]'")
        return 1
    app = FastMCP("bootwarden")

    @app.tool()
    def bootwarden_scan(target: str) -> str:
        """Audit UEFI firmware dumps for missing Secure Boot keys, unsigned modules, S3 boot-script vulns, and known SMM threats.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
