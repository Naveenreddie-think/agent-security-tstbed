"""
MCP Server exposing tools for the agent:
  1. read_file   - reads a file from a SANDBOXED directory only (path traversal blocked)
  2. web_search   - stubbed search tool (swap in a real API like Tavily/Serper for production)

This is intentionally kept simple in Step 1. Step 3 will attack this server
(e.g. tool-response poisoning, path traversal) and Step 4 will harden it.
"""
import os
import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

SANDBOX_DIR = Path(__file__).parent.parent / "sandbox_files"
SANDBOX_DIR.mkdir(exist_ok=True)

mcp = FastMCP("agent-security-testbed")


@mcp.tool()
def read_file(filename: str) -> str:
    """
    Read a text file from the sandboxed documents directory.

    Args:
        filename: name of the file to read (no path traversal allowed)
    """
    # --- deliberately naive in Step 1: no defenses yet ---
    # Step 4 will replace this with a hardened version that:
    #   - resolves the real path and checks it's still inside SANDBOX_DIR
    #   - refuses filenames containing '..', absolute paths, symlinks
    target = SANDBOX_DIR / filename
    try:
        if not target.exists():
            return f"ERROR: file '{filename}' not found in sandbox."
        content = target.read_text(errors="ignore")
        return content
    except Exception as e:
        return f"ERROR reading file: {e}"


@mcp.tool()
def web_search(query: str) -> str:
    """
    Search the web for a query and return summarized results.

    Args:
        query: the search query string
    """
    # --- STUBBED for local dev ---
    # In production, replace this with a real call to Tavily/Serper/Bing API.
    # We stub it here so Step 1 works with zero external API keys and zero cost.
    #
    # IMPORTANT (for Step 3 attacks later): this is exactly where an attacker
    # could poison results if this were a real, unvalidated web search --
    # the agent trusts whatever text comes back from this tool.
    fake_results = {
        "results": [
            {
                "title": f"Result about: {query}",
                "snippet": f"This is a stubbed search result for the query '{query}'. "
                           f"Replace web_search() with a real API call for production use.",
            }
        ]
    }
    return json.dumps(fake_results)


if __name__ == "__main__":
    mcp.run(transport="stdio")
