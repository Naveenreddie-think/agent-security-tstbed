"""
MCP Server exposing tools for the agent:
  1. read_file    - reads a file from a SANDBOXED directory only (path traversal NOT yet blocked)
  2. write_file   - writes a file to the SANDBOXED directory (path traversal NOT yet blocked)
  3. web_search    - stubbed search tool (swap in a real API like Tavily/Serper for production)

This is intentionally kept simple/naive through Step 2. Step 3 will attack this server
(e.g. path traversal on read/write, tool-response poisoning, prompt injection tricking
the agent into calling write_file with attacker-chosen content/paths) and Step 4 will
harden it based on what those attacks reveal.
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
    # --- deliberately naive through Step 2: no defenses yet ---
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
def write_file(filename: str, content: str) -> str:
    """
    Write text content to a file in the sandboxed documents directory.
    Creates the file if it doesn't exist, overwrites if it does.

    Args:
        filename: name of the file to write (no path traversal allowed)
        content: the text content to write
    """
    # --- deliberately naive through Step 2: this is the highest-value attack
    # surface in the whole project. An agent tricked (via prompt injection)
    # into calling write_file with an attacker-chosen filename/content could:
    #   - escape the sandbox via path traversal (e.g. filename="../../evil.txt")
    #   - overwrite an existing file the user didn't intend to touch
    #   - plant content that gets read and acted on again later (persistence)
    # Step 4 will harden this with path resolution checks, an allowlist of
    # writeable filenames, and a confirmation step for destructive writes.
    target = SANDBOX_DIR / filename
    try:
        target.write_text(content)
        return f"OK: wrote {len(content)} characters to '{filename}'."
    except Exception as e:
        return f"ERROR writing file: {e}"


@mcp.tool()
def web_search(query: str) -> str:
    """
    Search the web for a query and return summarized results.

    Args:
        query: the search query string
    """
    # --- STUBBED for local dev ---
    # In production, replace this with a real call to Tavily/Serper/Bing API.
    # We stub it here so Step 1/2 work with zero external API keys and zero cost.
    #
    # IMPORTANT (for Step 3 attacks later): this is exactly where an attacker
    # could poison results if this were a real, unvalidated web search --
    # the agent trusts whatever text comes back from this tool. We simulate
    # that by letting certain queries return content containing embedded
    # instructions (see sandbox_files/ and the attack suite in Step 3).
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