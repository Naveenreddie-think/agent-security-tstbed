"""
MCP Server exposing tools for the agent:
  1. read_file    - reads a file from a SANDBOXED directory only (path traversal BLOCKED, Step 4)
  2. write_file   - writes a file to the SANDBOXED directory (path traversal BLOCKED, Step 4)
  3. web_search    - stubbed search tool (swap in a real API like Tavily/Serper for production)

Step 4 hardening: both tools now resolve the requested path and verify it
stays inside SANDBOX_DIR before touching the filesystem. This blocks path
traversal (../, absolute paths, symlink tricks) at the CODE level -- it does
not depend on the calling model's judgment, unlike the Step 1-3 versions.
See app/test_mcp_attacks.py for the direct, no-LLM test that proves this.
"""
import os
import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

SANDBOX_DIR = (Path(__file__).parent.parent / "sandbox_files").resolve()
SANDBOX_DIR.mkdir(exist_ok=True)

mcp = FastMCP("agent-security-testbed")


class PathEscapeError(Exception):
    """Raised when a requested filename would resolve outside SANDBOX_DIR."""
    pass


def resolve_safe_path(filename: str) -> Path:
    """
    Resolve `filename` relative to SANDBOX_DIR and verify the result is
    actually still inside SANDBOX_DIR. This is the real fix, as opposed to
    string-checking for '..' (which is easy to bypass with absolute paths,
    symlinks, or OS-specific separators -- see FINDINGS.md for the Step 3
    proof that the naive version was vulnerable).

    Uses Path.resolve() (follows symlinks, collapses '..') + is_relative_to()
    for a containment check that can't be fooled by traversal tricks.
    """
    if not filename or not filename.strip():
        raise PathEscapeError("empty filename not allowed")

    candidate = (SANDBOX_DIR / filename).resolve()

    if not candidate.is_relative_to(SANDBOX_DIR):
        raise PathEscapeError(
            f"'{filename}' resolves outside the sandbox directory -- rejected"
        )

    return candidate


@mcp.tool()
def read_file(filename: str) -> str:
    """
    Read a text file from the sandboxed documents directory.

    Args:
        filename: name of the file to read (must resolve inside the sandbox)
    """
    try:
        target = resolve_safe_path(filename)
    except PathEscapeError as e:
        return f"ERROR: blocked -- {e}"

    try:
        if not target.exists():
            return f"ERROR: file '{filename}' not found in sandbox."
        if not target.is_file():
            return f"ERROR: '{filename}' is not a regular file."
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
        filename: name of the file to write (must resolve inside the sandbox)
        content: the text content to write
    """
    try:
        target = resolve_safe_path(filename)
    except PathEscapeError as e:
        return f"ERROR: blocked -- {e}"

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
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