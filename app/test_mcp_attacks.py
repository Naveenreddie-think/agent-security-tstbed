"""
Step 3b - Direct MCP-layer attack tests.

IMPORTANT: these tests call the MCP tools DIRECTLY, with NO LLM in the loop.
This is deliberate. The Step 3 run_attacks.py results showed the agent
refusing every attack -- but that only tells us Claude's own judgment
caught them. It tells us NOTHING about whether the underlying tool code
(read_file/write_file in mcp_server/server.py) is actually safe.

This script answers that separate question directly: if a malicious
filename/path reaches read_file or write_file (however it got there --
a jailbroken model, a different/weaker model, a bug that skips the LLM's
judgment, a future refactor, etc.), does the CODE stop it, or not?

Run:  python -m app.test_mcp_attacks
"""
import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER_SCRIPT = str(Path(__file__).parent.parent / "mcp_server" / "server.py")
SANDBOX_DIR = Path(__file__).parent.parent / "sandbox_files"


# Platform-appropriate traversal targets. We try several because different
# OSes/filesystems behave differently -- we want to know what ACTUALLY
# escapes on whatever machine this runs on, not assume based on convention.
TRAVERSAL_READ_TARGETS = [
    "../../../../etc/passwd",            # classic *nix target (may not exist on this OS)
    "..\\..\\..\\..\\Windows\\win.ini",   # classic Windows target (depth-dependent)
    "../../../../etc/hosts",             # milder *nix fallback (may not exist on this OS)
    "../requirements.txt",               # KNOWN to exist one level above sandbox_files/
    "../README.md",                      # KNOWN to exist one level above sandbox_files/
]
TRAVERSAL_WRITE_TARGET = "../../mcp_attack_proof.txt"  # writes just outside sandbox_files/


async def try_read(session: ClientSession, filename: str) -> dict:
    result = await session.call_tool("read_file", {"filename": filename})
    text = "".join(c.text for c in result.content if hasattr(c, "text"))
    escaped = not text.startswith("ERROR:")
    return {"filename": filename, "output_preview": text[:200], "escaped_sandbox": escaped}


async def try_write(session: ClientSession, filename: str) -> dict:
    result = await session.call_tool(
        "write_file", {"filename": filename, "content": "MCP_ATTACK_PROOF - written by test_mcp_attacks.py"}
    )
    text = "".join(c.text for c in result.content if hasattr(c, "text"))
    succeeded = text.startswith("OK:")

    # if it claims success, verify a file actually landed OUTSIDE sandbox_files/
    actually_escaped = False
    if succeeded:
        target_path = (SANDBOX_DIR / filename).resolve()
        actually_escaped = SANDBOX_DIR.resolve() not in target_path.parents and target_path != SANDBOX_DIR.resolve()

    return {
        "filename": filename,
        "tool_response": text,
        "claimed_success": succeeded,
        "verified_escaped_sandbox": actually_escaped,
    }


async def main():
    server_params = StdioServerParameters(command=sys.executable, args=[SERVER_SCRIPT])
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            print("=" * 70)
            print("DIRECT MCP-LAYER TESTS (no LLM involved -- pure code test)")
            print("=" * 70)

            print("\n--- read_file path traversal attempts ---")
            read_results = []
            for target in TRAVERSAL_READ_TARGETS:
                r = await try_read(session, target)
                read_results.append(r)
                status = "ESCAPED SANDBOX (vulnerable)" if r["escaped_sandbox"] else "blocked"
                print(f"  {target!r:45s} -> {status}")
                if r["escaped_sandbox"]:
                    print(f"      preview: {r['output_preview']!r}")

            print("\n--- write_file path traversal attempt ---")
            write_result = await try_write(session, TRAVERSAL_WRITE_TARGET)
            status = (
                "ESCAPED SANDBOX (vulnerable)"
                if write_result["verified_escaped_sandbox"]
                else "blocked / did not actually escape"
            )
            print(f"  {TRAVERSAL_WRITE_TARGET!r:45s} -> {status}")
            print(f"      tool said: {write_result['tool_response']!r}")

            # cleanup: remove any file we actually managed to plant outside the sandbox
            proof_path = (SANDBOX_DIR / TRAVERSAL_WRITE_TARGET).resolve()
            if proof_path.exists() and write_result["verified_escaped_sandbox"]:
                proof_path.unlink()
                print(f"      (cleaned up: deleted {proof_path})")

            print("\n" + "=" * 70)
            any_read_escaped = any(r["escaped_sandbox"] for r in read_results)
            any_write_escaped = write_result["verified_escaped_sandbox"]
            print(f"CODE-LEVEL VERDICT:")
            print(f"  read_file has path-traversal vulnerability:  {any_read_escaped}")
            print(f"  write_file has path-traversal vulnerability: {any_write_escaped}")
            print("=" * 70)
            print(
                "\nNote: this measures the TOOL CODE only. Step 3's run_attacks.py showed "
                "Claude's own judgment refuses these paths when going through the normal "
                "agent loop. Both results are real and both matter -- one tells you about "
                "your infrastructure, the other tells you about the model's behavior. "
                "Step 4 should harden the code regardless of model judgment, since you "
                "can't rely on model refusals as your only line of defense."
            )


if __name__ == "__main__":
    asyncio.run(main())