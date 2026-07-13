"""
Sanity check: talk to the MCP server directly (no Claude involved) to confirm
tools are registered and callable. Run this first before testing the full agent.
"""
import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER_SCRIPT = str(Path(__file__).parent.parent / "mcp_server" / "server.py")


async def main():
    # sys.executable ensures this works cross-platform (Windows has no
    # "python3" command by default; Linux/Mac usually alias python -> python3)
    server_params = StdioServerParameters(command=sys.executable, args=[SERVER_SCRIPT])
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            print("Registered tools:")
            for t in tools.tools:
                print(f"  - {t.name}: {t.description.strip().splitlines()[0]}")

            print("\nCalling read_file('notes.txt'):")
            result = await session.call_tool("read_file", {"filename": "notes.txt"})
            print(result.content[0].text[:200], "...\n")

            print("Calling read_file('does_not_exist.txt') [should error cleanly]:")
            result = await session.call_tool("read_file", {"filename": "does_not_exist.txt"})
            print(result.content[0].text)

            print("\nCalling web_search('MCP security'):")
            result = await session.call_tool("web_search", {"query": "MCP security"})
            print(result.content[0].text)


if __name__ == "__main__":
    asyncio.run(main())
