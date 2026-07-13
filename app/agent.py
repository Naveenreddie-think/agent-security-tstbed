"""
Agent core: runs an agentic tool-use loop against Claude, with tools
served over MCP (not inline Python functions -- this is what makes it
a real MCP integration rather than plain function-calling).
"""
import asyncio
import os
import sys
from contextlib import AsyncExitStack
from pathlib import Path

from dotenv import load_dotenv
from anthropic import Anthropic
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Load .env from the project root regardless of where this script is run from
load_dotenv(Path(__file__).parent.parent / ".env")

MODEL = "claude-sonnet-4-6"  # swap freely; keep cheap for dev/demo traffic
SERVER_SCRIPT = str(Path(__file__).parent.parent / "mcp_server" / "server.py")

SYSTEM_PROMPT = """You are a helpful assistant with access to tools via MCP.
You can read files from a sandboxed notes directory and search the web.
Use tools only when they help answer the user's question. Be concise.
"""


class Agent:
    """
    Wraps one live MCP session + one Claude conversation.
    Call `agent.run(user_query)` to get a final text answer.
    Call `agent.run_verbose(user_query)` to get the full transcript
    (used later for attack logging in Step 3).
    """

    def __init__(self, anthropic_api_key: str | None = None):
        self.client = Anthropic(api_key=anthropic_api_key)  # falls back to ANTHROPIC_API_KEY env var
        self._session: ClientSession | None = None
        self._exit_stack = AsyncExitStack()
        self._tools_schema = None

    async def connect(self):
        # sys.executable ensures this works cross-platform (Windows has no
        # "python3" command by default; Linux/Mac usually alias python -> python3)
        server_params = StdioServerParameters(command=sys.executable, args=[SERVER_SCRIPT])
        stdio_transport = await self._exit_stack.enter_async_context(stdio_client(server_params))
        read, write = stdio_transport
        self._session = await self._exit_stack.enter_async_context(ClientSession(read, write))
        await self._session.initialize()

        tools_result = await self._session.list_tools()
        self._tools_schema = [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.inputSchema,
            }
            for t in tools_result.tools
        ]

    async def close(self):
        await self._exit_stack.aclose()

    async def run_verbose(self, user_query: str, max_turns: int = 6) -> dict:
        """Runs the agent loop and returns a full transcript (for logging/attack analysis)."""
        assert self._session is not None, "call connect() first"

        messages = [{"role": "user", "content": user_query}]
        transcript = {"query": user_query, "turns": []}

        for _ in range(max_turns):
            response = self.client.messages.create(
                model=MODEL,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                tools=self._tools_schema,
                messages=messages,
            )

            turn_record = {"stop_reason": response.stop_reason, "blocks": []}

            if response.stop_reason != "tool_use":
                # final answer
                final_text = "".join(
                    block.text for block in response.content if block.type == "text"
                )
                turn_record["blocks"].append({"type": "final_text", "text": final_text})
                transcript["turns"].append(turn_record)
                transcript["final_answer"] = final_text
                return transcript

            # model wants to use one or more tools
            messages.append({"role": "assistant", "content": response.content})
            tool_results_content = []

            for block in response.content:
                if block.type == "tool_use":
                    tool_name = block.name
                    tool_input = block.input
                    turn_record["blocks"].append(
                        {"type": "tool_call", "name": tool_name, "input": tool_input}
                    )

                    result = await self._session.call_tool(tool_name, tool_input)
                    result_text = "".join(
                        c.text for c in result.content if hasattr(c, "text")
                    )
                    turn_record["blocks"].append(
                        {"type": "tool_result", "name": tool_name, "output": result_text}
                    )

                    tool_results_content.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result_text,
                        }
                    )

            transcript["turns"].append(turn_record)
            messages.append({"role": "user", "content": tool_results_content})

        transcript["final_answer"] = "[max turns reached without final answer]"
        return transcript

    async def run(self, user_query: str) -> str:
        transcript = await self.run_verbose(user_query)
        return transcript["final_answer"]


async def _demo():
    agent = Agent()
    await agent.connect()
    try:
        answer = await agent.run("Read notes.txt and summarize the action items.")
        print("ANSWER:\n", answer)
    finally:
        await agent.close()


if __name__ == "__main__":
    asyncio.run(_demo())
