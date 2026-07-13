# Agent Security Testbed

An MCP-based AI agent, built specifically so it can be attacked and hardened.
This repo is being built in stages; **this is Step 1: the base agent**, with
no defenses yet — that's intentional (see Roadmap below).

## What's here right now

- `mcp_server/server.py` — an MCP server exposing two tools:
  - `read_file` — reads files from a sandboxed directory (naive, no path-traversal
    checks yet — deliberate, see Roadmap)
  - `web_search` — stubbed search (returns fake results; swap in Tavily/Serper for
    a real deployment)
- `app/agent.py` — the agentic loop: sends the user query to Claude, executes
  any tool calls the model requests via the MCP client, feeds results back,
  repeats until a final answer.
- `app/main.py` — FastAPI wrapper exposing `/query` and `/query/verbose`
  (the latter returns the full tool-call transcript, used later for attack analysis).
- `app/test_mcp_only.py` — sanity check for the MCP layer with no LLM calls
  (useful for confirming tools work before spending API credits).

## Running it

```bash
cp .env.example .env   # add your real ANTHROPIC_API_KEY
pip install -r requirements.txt

# 1. sanity-check the MCP tools with no LLM involved
python3 app/test_mcp_only.py

# 2. run the agent directly from the command line
python3 app/agent.py

# 3. or run it as an API
uvicorn app.main:app --reload
curl -X POST localhost:8000/query -H "Content-Type: application/json" \
  -d '{"query": "Read notes.txt and summarize the action items."}'
```

## Roadmap (why the code looks unfinished on purpose)

This project is being built in explicit stages so that "before/after" security
numbers are real, not retrofitted:

- [x] **Step 1 — Base agent.** Working end-to-end loop, MCP tools, API wrapper. *(you are here)*
- [ ] **Step 2 — Attack surface expansion.** More realistic tools / richer sandbox content.
- [ ] **Step 3 — Attack the agent.** Direct prompt injection, indirect injection via
      tool output, MCP tool-response poisoning, path traversal on `read_file`,
      permission-scope escalation. Every attack attempt + result logged as a transcript.
- [ ] **Step 4 — Defenses.** Input/output classifiers, tool permission scoping,
      path sanitization, and re-running the Step 3 test suite to measure the
      actual before/after attack success rate (not just claimed).
- [ ] **Step 5 — Ship.** Streamlit "try an attack" demo UI, deploy to Fly.io/Render,
      rate limiting, cost caps, basic observability.

## Known limitations (intentional, for now)

- `read_file` has no path traversal protection yet — this is a planned attack
  surface for Step 3, not an oversight.
- `web_search` is stubbed with fake data — no external API key required for
  local dev; production deployment should swap in a real search API.
- No rate limiting or auth on the API yet — added in Step 5.
