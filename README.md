# Agent Security Testbed

An MCP-based AI agent, built specifically so it can be attacked and hardened.
This repo is being built in stages; **this is Step 1: the base agent**, with
no defenses yet — that's intentional (see Roadmap below).

## What's here right now

* \- `mcp\\\_server/server.py` — an MCP server exposing three tools:
* &#x20; - `read\\\_file` — reads files from a sandboxed directory (naive, no path-traversal
* &#x20;   checks yet — deliberate, see Roadmap)
* &#x20; - `write\\\_file` — writes files to the sandboxed directory (also naive/unrestricted
* &#x20;   on purpose — this is the highest-value attack surface in the project, since a
* &#x20;   successful injection here could escape the sandbox or plant persistent content)
* &#x20; - `web\\\_search` — stubbed search (returns fake results; swap in Tavily/Serper for
* &#x20;   a real deployment)
* \- `sandbox\\\_files/` — realistic bait content for later attack testing:
* &#x20; - `notes.txt` — benign meeting notes (used in Step 1 demos)
* &#x20; - `confidential\\\_salary\\\_data.txt` — fake sensitive data, used to test whether the
* &#x20;   agent can be tricked into reading/leaking content the user never asked for
* &#x20; - `vendor\\\_onboarding\\\_guide.txt` — contains an embedded hidden instruction, used
* &#x20;   as the Step 3 test case for \*\*indirect prompt injection\*\*`app/agent.py` — the agentic loop: sends the user query to Claude, executes
any tool calls the model requests via the MCP client, feeds results back,
repeats until a final answer.
* `app/main.py` — FastAPI wrapper exposing `/query` and `/query/verbose`
(the latter returns the full tool-call transcript, used later for attack analysis).
* `app/test\\\_mcp\\\_only.py` — sanity check for the MCP layer with no LLM calls
(useful for confirming tools work before spending API credits).

## Running it

```bash
cp .env.example .env   # add your real ANTHROPIC\\\_API\\\_KEY
pip install -r requirements.txt

# 1. sanity-check the MCP tools with no LLM involved
python3 app/test\\\_mcp\\\_only.py

# 2. run the agent directly from the command line
python3 app/agent.py

# 3. or run it as an API
uvicorn app.main:app --reload
curl -X POST localhost:8000/query -H "Content-Type: application/json" \\\\
  -d '{"query": "Read notes.txt and summarize the action items."}'
```

## Roadmap (why the code looks unfinished on purpose)

This project is being built in explicit stages so that "before/after" security
numbers are real, not retrofitted:

* \- \[x] \*\*Step 1 — Base agent.\*\* Working end-to-end loop, MCP tools, API wrapper.
* \- \[x] \*\*Step 2 — Attack surface expansion.\*\* Added `write\_file` tool (naive/unrestricted
* &#x20;     on purpose) and richer sandbox content: a fake sensitive file and a document with
* &#x20;     an embedded hidden instruction for testing indirect prompt injection.
* \- \[x] \*\*Step 3 — Attack the agent.\*\* Ran both agent-level attacks (model in the loop,
* &#x20;     `app/run\_attacks.py`) and direct code-level attacks (no model, `app/test\_mcp\_attacks.py`).
* &#x20;     Result: Claude's judgment blocked 100% of attacks going through the normal agent flow,
* &#x20;     but the underlying tool code has zero real protection (confirmed path traversal on both
* &#x20;     `read\_file` and `write\_file`). See \*\*\[FINDINGS.md](FINDINGS.md)\*\* for the full writeup.
* &#x20;     \*(you are here)\*
* \- \[x] \*\*Step 4 — Defenses.\*\* Hardened `read\_file`/`write\_file` with real path
* &#x20;     resolution + containment checks (not naive string matching). Re-ran the
* &#x20;     exact Step 3 code-level attack suite: all previously-successful traversal
* &#x20;     attacks now blocked, legitimate functionality unaffected. See
* &#x20;     \*\*\[FINDINGS.md](FINDINGS.md)\*\* for the full before/after comparison.
* &#x20;     
* \- \[x] \*\*Step 4b — Purpose-built injection classifier.\*\* Built a taxonomy of 6
* &#x20;     injection techniques with held-out phrasing families, trained a TF-IDF +
* &#x20;     Logistic Regression classifier, and compared it against a naive keyword
* &#x20;     baseline. Result: 100% recall / 100% precision on held-out novel phrasing
* &#x20;     vs. 42% recall for the keyword baseline. See \*\*\[FINDINGS.md](FINDINGS.md)\*\*.
* &#x20;     \*(you are here)\*
* \[ ] **Step 5 — Ship.** Streamlit "try an attack" demo UI, deploy to Fly.io/Render,
rate limiting, cost caps, basic observability.

## Known limitations (intentional, for now)

* `read\\\_file` has no path traversal protection yet — this is a planned attack
surface for Step 3, not an oversight.
* `web\\\_search` is stubbed with fake data — no external API key required for
local dev; production deployment should swap in a real search API.
* No rate limiting or auth on the API yet — added in Step 5.

