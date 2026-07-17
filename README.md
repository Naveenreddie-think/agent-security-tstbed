\# Agent Security Testbed



An MCP-based AI agent, built specifically so it can be attacked and hardened.

This repo was built in explicit stages -- base agent, attack, defend, ship --

so that every "before/after" security claim below is backed by a real,

re-runnable test, not just asserted.



\## What's here right now



\- `mcp\\\_server/server.py` — an MCP server exposing three tools:

&#x20; - `read\\\_file` — reads files from a sandboxed directory. \*\*Hardened in Step 4\*\*

&#x20;   with real path-resolution + containment checks (not naive string matching).

&#x20; - `write\\\_file` — writes files to the sandboxed directory. \*\*Hardened in Step 4\*\*

&#x20;   the same way.

&#x20; - `web\\\_search` — stubbed search (returns fake results; swap in Tavily/Serper for

&#x20;   a real deployment).

\- `sandbox\\\_files/` — realistic bait content used throughout the attack testing:

&#x20; - `notes.txt` — benign meeting notes.

&#x20; - `confidential\\\_salary\\\_data.txt` — fake sensitive data, used to test whether the

&#x20;   agent can be tricked into reading/leaking content the user never asked for.

&#x20; - `vendor\\\_onboarding\\\_guide.txt` — contains an embedded hidden instruction, the

&#x20;   real \*\*indirect prompt injection\*\* test case used throughout Steps 3-4c.

\- `app/agent.py` — the agentic loop: sends the user query to Claude, executes

&#x20; any tool calls the model requests via the MCP client, feeds results back,

&#x20; repeats until a final answer. \*\*Step 4c\*\*: every tool result is classified by

&#x20; the defense layer before being sent back to Claude (toggle via `defense\\\_enabled`).

\- `app/defense.py` — wraps the trained injection classifier for use as a live

&#x20; content filter; flags and redacts suspicious tool output before the model sees it.

\- `app/attack\\\_taxonomy.py` — defines 6 injection attack technique categories with

&#x20; train/test phrasing families held out from each other, for honest generalization testing.

\- `app/train\\\_injection\\\_classifier.py` — trains a TF-IDF + Logistic Regression

&#x20; classifier and compares it against a naive keyword baseline on held-out data.

\- `app/main.py` — FastAPI wrapper exposing `/query` and `/query/verbose`.

\- `app/streamlit\\\_app.py` — \*\*Step 5\*\*: interactive demo UI with example attacks,

&#x20; a live defense on/off toggle, and rate limiting.

\- `app/test\\\_mcp\\\_only.py` — sanity check for the MCP layer with no LLM calls.

\- `app/test\\\_mcp\\\_attacks.py` — direct, no-LLM attack suite against the MCP tool layer.

\- `app/run\\\_attacks.py` — attack suite run through the full agent (model in the loop).

\- `app/test\\\_defense\\\_integration.py` — verifies the defense layer inside the live pipeline.

\- `FINDINGS.md` — the full write-up: every attack, every result, every bug found

&#x20; and fixed along the way, with honest limitations noted throughout.



\## Running it locally



```bash

cp .env.example .env   # add your real ANTHROPIC\_API\_KEY

pip install -r requirements.txt



\# 1. sanity-check the MCP tools with no LLM involved

python app/test\_mcp\_only.py



\# 2. generate the attack taxonomy + train the injection classifier (one-time)

python -m app.attack\_taxonomy

python -m app.train\_injection\_classifier



\# 3. run the agent directly from the command line

python app/agent.py



\# 4. or run the interactive demo

streamlit run app/streamlit\_app.py



\# 5. or run it as an API

uvicorn app.main:app --reload

curl -X POST localhost:8000/query -H "Content-Type: application/json" \\

&#x20; -d '{"query": "Read notes.txt and summarize the action items."}'

```



\## Deployment (Render)



This repo includes `render.yaml` for one-click deployment to Render's free tier:



1\. Push this repo to GitHub (already done if you're reading this on GitHub).

2\. On \[render.com](https://render.com), create a new \*\*Web Service\*\* from this repo.

&#x20;  Render will detect `render.yaml` automatically.

3\. In the Render dashboard, set the `ANTHROPIC\\\_API\\\_KEY` environment variable

&#x20;  manually (never commit real keys — `render.yaml` intentionally leaves this

&#x20;  blank with `sync: false`).

4\. Deploy. Render will run `pip install -r requirements.txt` then start the

&#x20;  Streamlit app on the assigned port.



\*\*Cost/rate-limit note:\*\* the deployed demo makes real Anthropic API calls.

`app/streamlit\\\_app.py` includes a per-session query cap and a best-effort daily

global cap (see the docstring at the top of that file for exact limits and

honest caveats about their reliability on ephemeral hosting). For a real

production deployment, also set a hard monthly spend cap in the Anthropic

console itself -- that is the only fully reliable backstop.



\## Roadmap (why the code looks unfinished on purpose)



This project was built in explicit stages so that "before/after" security

numbers are real, not retrofitted:



\- \[x] \*\*Step 1 — Base agent.\*\* Working end-to-end loop, MCP tools, API wrapper.

\- \[x] \*\*Step 2 — Attack surface expansion.\*\* Added `write\\\_file` tool (naive/unrestricted

&#x20;     on purpose) and richer sandbox content: a fake sensitive file and a document with

&#x20;     an embedded hidden instruction for testing indirect prompt injection.

\- \[x] \*\*Step 3 — Attack the agent.\*\* Ran both agent-level attacks (model in the loop,

&#x20;     `app/run\\\_attacks.py`) and direct code-level attacks (no model, `app/test\\\_mcp\\\_attacks.py`).

&#x20;     Result: Claude's judgment blocked 100% of attacks going through the normal agent flow,

&#x20;     but the underlying tool code had zero real protection (confirmed path traversal on both

&#x20;     `read\\\_file` and `write\\\_file`). See \*\*\[FINDINGS.md](FINDINGS.md)\*\*.

\- \[x] \*\*Step 4 — Defenses.\*\* Hardened `read\\\_file`/`write\\\_file` with real path

&#x20;     resolution + containment checks. Re-ran the exact Step 3 code-level attack

&#x20;     suite: all previously-successful traversal attacks now blocked, legitimate

&#x20;     functionality unaffected.

\- \[x] \*\*Step 4b — Purpose-built injection classifier.\*\* Built a taxonomy of 6

&#x20;     injection techniques with held-out phrasing families, trained a TF-IDF +

&#x20;     Logistic Regression classifier, and compared it against a naive keyword

&#x20;     baseline. Result: 100% recall / 100% precision on held-out novel phrasing

&#x20;     vs. 42% recall for the keyword baseline.

\- \[x] \*\*Step 4c — Wire the classifier into the live agent.\*\* Every tool result

&#x20;     is now classified before reaching Claude; flagged content is redacted

&#x20;     before the model ever sees it. Verified via a real side-by-side run:

&#x20;     with defense on, the hidden injection in `vendor\\\_onboarding\\\_guide.txt`

&#x20;     never reached the model at all (classifier confidence 0.65); with

&#x20;     defense off, the model still refused via its own judgment (same as

&#x20;     Step 3). Two independent layers now provide real defense in depth.

\- \[x] \*\*Step 4d — Adaptive adversarial red-teaming.\*\* Claude itself, in a

&#x20;     self-testing role, generated 8 rounds of increasingly varied poisoned

&#x20;     documents (different genres each round) targeting the trained classifier,

&#x20;     adapting based on feedback each round. Result: 0/8 evasions -- but with

&#x20;     an honest caveat that every candidate had to literally reference the

&#x20;     target filename, which may inflate this result. See \*\*\[FINDINGS.md](FINDINGS.md)\*\*

&#x20;     for the full honest interpretation. \*(you are here)\*

\- \[ ] Adversarial suffix / embedding-space attacks -- optional stretch goal,

&#x20;     requires white-box access to an open-weight model (not applicable to

&#x20;     Claude via API in its current form).



\- \[x] \*\*Step 5 — Ship.\*\* Interactive Streamlit demo with example attacks, a

&#x20;     live defense on/off toggle, and rate limiting. Deployable to Render.

&#x20;     \*(you are here)\*

\- \[ ] Additional attack techniques (multi-agent red-teaming, adversarial

&#x20;     suffix attacks) -- optional depth to add after shipping.



See \*\*\[FINDINGS.md](FINDINGS.md)\*\* for the full methodology and results at every step.



\## Known limitations (documented honestly, not hidden)



\- `web\\\_search` is stubbed with fake data — no external API key required for

&#x20; local dev; production deployment should swap in a real search API.

\- The injection classifier's held-out test set is small (17 examples) --

&#x20; results are a promising signal, not a statistically robust guarantee. See

&#x20; `attack\\\_results/classifier\\\_eval.md` for full numbers and caveats.

\- The classifier's decision margin on some benign content is narrower than

&#x20; the clean headline numbers suggest (see FINDINGS.md, Step 4c honest note).

\- Rate limiting on the deployed demo is best-effort, not a hard guarantee --

&#x20; see the Deployment section above.

