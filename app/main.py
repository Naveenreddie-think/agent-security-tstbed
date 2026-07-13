"""
FastAPI wrapper around the Agent. This is what you'll eventually deploy
and (in Step 5) add rate limiting / observability / the attack-testing UI to.
"""
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from pydantic import BaseModel

from app.agent import Agent

load_dotenv(Path(__file__).parent.parent / ".env")

agent_instance: Agent | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global agent_instance
    agent_instance = Agent()
    await agent_instance.connect()
    yield
    await agent_instance.close()


app = FastAPI(title="Agent Security Testbed", lifespan=lifespan)


class QueryRequest(BaseModel):
    query: str


class QueryResponse(BaseModel):
    answer: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/query", response_model=QueryResponse)
async def query(req: QueryRequest):
    answer = await agent_instance.run(req.query)
    return QueryResponse(answer=answer)


@app.post("/query/verbose")
async def query_verbose(req: QueryRequest):
    """Returns the full transcript -- useful for attack analysis in Step 3."""
    transcript = await agent_instance.run_verbose(req.query)
    return transcript
