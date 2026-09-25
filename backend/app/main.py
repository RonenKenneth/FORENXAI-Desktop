from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.analysis import router as analysis_router
from app.services.recommendation_service import (
    rag_status,
    start_rag_warmup,
)


@asynccontextmanager
async def lifespan(_app):
    # Open the RAG index and load Qwen on a background thread. The server
    # starts accepting requests immediately; an analysis that arrives first
    # waits only for whatever is still loading.
    start_rag_warmup()
    yield


app = FastAPI(
    title="FORENXAI Backend",
    version="1.0.0",
    lifespan=lifespan,
)


app.include_router(analysis_router)


@app.get("/")
def root():
    return {
        "application": "FORENXAI Backend",
        "status": "online"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "rag": rag_status(),
    }