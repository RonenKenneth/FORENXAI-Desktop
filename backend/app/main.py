from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.gzip import GZipMiddleware

from app.api.analysis import (
    router as analysis_router,
)

from app.api.cases import (
    router as cases_router,
)

from app.services.logging_service import (
    logger,
)

from app.services.recommendation_service import (
    rag_status,
    start_rag_warmup,
)


# ============================================================
# APPLICATION LIFESPAN
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    # --------------------------------------------------------
    # STARTUP
    # --------------------------------------------------------
    # Open the RAG index and load Qwen on a background thread. The server
    # starts accepting requests immediately; an analysis that arrives first
    # waits only for whatever is still loading.

    start_rag_warmup()

    logger.info(
        "FORENXAI backend startup complete."
    )

    try:
        yield

    finally:

        # ----------------------------------------------------
        # SHUTDOWN
        # ----------------------------------------------------

        logger.info(
            "FORENXAI backend shutdown initiated."
        )


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="FORENXAI Backend",
    version="1.0.0",
    lifespan=lifespan
)


# ============================================================
# ROUTERS
# ============================================================

# analysis.json is mostly repeated recommendation text: gzip cuts the
# transfer to a small fraction.
app.add_middleware(
    GZipMiddleware,
    minimum_size=1024
)

app.include_router(
    analysis_router
)

app.include_router(
    cases_router
)


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get("/")
def root():
    return {
        "application": "FORENXAI Backend",
        "status": "online"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "rag": rag_status(),
    }
