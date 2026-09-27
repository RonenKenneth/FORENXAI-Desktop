from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.analysis import (
    router as analysis_router,
)

from app.api.cases import (
    router as cases_router,
)

from app.services.logging_service import (
    logger,
)


# ============================================================
# APPLICATION LIFESPAN
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    # --------------------------------------------------------
    # STARTUP
    # --------------------------------------------------------

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
        "status": "healthy"
    }