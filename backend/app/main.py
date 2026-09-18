from fastapi import FastAPI

from app.api.analysis import router as analysis_router


app = FastAPI(
    title="FORENXAI Backend",
    version="1.0.0"
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
        "status": "healthy"
    }