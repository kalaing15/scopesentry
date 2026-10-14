from fastapi import FastAPI

app = FastAPI(
    title="ScopeSentry-R API",
    description="Intent-conditioned least-privilege security analysis system",
    version="0.1.0",
)


@app.get("/")
async def root():
    return {
        "project": "ScopeSentry-R",
        "status": "running",
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
    }