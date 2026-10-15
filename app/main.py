from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.analysis import router as analysis_router
from app.api.composition import router as composition_router
from app.api.evidence import router as evidence_router
from app.api.gateway import router as gateway_router
from app.api.demo import router as demo_router

app = FastAPI(
    title="ScopeSentry-R API",
    description=(
        "Intent-conditioned OAuth exposure analysis and "
        "least-privilege synthesis system"
    ),
    version="0.1.0",
)

_DASHBOARD_DIRECTORY = Path(__file__).resolve().parent / "static" / "dashboard"
_DASHBOARD_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self' data:; font-src 'none'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

app.mount(
    "/demo-assets",
    StaticFiles(directory=_DASHBOARD_DIRECTORY),
    name="demo-assets",
)

app.include_router(analysis_router)
app.include_router(composition_router)
app.include_router(evidence_router)
app.include_router(gateway_router)
app.include_router(demo_router)


@app.get("/demo", include_in_schema=False, response_class=FileResponse)
async def demo_dashboard() -> FileResponse:
    return FileResponse(
        _DASHBOARD_DIRECTORY / "index.html",
        media_type="text/html",
        headers=_DASHBOARD_HEADERS,
    )


@app.get("/")
async def root():
    return {
        "project": "ScopeSentry-R",
        "status": "running",
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy"}
