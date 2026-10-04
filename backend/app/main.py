"""FastAPI application entrypoint."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.core.config import settings
from app.core.errors import NetGuardError, netguard_error_handler, unhandled_error_handler
from app.core.logging import configure_logging, get_logger
from app.core.utils import safe_init_db
from app.api.routes_assets import router as assets_router
from app.api.routes_findings import router as findings_router
from app.api.routes_scans import router as scans_router
from app.api.routes_stats import router as stats_router

configure_logging(settings.log_level)
logger = get_logger("app.main")
STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await safe_init_db()
    logger.info("%s started (env=%s)", settings.app_name, settings.app_env)
    yield
    logger.info("%s shutting down", settings.app_name)


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description=(
        "Defensive network asset scanner. Scans only networks the user owns or is "
        "explicitly authorized to assess, using safe, non-intrusive TCP checks."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Error handling
app.add_exception_handler(NetGuardError, netguard_error_handler)
app.add_exception_handler(Exception, unhandled_error_handler)

# Routers
app.include_router(scans_router)
app.include_router(assets_router)
app.include_router(findings_router)
app.include_router(stats_router)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
async def dashboard():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health", tags=["health"])
async def health():
    return {"status": "ok", "app": settings.app_name, "env": settings.app_env}
