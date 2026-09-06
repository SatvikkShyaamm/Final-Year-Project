"""
FastAPI application entrypoint.

Run directly with:  uvicorn app.main:app --reload --port 8000
(from the backend/ directory, with the virtualenv from requirements.txt active)
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger

settings = get_settings()
configure_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("%s starting up in '%s' mode", settings.project_name, settings.environment)
    yield
    logger.info("%s shutting down", settings.project_name)


app = FastAPI(
    title=settings.project_name,
    description=(
        "Zero Trust Session-Aware Access Control system, extended with "
        "Trust Score, Adaptive MFA, and Continuous Trust Evaluation."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")


@app.get("/", tags=["system"])
def root() -> dict:
    return {
        "project": settings.project_name,
        "status": "running",
        "docs": "/docs",
        "api_prefix": "/api/v1",
    }
