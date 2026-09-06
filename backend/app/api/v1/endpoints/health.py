"""
Health/status endpoint — the one real functional deliverable of Module 1.

This is intentionally not a fake "always OK" endpoint: it performs a live
SELECT 1 against Postgres and a live PING against Redis, so the dashboard
(and CI, later) can tell the difference between "the API process is up" and
"the API's actual dependencies are reachable".
"""
from fastapi import APIRouter

from app.core.config import get_settings
from app.core.database import check_database_connection
from app.core.redis_client import check_redis_connection

router = APIRouter()
settings = get_settings()


@router.get("/health", tags=["system"])
def health_check() -> dict:
    db_ok = check_database_connection()
    redis_ok = check_redis_connection()

    return {
        "status": "ok" if (db_ok and redis_ok) else "degraded",
        "project": settings.project_name,
        "environment": settings.environment,
        "dependencies": {
            "database": "connected" if db_ok else "unreachable",
            "redis": "connected" if redis_ok else "unreachable",
        },
    }
