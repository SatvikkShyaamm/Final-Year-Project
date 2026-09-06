"""
Placeholder for Module 8 — Security Dashboard (backend aggregation endpoints).

Will implement the REST/WebSocket endpoints that feed the admin dashboard's
overview cards, live session table, trust-score panels, alerts feed, ACL
monitor, and analytics charts — all reading real state produced by
Modules 2-7, never mocked data.
"""
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

router = APIRouter()

_NOT_IMPLEMENTED = JSONResponse(
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    content={"detail": "Not implemented yet — planned for Module 8 (Security Dashboard)."},
)


@router.get("/dashboard/overview", tags=["dashboard"])
def dashboard_overview():
    return _NOT_IMPLEMENTED
