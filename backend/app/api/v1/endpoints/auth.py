"""
Placeholder for Module 2 — Authentication.

Will implement: POST /auth/register, POST /auth/login (returns JWT),
POST /auth/logout, GET /auth/me. Endpoints intentionally return 501 for now
so the route is real and discoverable in OpenAPI docs, but nothing pretends
to authenticate anyone until Module 2 is implemented.
"""
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

router = APIRouter()

_NOT_IMPLEMENTED = JSONResponse(
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    content={"detail": "Not implemented yet — planned for Module 2 (Authentication)."},
)


@router.post("/auth/register", tags=["auth"])
def register():
    return _NOT_IMPLEMENTED


@router.post("/auth/login", tags=["auth"])
def login():
    return _NOT_IMPLEMENTED


@router.post("/auth/logout", tags=["auth"])
def logout():
    return _NOT_IMPLEMENTED
