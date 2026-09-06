"""
Placeholder for Module 5 — Trust Score Engine.

Will implement the configurable weighted-factor trust score calculation
(known device, known IP, VPN/proxy, login-time normalcy, failed-auth
history, etc.), risk classification, and score storage/history.
"""
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

router = APIRouter()

_NOT_IMPLEMENTED = JSONResponse(
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    content={"detail": "Not implemented yet — planned for Module 5 (Trust Score Engine)."},
)


@router.get("/trust-score/{user_id}", tags=["trust-score"])
def get_trust_score(user_id: str):
    return _NOT_IMPLEMENTED
