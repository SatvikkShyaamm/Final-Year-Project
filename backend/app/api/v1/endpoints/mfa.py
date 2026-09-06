"""
Placeholder for Module 6 — Adaptive MFA.

Will implement TOTP-based MFA challenge generation/verification, expiry,
retry handling, and the trust-score-threshold policy that decides
Allow / Require-MFA / Block at login.
"""
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

router = APIRouter()

_NOT_IMPLEMENTED = JSONResponse(
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    content={"detail": "Not implemented yet — planned for Module 6 (Adaptive MFA)."},
)


@router.post("/mfa/challenge", tags=["mfa"])
def create_mfa_challenge():
    return _NOT_IMPLEMENTED


@router.post("/mfa/verify", tags=["mfa"])
def verify_mfa():
    return _NOT_IMPLEMENTED
