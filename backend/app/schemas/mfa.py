"""
Pydantic schemas for Module 6 — Adaptive MFA.

Mirrored on the frontend in frontend/src/types/index.ts.
"""
from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field


class MFAEnrollmentOut(BaseModel):
    """Only returned until the user's TOTP credential is `confirmed`."""

    secret: str
    provisioning_uri: str
    digits: int
    interval_seconds: int


class MFAChallengeOut(BaseModel):
    """A live challenge the client must satisfy — from /auth/login (MFA
    required) or POST /mfa/challenge (step-up)."""

    challenge_id: str
    mfa_token: str                 # short-lived; the only thing /mfa/verify accepts
    method: str
    reason: str
    status: str
    expires_at: datetime
    attempts_remaining: int
    max_attempts: int
    trust_score: int | None = None
    risk_level: str | None = None
    enrollment: MFAEnrollmentOut | None = None
    dev_code: str | None = None    # dev/test only — the currently valid TOTP code


class MFAVerifyRequest(BaseModel):
    mfa_token: str
    code: str = Field(min_length=1, max_length=16)


class MFAChallengeStatusOut(BaseModel):
    """Read-only view — no secret, no mfa_token."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: int
    username: str | None = None
    method: str
    reason: str
    status: str
    attempts: int
    max_attempts: int
    trust_score: int | None = None
    risk_level: str | None = None
    created_at: datetime
    expires_at: datetime
    verified_at: datetime | None = None


class MFAChallengeListResponse(BaseModel):
    challenges: list[MFAChallengeStatusOut]
    counts: dict[str, int]
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
