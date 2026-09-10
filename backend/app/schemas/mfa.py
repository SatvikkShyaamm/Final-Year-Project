"""
Pydantic schemas for Module 6 -- Adaptive MFA.

Mirrored on the frontend in frontend/src/types/index.ts.
"""
from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field, ConfigDict


class MFAChallengeOut(BaseModel):
    """A live challenge the client must satisfy -- from /auth/login (MFA
    required) or POST /mfa/challenge (step-up). The code itself is never in
    this payload -- it was emailed to the user's registered address (or,
    only when SMTP isn't configured, dev-logged and echoed back as
    `dev_code` -- see app/services/mfa/email_otp.py)."""

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
    delivery: str | None = None    # "sent" | "dev_logged" | "failed"
    dev_code: str | None = None    # dev/test only -- see email_otp.py


class MFAVerifyRequest(BaseModel):
    mfa_token: str
    code: str = Field(min_length=1, max_length=16)


class MFAChallengeStatusOut(BaseModel):
    """Read-only view -- no code, no mfa_token."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: int
    username: str | None = None
    method: str
    reason: str
    status: str
    delivery: str | None = Field(default=None, validation_alias="delivered_via")
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
