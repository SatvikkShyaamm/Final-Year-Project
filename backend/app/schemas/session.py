"""
Pydantic schemas for Module 3 — Session Lifecycle.

Mirrored on the frontend in frontend/src/types/index.ts. The three trailing
``*_reserved`` fields are intentionally always null in Module 3 — they keep the
dashboard's Live Sessions table column set stable so it doesn't have to change
when Module 5 (trust score / risk) and Module 4 (ACL status) start filling
them in.
"""
from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field


class SessionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: int
    username: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    state: str
    ws_connected: bool
    created_at: datetime
    last_seen_at: datetime
    terminated_at: datetime | None = None
    termination_reason: str | None = None
    duration_seconds: int

    # Reserved for later modules (always null here).
    trust_score: int | None = None
    risk_level: str | None = None
    acl_status: str | None = None
    # Module 7: "reverify_required" while a continuous re-evaluation has an
    # open (pending) risk_retrigger MFA challenge outstanding for this
    # session; null otherwise. Computed at the endpoint layer (not a DB
    # column), same pattern as acl_status.
    current_action: str | None = None


class SessionListResponse(BaseModel):
    sessions: list[SessionRead]
    active_count: int
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class SessionTerminateResponse(BaseModel):
    id: str
    state: str
    termination_reason: str | None = None
