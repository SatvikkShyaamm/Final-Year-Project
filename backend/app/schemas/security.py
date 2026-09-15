"""
Pydantic schemas for Module 7 -- Continuous Trust Evaluation.

Mirrored on the frontend in frontend/src/types/index.ts.
"""
from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field


class SecurityEventRequest(BaseModel):
    """POST /security/events body -- admin today (and, once built, Module 9's
    simulation buttons) trigger a mid-session security-relevant event for one
    ACTIVE session. `ip_address` only matters for ip_change / vpn_detected;
    every other event_type ignores it."""

    session_id: str
    event_type: str
    ip_address: str | None = None


class SecurityEventResultOut(BaseModel):
    """What actually happened as a result of ingesting one event."""

    security_event_id: str
    session_id: str
    event_type: str
    weight_applied: int
    reason: str
    previous_score: int
    new_score: int
    previous_risk: str
    new_risk: str
    action: str                          # none | reverify | revoke
    source: str                          # auto | admin -- Section 18 (2026-09-15)
    mfa_challenge_id: str | None = None  # set when action == reverify


class SecurityEventReadOut(BaseModel):
    """Read-only audit row -- GET /security/events (dashboard feed)."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    session_id: str
    user_id: int
    event_type: str
    weight_applied: int
    reason: str
    previous_score: int
    new_score: int
    previous_risk: str
    new_risk: str
    action: str
    source: str  # auto | admin -- Section 18 (2026-09-15)
    created_at: datetime


class SecurityEventListResponse(BaseModel):
    events: list[SecurityEventReadOut]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class HeartbeatResultOut(BaseModel):
    """POST /security/heartbeat response -- Module 7 hardening, Section 18
    (2026-09-15). Best-effort/informational: the frontend fires this on a
    timer and doesn't need to act on the response itself (any resulting
    trust.updated / trust.reverify_required / session.terminated push
    arrives on the session's own signalling WebSocket, exactly as it would
    for a manual admin Trigger)."""

    session_id: str | None  # null if the caller has no active session right now
    seeded: bool            # True on this session's first-ever heartbeat (nothing fired)
    events: list[str] = []  # event_type(s) fired by this one heartbeat, in order
    session_terminated: bool = False
