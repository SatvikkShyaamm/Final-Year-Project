"""
Pydantic schemas for Module 8 -- Security Dashboard.

Mirrored on the frontend in frontend/src/types/index.ts.
"""
from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class DashboardOverviewResponse(BaseModel):
    """Section 5's "Dashboard Home" stat cards -- real aggregates over
    Modules 2-7's own state (app.services.dashboard.overview), nothing
    computed or stored by this module itself."""

    active_users: int
    active_sessions: int
    average_trust_score: float | None
    high_risk_sessions: int
    mfa_requests_pending: int
    revoked_sessions: int
    current_acl_rules: int
    avg_authorization_latency_ms: float | None
    avg_revocation_latency_ms: float | None
    locked_out_accounts: int
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CountBucket(BaseModel):
    """One bar/slice of an Analytics chart."""

    label: str
    count: int


class DashboardAnalyticsResponse(BaseModel):
    """Section 5's "Analytics" charts -- one bucket list per chart, always
    real counts over actual rows (see app.services.dashboard.analytics's
    own docstring on why a multi-day failed-login trend is intentionally
    absent rather than fabricated)."""

    login_activity: list[CountBucket]
    trust_score_distribution: list[CountBucket]
    risk_levels: list[CountBucket]
    mfa_events: list[CountBucket]
    revoked_sessions: list[CountBucket]
    security_alerts: list[CountBucket]
    avg_authorization_latency_ms: float | None
    avg_revocation_latency_ms: float | None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class LockedAccountOut(BaseModel):
    """One row of the admin "Locked Accounts" panel -- deferred from the
    Module 6/7 lockout hardening passes to Module 8 (Project status.md
    sections 17b/18)."""

    user_id: int
    username: str | None
    email: str | None
    lock_type: str              # "mfa" | "risk"
    retry_after_seconds: int
    tier: int | None = None     # risk lockouts only (1/2/3 -- see risk_lockout.py)


class LockedAccountsResponse(BaseModel):
    accounts: list[LockedAccountOut]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class LockoutClearedResponse(BaseModel):
    user_id: int
    cleared_mfa: bool
    cleared_risk: bool
