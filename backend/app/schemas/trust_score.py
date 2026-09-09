"""
Pydantic schemas for Module 5 — Trust Score Engine.

Mirrored on the frontend in frontend/src/types/index.ts.
"""
from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field


class TrustFactorRead(BaseModel):
    """One factor that adjusted (or, in the config catalogue, could adjust) the score."""

    model_config = ConfigDict(from_attributes=True)

    factor_name: str
    factor_kind: str          # baseline | positive | negative
    weight_applied: int       # signed
    reason: str


class SessionTrustScoreRead(BaseModel):
    """The score + breakdown for one session (dashboard Trust Score Monitoring)."""

    session_id: str
    user_id: int
    username: str | None = None
    trust_score: int | None = None
    risk_level: str | None = None
    evaluated_at: datetime | None = None
    factors: list[TrustFactorRead] = Field(default_factory=list)


class TrustScoreHistoryEntry(BaseModel):
    session_id: str
    trust_score: int | None = None
    risk_level: str | None = None
    created_at: datetime
    ip_address: str | None = None
    state: str


class TrustScoreHistoryResponse(BaseModel):
    user_id: int
    username: str | None = None
    entries: list[TrustScoreHistoryEntry]
    average_trust_score: float | None = None


class TrustFactorCatalogEntry(BaseModel):
    factor_name: str
    factor_kind: str
    weight: int                # unsigned magnitude from config
    applies_when: str


class TrustScoreConfigResponse(BaseModel):
    """The live weight table + thresholds, for the dashboard's reference view."""

    baseline: int
    risk_bands: dict[str, str]         # e.g. {"LOW": ">=80", "MEDIUM": "50-79", "HIGH": "<50"}
    factors: list[TrustFactorCatalogEntry]
    failed_login_threshold: int
    failed_login_window_minutes: int
    approved_vpn_cidrs: list[str]
    known_vpn_cidrs: list[str]
    known_vpn_list_is_static_sample: bool = True
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
