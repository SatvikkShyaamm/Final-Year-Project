"""
Pydantic schemas for Module 9 -- Attack Simulation.

Mirrored on the frontend in frontend/src/types/index.ts.
"""
from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class SimulationRequest(BaseModel):
    """POST /simulate/{scenario} body -- which ACTIVE session to run the
    scenario against."""

    session_id: str


class SimulationResultOut(BaseModel):
    """What actually happened. Only the fields relevant to the scenario that
    ran are populated -- the six continuous-evaluation scenarios populate
    the score/risk/action fields (mirroring SecurityEventResultOut exactly);
    `session_termination` populates `state`/`termination_reason` instead."""

    scenario: str
    session_id: str

    # populated for every scenario except session_termination
    security_event_id: str | None = None
    event_type: str | None = None
    weight_applied: int | None = None
    reason: str | None = None
    previous_score: int | None = None
    new_score: int | None = None
    previous_risk: str | None = None
    new_risk: str | None = None
    action: str | None = None
    source: str | None = None
    mfa_challenge_id: str | None = None

    # populated only for session_termination
    state: str | None = None
    termination_reason: str | None = None


class SimulationScenarioOut(BaseModel):
    scenario: str
    label: str


class SimulationScenariosResponse(BaseModel):
    scenarios: list[SimulationScenarioOut]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
