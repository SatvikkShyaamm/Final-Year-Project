"""
Pydantic schemas for Module 4 — Dynamic ACL Management.

Mirrored on the frontend in frontend/src/types/index.ts. These describe the
persisted ACL state the dashboard's ACL Monitor renders — real backend state,
not a UI-only view.
"""
from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field


class ACLRuleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    session_id: str
    user_id: int
    username: str | None = None
    client_ip: str
    resource: str
    ipset_name: str
    state: str
    enforcement: str
    created_at: datetime
    activated_at: datetime | None = None
    removed_at: datetime | None = None
    authorization_latency_ms: int | None = None
    revocation_latency_ms: int | None = None
    removal_reason: str | None = None
    last_error: str | None = None


class ACLRuleListResponse(BaseModel):
    rules: list[ACLRuleRead]
    active_count: int
    enforcement_backend: str
    avg_authorization_latency_ms: float | None = None
    avg_revocation_latency_ms: float | None = None
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class ACLStatusResponse(BaseModel):
    """Health of the ACL enforcement plane for the dashboard."""

    enforcement_backend: str
    worker_enabled: bool
    queue_depth: int
    active_rules: int
    kernel_entries: dict[str, int]
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
