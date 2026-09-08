"""
Module 4 — Dynamic ACL Management (read surface).

    GET /acl/rules        admin: the dashboard's ACL Monitor feed
    GET /acl/rules/{id}    admin: one rule
    GET /acl/status        admin: health of the enforcement plane

There is deliberately no POST / DELETE here: ACL rules are not hand-editable,
they are strictly bound to session lifecycle (created on session open, removed
on session close). Terminating a session — which an admin can do via
DELETE /api/v1/sessions/{id} — is what removes its ACL rule.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session as DbSession

from app.api.deps import CurrentAdmin, get_db
from app.models.acl import ACLState
from app.schemas.acl import ACLRuleListResponse, ACLRuleRead, ACLStatusResponse
from app.services import acl as acl_service
from app.services.acl import store as acl_store
from app.services.acl.enforcer import get_enforcer
from app.core.config import get_settings

router = APIRouter()
settings = get_settings()


@router.get(
    "/acl/rules",
    tags=["acl"],
    response_model=ACLRuleListResponse,
    summary="List ACL rules (admin) — the dashboard's ACL Monitor feed",
)
def list_acl_rules(
    _admin: CurrentAdmin,
    db: DbSession = Depends(get_db),
    include_removed: bool = Query(default=False),
    state: str | None = Query(default=None, description="Filter by exact state"),
) -> ACLRuleListResponse:
    rules = acl_service.list_rules(db, include_removed=include_removed, state=state)
    auth_ms, revoke_ms = acl_service.average_latencies(db)
    return ACLRuleListResponse(
        rules=[ACLRuleRead.model_validate(r) for r in rules],
        active_count=acl_service.count_active(db),
        enforcement_backend=get_enforcer().name,
        avg_authorization_latency_ms=auth_ms,
        avg_revocation_latency_ms=revoke_ms,
    )


@router.get(
    "/acl/rules/{rule_id}",
    tags=["acl"],
    response_model=ACLRuleRead,
    summary="Inspect one ACL rule (admin)",
)
def get_acl_rule(
    rule_id: str, _admin: CurrentAdmin, db: DbSession = Depends(get_db)
) -> ACLRuleRead:
    rule = acl_service.get_rule(db, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ACL rule not found")
    return ACLRuleRead.model_validate(rule)


@router.get(
    "/acl/status",
    tags=["acl"],
    response_model=ACLStatusResponse,
    summary="Health of the ACL enforcement plane (admin)",
)
def acl_status(
    _admin: CurrentAdmin, db: DbSession = Depends(get_db)
) -> ACLStatusResponse:
    kernel = {
        settings.acl_ipset_v4: len(acl_store.kernel_members(settings.acl_ipset_v4)),
        settings.acl_ipset_v6: len(acl_store.kernel_members(settings.acl_ipset_v6)),
    }
    return ACLStatusResponse(
        enforcement_backend=get_enforcer().name,
        worker_enabled=settings.l_pep_worker_enabled,
        queue_depth=acl_store.queue_depth(),
        active_rules=acl_service.count_active(db),
        kernel_entries=kernel,
    )
