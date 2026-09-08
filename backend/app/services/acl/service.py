"""
ACL control-plane logic — Module 4 (the base paper's SS-PDP side).

On ``session.opened`` it creates a PENDING ``acl_rules`` row and pushes an
``add`` task; on ``session.closed`` it flips the row to REMOVING and pushes a
``remove`` task. It does NOT block waiting for the L-PEP to finish — Redis is
the async decoupling buffer the paper describes; the worker updates the row to
ACTIVE / REMOVED and records the measured latency.

No FastAPI imports. Called from the session hooks (app/services/acl/wiring.py)
and read from the ACL endpoints.
"""
from __future__ import annotations

import ipaddress
import time
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.acl import ACLRule, ACLState
from app.models.session import Session as SessionModel
from app.models.session import utcnow
from app.services.acl import store
from app.services.acl.enforcer import get_enforcer

logger = get_logger(__name__)
settings = get_settings()


def _ipset_for(ip: str) -> str:
    try:
        return (
            settings.acl_ipset_v6
            if ipaddress.ip_address(ip).version == 6
            else settings.acl_ipset_v4
        )
    except ValueError:
        # Not a real IP (e.g. the test client's "testclient" host) — the v4 set
        # name is a harmless label for the simulated backend.
        return settings.acl_ipset_v4


def _now_ts() -> float:
    return time.time()


# --------------------------------------------------------------------------- #
# Control-plane actions (called from session hooks)
# --------------------------------------------------------------------------- #
def request_acl_for_session(db: DbSession, session: SessionModel) -> ACLRule | None:
    """session.opened -> create the rule row + enqueue an `add` task."""
    if not session.ip_address:
        logger.warning("session %s has no client ip; no ACL rule created", session.id)
        return None

    existing = db.scalar(
        select(ACLRule).where(ACLRule.session_id == session.id)
    )
    if existing is not None:
        return existing  # idempotent (hook may fire twice)

    rule = ACLRule(
        id=uuid.uuid4().hex,
        session_id=session.id,
        user_id=session.user_id,
        client_ip=session.ip_address,
        resource=settings.acl_protected_resource,
        ipset_name=_ipset_for(session.ip_address),
        state=ACLState.PENDING,
        enforcement=get_enforcer().name,
        created_at=utcnow(),
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)

    store.enqueue_task(
        {
            "op": "add",
            "task_id": uuid.uuid4().hex,
            "rule_id": rule.id,
            "ip": rule.client_ip,
            "ipset": rule.ipset_name,
            "enqueued_at": _now_ts(),
        }
    )
    store.publish_event(
        "acl.requested",
        {"rule_id": rule.id, "session_id": session.id, "ip": rule.client_ip},
    )
    logger.info("acl requested rule=%s session=%s ip=%s", rule.id, session.id, rule.client_ip)
    return rule


def remove_acl_for_session(
    db: DbSession, session_id: str, *, reason: str
) -> ACLRule | None:
    """session.closed -> flip the rule to REMOVING + enqueue a `remove` task."""
    rule = db.scalar(select(ACLRule).where(ACLRule.session_id == session_id))
    if rule is None:
        return None
    if rule.state in (ACLState.REMOVING, ACLState.REMOVED):
        return rule

    rule.state = ACLState.REMOVING
    rule.removal_reason = reason
    db.commit()
    db.refresh(rule)

    store.enqueue_task(
        {
            "op": "remove",
            "task_id": uuid.uuid4().hex,
            "rule_id": rule.id,
            "ip": rule.client_ip,
            "ipset": rule.ipset_name,
            "enqueued_at": _now_ts(),
        }
    )
    store.publish_event(
        "acl.revoking",
        {"rule_id": rule.id, "session_id": session_id, "reason": reason},
    )
    logger.info("acl revoking rule=%s session=%s reason=%s", rule.id, session_id, reason)
    return rule


# --------------------------------------------------------------------------- #
# Reads (for the ACL endpoints + session-list enrichment)
# --------------------------------------------------------------------------- #
def get_rule(db: DbSession, rule_id: str) -> ACLRule | None:
    return db.get(ACLRule, rule_id)


def get_rule_for_session(db: DbSession, session_id: str) -> ACLRule | None:
    return db.scalar(select(ACLRule).where(ACLRule.session_id == session_id))


def list_rules(
    db: DbSession, *, include_removed: bool = False, state: str | None = None,
    limit: int = 200,
) -> list[ACLRule]:
    stmt = select(ACLRule).order_by(ACLRule.created_at.desc()).limit(limit)
    if state is not None:
        stmt = stmt.where(ACLRule.state == state)
    elif not include_removed:
        stmt = stmt.where(ACLRule.state != ACLState.REMOVED)
    return list(db.scalars(stmt))


def count_active(db: DbSession) -> int:
    return db.scalar(
        select(func.count()).select_from(ACLRule).where(
            ACLRule.state == ACLState.ACTIVE
        )
    ) or 0


def acl_status_map(db: DbSession, session_ids: list[str]) -> dict[str, str]:
    """{session_id: acl_state} for the Live Sessions table's ACL column."""
    if not session_ids:
        return {}
    rows = db.execute(
        select(ACLRule.session_id, ACLRule.state).where(
            ACLRule.session_id.in_(session_ids)
        )
    ).all()
    return {session_id: state for session_id, state in rows}


def average_latencies(db: DbSession) -> tuple[float | None, float | None]:
    auth = db.scalar(
        select(func.avg(ACLRule.authorization_latency_ms)).where(
            ACLRule.authorization_latency_ms.is_not(None)
        )
    )
    revoke = db.scalar(
        select(func.avg(ACLRule.revocation_latency_ms)).where(
            ACLRule.revocation_latency_ms.is_not(None)
        )
    )
    return (
        round(float(auth), 2) if auth is not None else None,
        round(float(revoke), 2) if revoke is not None else None,
    )
