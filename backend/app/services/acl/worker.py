"""
The L-PEP worker — Module 4 (base paper's data plane / task dispatcher).

Pulls ``{op, task_id, rule_id, ip, ipset, enqueued_at}`` tasks off the Redis
queue and, per task:

  add     INCR the IP ref-count; if it just went 0 -> 1, actually apply the
          kernel allow-list entry. Mark the rule ACTIVE and record the
          authorization latency.
  remove  DECR the ref-count; if it hit 0, actually remove the entry and clear
          the counter. Mark the rule REMOVED and record the revocation latency.

Ref-counting is what lets two sessions from one IP (two browser tabs) share a
single kernel entry: closing one tab must not revoke the other's access.

Runs either in-process (background task in app.main, single-container dev/demo)
or standalone (``python -m app.lpep`` on the enforcement host).
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session as DbSession

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.core.logging import get_logger
from app.models.acl import ACLRule, ACLState
from app.models.session import utcnow
from app.services.acl import store
from app.services.acl.enforcer import get_enforcer
from app.services.acl.fsm import InvalidACLTransition, assert_transition

logger = get_logger(__name__)
settings = get_settings()


def _elapsed_ms(enqueued_at: Any) -> int:
    try:
        return max(0, int((time.time() - float(enqueued_at)) * 1000))
    except (TypeError, ValueError):
        return 0


def _set_state(rule: ACLRule, target: str) -> None:
    try:
        assert_transition(rule.state, target)
    except InvalidACLTransition:
        logger.warning("acl rule %s: skip illegal %s -> %s", rule.id, rule.state, target)
        return
    rule.state = target


def process_task(db: DbSession, task: dict[str, Any]) -> None:
    """Apply one enforcement task. Safe to call from tests directly."""
    op = task.get("op")
    rule = db.get(ACLRule, task.get("rule_id", ""))
    if rule is None:
        store.publish_receipt(task.get("task_id", ""), "skipped", None)
        return

    enforcer = get_enforcer()
    ip = task["ip"]
    ipset_name = task["ipset"]

    if op == "add":
        count = store.incr_refcount(ip)
        ok, err = (True, None)
        if count == 1:
            ok, err = enforcer.add(
                ipset_name, ip, ttl=settings.acl_entry_ttl_seconds
            )
        if not ok:
            store.decr_refcount(ip)  # keep the counter honest on failure
            _set_state(rule, ACLState.FAILED)
            rule.last_error = err
        else:
            _set_state(rule, ACLState.ACTIVE)
            if rule.state == ACLState.ACTIVE:  # transition wasn't blocked
                rule.activated_at = utcnow()
                rule.authorization_latency_ms = _elapsed_ms(task.get("enqueued_at"))
        db.commit()
        store.publish_receipt(
            task.get("task_id", ""),
            "done" if ok else "failed",
            rule.authorization_latency_ms,
        )
        store.publish_event(
            "acl.applied" if ok else "acl.failed",
            {"rule_id": rule.id, "ip": ip, "refcount": count},
        )

    elif op == "remove":
        count = store.decr_refcount(ip)
        err = None
        if count <= 0:
            _ok, err = enforcer.remove(ipset_name, ip)
            store.clear_refcount(ip)
        _set_state(rule, ACLState.REMOVED)
        rule.removed_at = utcnow()
        rule.revocation_latency_ms = _elapsed_ms(task.get("enqueued_at"))
        if err:
            rule.last_error = err
        db.commit()
        store.publish_receipt(
            task.get("task_id", ""), "done", rule.revocation_latency_ms
        )
        store.publish_event(
            "acl.removed", {"rule_id": rule.id, "ip": ip, "refcount": max(0, count)}
        )

    else:
        logger.warning("acl worker: unknown task op %r", op)


def drain_queue(db: DbSession) -> int:
    """Process every queued task now. Used by the test suite."""
    tasks = store.pop_all_tasks()
    for task in tasks:
        process_task(db, task)
    return len(tasks)


async def run_worker(stop_event: asyncio.Event) -> None:
    """Background loop for the in-process L-PEP (app.main lifespan)."""
    timeout = max(1, settings.l_pep_poll_timeout_seconds)
    logger.info("L-PEP worker started (backend=%s)", get_enforcer().name)
    while not stop_event.is_set():
        try:
            task = await run_in_threadpool(store.dequeue_task, timeout)
            if task is None:
                continue
            await run_in_threadpool(_process_task_with_own_session, task)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - one bad task must not kill the worker
            logger.warning("L-PEP worker iteration failed", exc_info=True)
    logger.info("L-PEP worker stopped")


def _process_task_with_own_session(task: dict[str, Any]) -> None:
    db = SessionLocal()
    try:
        process_task(db, task)
    finally:
        db.close()
