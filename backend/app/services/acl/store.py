"""
Redis side of the ACL layer — Module 4.

This is the base paper's "intermediate layer" for the data plane:

  * task queue      ztsaacm:acl:tasks         (LPUSH by the SS-PDP / hooks,
                                               BRPOP by the L-PEP worker)
  * completion bus  ztsaacm:acl:receipt:{id}  (worker PUBLISHes a receipt;
                                               used for latency analysis / M8)
  * ref-counts      ztsaacm:acl:refcount:{ip} (one kernel entry per IP no
                                               matter how many sessions share it)
  * kernel mirror   ztsaacm:acl:kernel:{set}  (what the *simulated* enforcer has
                                               "added"; the real ipset backend
                                               doesn't use this)
  * event stream    ztsaacm:events:acl        (acl.requested/applied/... for M8)

The Postgres ``acl_rules`` table is the source of truth for rule state. The
task queue, however, is load-bearing: a failure to enqueue is raised, not
swallowed, so a broken Redis surfaces instead of silently skipping enforcement
(which — correctly for Zero Trust — means the client never gets access).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import redis

from app.core.logging import get_logger
from app.core.redis_client import get_redis

logger = get_logger(__name__)

_PREFIX = "ztsaacm"
TASK_QUEUE = f"{_PREFIX}:acl:tasks"
EVENT_CHANNEL = f"{_PREFIX}:events:acl"


def _refcount_key(ip: str) -> str:
    return f"{_PREFIX}:acl:refcount:{ip}"


def _kernel_key(ipset_name: str) -> str:
    return f"{_PREFIX}:acl:kernel:{ipset_name}"


def _receipt_channel(task_id: str) -> str:
    return f"{_PREFIX}:acl:receipt:{task_id}"


# --------------------------------------------------------------------------- #
# Task queue (load-bearing — errors propagate)
# --------------------------------------------------------------------------- #
def enqueue_task(task: dict[str, Any]) -> None:
    get_redis().lpush(TASK_QUEUE, json.dumps(task))


def dequeue_task(timeout: int = 1) -> dict[str, Any] | None:
    """Blocking pop for the worker loop. Returns None on timeout."""
    result = get_redis().brpop(TASK_QUEUE, timeout=timeout)
    if result is None:
        return None
    _key, raw = result
    return json.loads(raw)


def pop_all_tasks() -> list[dict[str, Any]]:
    """Non-blocking drain — used by the test suite to process the queue."""
    r = get_redis()
    tasks: list[dict[str, Any]] = []
    while True:
        raw = r.rpop(TASK_QUEUE)
        if raw is None:
            return tasks
        tasks.append(json.loads(raw))


def queue_depth() -> int:
    try:
        return int(get_redis().llen(TASK_QUEUE))
    except redis.RedisError:
        return 0


# --------------------------------------------------------------------------- #
# IP reference counting
# --------------------------------------------------------------------------- #
def incr_refcount(ip: str) -> int:
    return int(get_redis().incr(_refcount_key(ip)))


def decr_refcount(ip: str) -> int:
    return int(get_redis().decr(_refcount_key(ip)))


def get_refcount(ip: str) -> int:
    try:
        value = get_redis().get(_refcount_key(ip))
        return int(value) if value is not None else 0
    except (redis.RedisError, ValueError):
        return 0


def clear_refcount(ip: str) -> None:
    try:
        get_redis().delete(_refcount_key(ip))
    except redis.RedisError:
        logger.warning("redis clear_refcount failed for %s", ip, exc_info=True)


# --------------------------------------------------------------------------- #
# Simulated kernel allow-list mirror
# --------------------------------------------------------------------------- #
def kernel_add(ipset_name: str, ip: str, *, ttl: int = 0) -> None:
    r = get_redis()
    r.sadd(_kernel_key(ipset_name), ip)
    if ttl > 0:
        # coarse TTL fail-safe: expire the whole mirror set (fine for a demo;
        # a real ipset expires per-entry).
        r.expire(_kernel_key(ipset_name), ttl)


def kernel_remove(ipset_name: str, ip: str) -> None:
    get_redis().srem(_kernel_key(ipset_name), ip)


def kernel_members(ipset_name: str) -> set[str]:
    try:
        return set(get_redis().smembers(_kernel_key(ipset_name)))
    except redis.RedisError:
        return set()


# --------------------------------------------------------------------------- #
# Receipts + events (best-effort)
# --------------------------------------------------------------------------- #
def publish_receipt(task_id: str, status: str, latency_ms: int | None) -> None:
    payload = {"task_id": task_id, "status": status, "latency_ms": latency_ms}
    try:
        get_redis().publish(_receipt_channel(task_id), json.dumps(payload))
    except redis.RedisError:
        logger.debug("redis publish_receipt failed for %s", task_id, exc_info=True)


def publish_event(event_type: str, payload: dict[str, Any]) -> None:
    message = {
        "type": event_type,
        "ts": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    try:
        get_redis().publish(EVENT_CHANNEL, json.dumps(message))
    except redis.RedisError:
        logger.warning("redis acl publish_event %s failed", event_type, exc_info=True)
