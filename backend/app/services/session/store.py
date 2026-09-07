"""
Redis side of the session layer — Module 3.

Redis is the base paper's "intermediate layer". For sessions it holds:
  * a set of currently-active session ids            (fast "who's online" reads)
  * a per-user set of their active session ids
  * a small snapshot hash per session                (dashboard convenience)
  * a pub/sub channel of session open/close events   (consumed by Module 8)

The Postgres ``sessions`` table is the source of truth. Everything here is an
index / cache / notification, so every call is best-effort: if Redis is down we
log and carry on rather than failing the session operation.
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
ACTIVE_SET = f"{_PREFIX}:sessions:active"
EVENT_CHANNEL = f"{_PREFIX}:events:session"

# Safety-net TTL on the per-session snapshot hash so a missed close event can't
# leak keys forever. Comfortably longer than the max session lifetime.
_SNAPSHOT_TTL_SECONDS = 24 * 3600


def _session_key(session_id: str) -> str:
    return f"{_PREFIX}:session:{session_id}"


def _user_key(user_id: int) -> str:
    return f"{_PREFIX}:user:{user_id}:sessions"


def register_active(
    *, session_id: str, user_id: int, username: str | None,
    ip_address: str | None, created_at: datetime,
) -> None:
    try:
        r = get_redis()
        pipe = r.pipeline()
        pipe.sadd(ACTIVE_SET, session_id)
        pipe.sadd(_user_key(user_id), session_id)
        pipe.hset(
            _session_key(session_id),
            mapping={
                "id": session_id,
                "user_id": str(user_id),
                "username": username or "",
                "ip_address": ip_address or "",
                "state": "active",
                "created_at": created_at.isoformat(),
            },
        )
        pipe.expire(_session_key(session_id), _SNAPSHOT_TTL_SECONDS)
        pipe.execute()
    except redis.RedisError:
        logger.warning("redis register_active failed for session %s", session_id, exc_info=True)


def deregister_active(*, session_id: str, user_id: int) -> None:
    try:
        r = get_redis()
        pipe = r.pipeline()
        pipe.srem(ACTIVE_SET, session_id)
        pipe.srem(_user_key(user_id), session_id)
        pipe.delete(_session_key(session_id))
        pipe.execute()
    except redis.RedisError:
        logger.warning("redis deregister_active failed for session %s", session_id, exc_info=True)


def set_ws_connected(session_id: str, connected: bool) -> None:
    try:
        get_redis().hset(_session_key(session_id), "ws_connected", "1" if connected else "0")
    except redis.RedisError:
        logger.warning("redis set_ws_connected failed for session %s", session_id, exc_info=True)


def active_session_ids() -> set[str]:
    try:
        return set(get_redis().smembers(ACTIVE_SET))
    except redis.RedisError:
        logger.warning("redis active_session_ids failed", exc_info=True)
        return set()


def publish_event(event_type: str, payload: dict[str, Any]) -> None:
    """Fire-and-forget session event for the Module 8 dashboard to subscribe to."""
    message = {
        "type": event_type,
        "ts": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    try:
        get_redis().publish(EVENT_CHANNEL, json.dumps(message))
    except redis.RedisError:
        logger.warning("redis publish_event %s failed", event_type, exc_info=True)
