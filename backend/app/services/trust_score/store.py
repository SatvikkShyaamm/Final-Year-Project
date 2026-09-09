"""
Redis side of the Trust Score engine — Module 5.

Only one thing lives here: the failed-login burst counter. Section 6 finalized
this as Redis-backed (not a Postgres table) — consistent with how Modules 3/4
already use Redis for ephemeral, time-bound state.

  key      ztsaacm:failed_logins:{user_id}
  write    INCR on every failed POST /auth/login for a *known* username, then
           (re)set a 15-minute TTL so it auto-expires with no cleanup job
  read     GET at a successful login to decide the -15 penalty
"""
from __future__ import annotations

import redis

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.redis_client import get_redis

logger = get_logger(__name__)
settings = get_settings()

_PREFIX = "ztsaacm"


def _key(user_id: int) -> str:
    return f"{_PREFIX}:failed_logins:{user_id}"


def record_failed_login(user_id: int) -> int:
    """Increment the burst counter and refresh its TTL. Returns the new count."""
    window = max(60, settings.trust_failed_login_window_minutes * 60)
    try:
        r = get_redis()
        pipe = r.pipeline()
        pipe.incr(_key(user_id))
        pipe.expire(_key(user_id), window)
        count, _ = pipe.execute()
        return int(count)
    except redis.RedisError:
        logger.warning("redis record_failed_login failed for user %s", user_id, exc_info=True)
        return 0


def failed_login_count(user_id: int) -> int:
    try:
        value = get_redis().get(_key(user_id))
        return int(value) if value is not None else 0
    except (redis.RedisError, ValueError):
        logger.warning("redis failed_login_count failed for user %s", user_id, exc_info=True)
        return 0


def clear_failed_logins(user_id: int) -> None:
    try:
        get_redis().delete(_key(user_id))
    except redis.RedisError:
        logger.debug("redis clear_failed_logins failed for user %s", user_id, exc_info=True)
