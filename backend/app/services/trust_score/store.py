"""
Redis side of the Trust Score engine — Module 5.

The failed-login burst counter. Section 6 finalized this as Redis-backed
(not a Postgres table) — consistent with how Modules 3/4 already use Redis
for ephemeral, time-bound state.

  key      ztsaacm:failed_logins:{user_id}
  write    INCR on every failed POST /auth/login for a *known* username, then
           (re)set a 15-minute TTL so it auto-expires with no cleanup job
  read     GET at a successful login to decide the -15 penalty

Also, since 2026-09-17 (Module 7 hardening — see continuous.py and this
project's Project status.md), a second, purely auxiliary key tracks whether
this same burst has already fired the mid-session ``multiple_failed_logins``
event against any of this user's ACTIVE sessions elsewhere:

  key      ztsaacm:failed_logins_fired:{user_id}
  write    set (NX-equivalent via an existence check) the first time this
           burst is observed at/above trust_failed_login_threshold, with the
           SAME remaining TTL as the counter above — so it expires together
           with the window it belongs to, exactly like
           app.services.trust_score.request_rate's "fired" flag for
           abnormal_request_rate, and for the identical reason: without it,
           every failed attempt past the threshold within the same window
           would re-fire the mid-session event again.
  read     check_and_mark_burst_fired() — see below.
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


def _fired_key(user_id: int) -> str:
    return f"{_PREFIX}:failed_logins_fired:{user_id}"


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


def check_and_mark_burst_fired(user_id: int) -> bool:
    """Called from record_failed_login_attempt (trust_score/service.py),
    right after record_failed_login above. Returns True the first time this
    burst is observed at/above trust_failed_login_threshold; False otherwise
    (below threshold, or this same burst already fired once). Mirrors
    app.services.trust_score.request_rate.check_and_mark_fired's exact
    fire-once-per-window pattern. Fail-open: a Redis error returns False
    (never fires on an infrastructure blip, same policy as every other
    auxiliary Redis mechanism in this codebase)."""
    try:
        r = get_redis()
        raw = r.get(_key(user_id))
        count = int(raw) if raw is not None else 0
        if count < settings.trust_failed_login_threshold:
            return False
        if r.exists(_fired_key(user_id)):
            return False
        ttl = r.ttl(_key(user_id))
        ttl = ttl if ttl and ttl > 0 else max(60, settings.trust_failed_login_window_minutes * 60)
        r.set(_fired_key(user_id), "1", ex=ttl)
        return True
    except redis.RedisError:
        logger.warning("redis failed-login burst check failed for user %s", user_id, exc_info=True)
        return False
    except (TypeError, ValueError):
        logger.warning("corrupt failed-login counter value for user %s", user_id)
        return False


def clear_failed_logins(user_id: int) -> None:
    try:
        get_redis().delete(_key(user_id), _fired_key(user_id))
    except redis.RedisError:
        logger.debug("redis clear_failed_logins failed for user %s", user_id, exc_info=True)
