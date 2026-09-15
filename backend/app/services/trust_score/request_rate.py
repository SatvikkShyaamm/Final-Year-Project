"""
abnormal_request_rate counting -- Module 7 hardening, Section 18 of
MASTER_PROJECT_CONTEXT.docx (redesigned 2026-09-15, same day as the initial
heartbeat-only implementation).

Section 18's own spec left the counting strategy an explicit open choice
between two options:

  Option A -- a lightweight dependency increments a Redis counter on every
              authenticated call, anywhere in the app, attributed to the
              caller's own current session.
  Option B -- only calls to the heartbeat endpoint itself are counted.

The first cut of this module shipped Option B (simplest to wire -- the
heartbeat handler already had a session_id in hand and did both the
increment and the threshold check in one place). This module replaces that
with Option A, per an explicit decision: instrumenting every authenticated
call is the more realistic passive detector, since a real abnormal-rate
attack (credential-stuffing a protected endpoint, scripted abuse of a data
export, etc.) has no reason to also hit the heartbeat endpoint -- Option B
could only ever notice a tight loop of heartbeat calls specifically, not an
actual abnormal-traffic pattern anywhere else in the app.

Left unscoped, Option A would also count an admin's own dashboard polling
(read-heavy, comparatively high-frequency) against the admin's own session
-- a real, demoable false positive, not just a theoretical one. So this
module counts only state-changing calls: GET/HEAD/OPTIONS requests (reads,
including all normal dashboard polling) are never counted at all; only
POST/PUT/PATCH/DELETE (state-changing or explicitly action-triggering
calls) count towards the threshold. This was chosen over "count everything
but exempt specific dashboard-polling routes by path" because it needs no
per-route allowlist to keep in sync as new read endpoints are added, and it
matches the underlying intuition directly: a burst of *state changes* is
what is actually suspicious about a compromised or scripted session, not a
burst of reads.

Where a call is attributed: the caller's own currently active session, via
app.services.session.store's existing per-user active-session index
(ztsaacm:user:{user_id}:sessions -- populated by register_active /
deregister_active, which already run inside create_session /
terminate_session; nothing about the session layer changes here). This is
a deliberate reuse of an existing index rather than a new cache -- see that
module's own docstring. Session layer -> trust_score dependency direction
is never introduced by this: this module reads that index, the session
layer knows nothing about this one (the same "trust_score -> session"
direction already established by wiring.py for the session_opened /
session_closed hooks).

Storage: two Redis keys per session, fixed-window, mirroring every other
auxiliary Redis mechanism in this codebase (best-effort / fail-open on a
Redis outage -- never fail closed, never raise, and never block or fail
the request that triggered the count):

  ztsaacm:reqrate:{session_id}         INCR + EXPIRE-if-new fixed-window
                                        counter of non-GET authenticated
                                        calls attributed to this session.
  ztsaacm:reqrate:fired:{session_id}   set once this window's count has
                                        already crossed the threshold and
                                        fired -- see check_and_mark_fired.

The "fired" flag exists because counting now happens continuously, from
many different call sites (any non-GET endpoint, via the FastAPI
dependency in app.api.deps), rather than atomically alongside a single
"did we just cross the threshold" check the way the old heartbeat-only
counter could do in one INCR call. Without it, every qualifying call past
the threshold within the same window would re-fire the event. With it, the
first call (heartbeat or otherwise) that observes the count at or above
the threshold fires exactly once; the flag carries the counter's own
remaining TTL, so it expires together with the window it belongs to.

record_authenticated_call is invoked from app.api.deps.get_current_user
for essentially every authenticated request in the app, so it is held to
this codebase's Redis fail-open discipline strictly enough that even a
malformed session_id or unexpected type could never raise past this
module -- the call site additionally wraps this in its own
contextlib.suppress(Exception) as a second safety net (see deps.py).

check_and_mark_fired is invoked from the heartbeat detector
(app.services.trust_score.heartbeat.record_heartbeat), which still owns
firing the actual continuous.record_event('abnormal_request_rate', ...)
call -- this module only tracks the count and the fired-this-window flag,
it never calls into continuous.py itself, to stay a "leaf" module within
trust_score (see continuous.py's own docstring on why heavier submodules
can't be imported eagerly from certain trust_score entry points without
risking a circular import).
"""
from __future__ import annotations

import redis

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.redis_client import get_redis
from app.services.session import store as session_store

logger = get_logger(__name__)
settings = get_settings()

_PREFIX = "ztsaacm"

# Reads never count -- see module docstring. HEAD/OPTIONS are included for
# completeness (browsers/tools issue them for CORS preflight and caching
# checks; they never represent a real state-changing action either).
_EXEMPT_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _key(session_id: str) -> str:
    return f"{_PREFIX}:reqrate:{session_id}"


def _fired_key(session_id: str) -> str:
    return f"{_PREFIX}:reqrate:fired:{session_id}"


def record_authenticated_call(user_id: int, method: str) -> None:
    """Called from app.api.deps.get_current_user for every authenticated
    request. No-ops for GET/HEAD/OPTIONS (reads, including all normal
    dashboard polling -- see module docstring). Otherwise resolves the
    caller's own current active session via app.services.session.store's
    existing per-user index and bumps that session's fixed-window
    request-rate counter. If the caller has no active session on record
    (a race at login/logout, or a Redis blip in the index itself) or more
    than one (multi-tab/multi-device -- rare, and this is a best-effort
    passive signal, not an authorization decision), this silently no-ops
    rather than guessing; the fail-open policy here is the same as every
    other auxiliary Redis mechanism in this codebase."""
    if method.upper() in _EXEMPT_METHODS:
        return
    try:
        session_id = session_store.active_session_id_for_user(user_id)
    except Exception:  # noqa: BLE001 -- see module docstring: must never raise
        logger.warning("request-rate: resolving active session failed user=%s", user_id, exc_info=True)
        return
    if session_id is None:
        return
    _bump(session_id)


def _bump(session_id: str) -> int:
    """Fixed-window counter -- identical INCR + EXPIRE-if-new pattern to
    app.services.trust_score.store.record_failed_login and the original
    heartbeat-only counter this replaces. Fail-open: a Redis error returns
    0, which can never cross request_rate_threshold, so an infrastructure
    blip silently disables this one detector rather than misfiring or
    blocking the request that triggered the count."""
    window = max(1, settings.request_rate_window_seconds)
    try:
        r = get_redis()
        pipe = r.pipeline()
        pipe.incr(_key(session_id))
        pipe.expire(_key(session_id), window, nx=True)
        count, _ = pipe.execute()
        return int(count)
    except redis.RedisError:
        logger.warning("redis request-rate counter failed session=%s", session_id, exc_info=True)
        return 0


def check_and_mark_fired(session_id: str) -> bool:
    """Called from the heartbeat detector. Returns True the first time this
    window's count is observed at or above request_rate_threshold; False
    otherwise (below threshold, or this window already fired once). See the
    module docstring for why a separate flag key is needed now that
    counting happens from many call sites instead of one. Fail-open: a
    Redis error returns False (never fires on an infrastructure blip)."""
    try:
        r = get_redis()
        raw = r.get(_key(session_id))
        count = int(raw) if raw is not None else 0
        if count < settings.request_rate_threshold:
            return False
        if r.exists(_fired_key(session_id)):
            return False
        ttl = r.ttl(_key(session_id))
        ttl = ttl if ttl and ttl > 0 else max(1, settings.request_rate_window_seconds)
        r.set(_fired_key(session_id), "1", ex=ttl)
        return True
    except redis.RedisError:
        logger.warning("redis request-rate check failed session=%s", session_id, exc_info=True)
        return False
    except (TypeError, ValueError):
        logger.warning("corrupt request-rate counter value session=%s", session_id)
        return False


def clear_session_state(session_id: str) -> None:
    """Called from heartbeat.clear_session_state, itself called from the
    session_closed hook (wiring.py) -- the authoritative clear of this
    module's Redis state, mirroring every other session-scoped Redis
    mechanism in this codebase rather than relying solely on the TTL."""
    try:
        get_redis().delete(_key(session_id), _fired_key(session_id))
    except redis.RedisError:
        logger.debug(
            "redis request-rate state clear failed session=%s (TTL will still expire it)",
            session_id, exc_info=True,
        )
