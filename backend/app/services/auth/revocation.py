"""
Server-side access-token revocation — Module 2/3 hardening.

Closes a gap identified during live testing (Project status.md, section 6b):
ending a session (logout, admin terminate, idle/max-lifetime sweep, and —
once built — a Module 7 risk-based revocation) previously only ended the
*session row* and its ACL rule. The JWT itself is stateless and was never
invalidated, so a copy of it made before termination kept authenticating a
brand-new session for the rest of its original lifetime.

Mechanism: every access token now carries a `jti` (app.core.security). When a
session closes for a "terminated for cause" reason (logout, admin terminate,
idle/max-lifetime sweep, or a future Module 7 risk-revocation -- see the
reason allowlist in wiring.py), this module's `on_session_closed` hook
(registered by `wiring.py`, same pattern as Module 4's ACL / Module 5's trust
score) looks up the `jti` + `exp` that were stamped onto that session row when
it was opened, and adds the `jti` to a Redis denylist until the token would
have expired anyway. `get_current_user` and `resolve_ws_user` both check the
denylist after decoding a token, so a revoked token can no longer authenticate
a REST call or open a new session.

Deliberately NOT triggered by an ordinary WEBSOCKET_DISCONNECT (a closed tab
or a page refresh) -- that termination reason is excluded in wiring.py,
because a refresh while a session is active is documented, intended behaviour
(docs/architecture.md, Project status.md section 6b): the same still-valid
token reopening a fresh session on reload. Revoking on every disconnect would
silently break that and any legitimate multi-session use of one token.

Deliberately narrow: this revokes the *specific token that opened the
terminated session*, not every token the user holds — a session ending on one
device should not silently sign the user out on another. A token that never
opened a session (e.g. only ever used for REST calls) has no `jti` recorded on
any session row and so cannot be targeted this way; there is nothing to
terminate for it.

Best-effort like every other Redis use in this codebase (session store, ACL
ref-counts, trust-score failed-login counter): if Redis is unreachable, a
revocation write is dropped (logged) and a revocation check fails OPEN
(treats the token as not revoked) rather than locking everyone out because
Redis is down.
"""
from __future__ import annotations

from datetime import datetime

import redis

from app.core.logging import get_logger
from app.core.redis_client import get_redis
from app.models.session import utcnow

logger = get_logger(__name__)

_KEY_PREFIX = "ztsaacm:revoked_tokens:"


def _key(jti: str) -> str:
    return f"{_KEY_PREFIX}{jti}"


def revoke_access_token(jti: str | None, exp: datetime | None) -> None:
    """Denylist one token's `jti` until it would have expired anyway.

    A no-op if `jti`/`exp` is missing (a pre-revocation-era token, or a token
    that never opened a session) — there is nothing to key the denylist on.
    """
    if not jti or exp is None:
        return
    ttl_seconds = max(1, int((exp - utcnow()).total_seconds()))
    try:
        get_redis().set(_key(jti), "1", ex=ttl_seconds)
    except redis.RedisError:
        logger.warning("token revocation write failed for jti=%s", jti, exc_info=True)
    else:
        logger.info("access token revoked jti=%s ttl_seconds=%s", jti, ttl_seconds)


def is_token_revoked(jti: str | None) -> bool:
    """True if this `jti` has been revoked and the denylist entry hasn't
    expired yet. Missing `jti` (a pre-revocation-era token) is never
    considered revoked — there is no way to have denylisted it."""
    if not jti:
        return False
    try:
        return bool(get_redis().exists(_key(jti)))
    except redis.RedisError:
        logger.warning("token revocation check failed for jti=%s", jti, exc_info=True)
        return False


def clear_all_revocations_for_testing() -> None:
    """Test helper only — not used by app code."""
    try:
        r = get_redis()
        keys = list(r.scan_iter(f"{_KEY_PREFIX}*"))
        if keys:
            r.delete(*keys)
    except redis.RedisError:
        pass
