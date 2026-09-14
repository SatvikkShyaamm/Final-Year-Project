"""
Account-level RISK lockout -- Module 7 hardening (2026-09-14).

Separate from, and unrelated to, the MFA account lockout in
app/services/mfa/service.py (that one counts wrong MFA codes across any
challenge; this one counts SESSIONS forcibly revoked for risk). Triggered
ONLY when continuous evaluation
(app.services.trust_score.continuous.record_event) revokes an
already-active session because its live score crossed straight into HIGH --
a direct HIGH crossing, i.e. TerminationReason.RISK_REVOKED with no
reverify chance ever offered.

Deliberately does NOT count as an offense:
  - a HIGH-risk *login* attempt getting its existing 403 (already blocked
    per-attempt, no session was ever created -- doesn't need this too), or
  - a MEDIUM-risk Module 7 reverify challenge that the user failed, was
    exhausted on, got MFA-account-locked during, never answered (expired),
    or that failed to even send (DeliveryFailed) -- all of these currently
    also end in the same TerminationReason.RISK_REVOKED as a direct HIGH
    crossing, but the *reason* is different: the risk itself was only
    MEDIUM, and the session only ended because a recoverable follow-up
    check wasn't cleared (or couldn't even be offered). That is not the
    same signal as the risk crossing straight into HIGH on its own, so it
    must not escalate this lockout. See
    app.services.trust_score.continuous.record_event -- the call into this
    module sits ONLY inside its direct-HIGH branch, never inside the
    reverify-then-reassigned-to-revoke branch.

Each qualifying offense blocks the ACCOUNT -- every device/User-Agent, not
just the one that misbehaved -- from logging in at all, for an escalating
cool-down: 1st offense -> settings.risk_lockout_tier1_hours, 2nd ->
settings.risk_lockout_tier2_hours, 3rd and every one after that (within the
same window) -> settings.risk_lockout_tier3_hours (the cap; it repeats, it
never stops enforcing). The whole streak resets to zero once
settings.risk_lockout_window_hours have passed since the FIRST offense in
it, regardless of how many escalations happened inside that window --
implemented as one Redis counter key whose TTL is set once, at creation,
and never renewed by later increments (so it stays anchored to the first
offense, not the most recent one).

Checked in POST /auth/login -- deliberately AFTER the password has already
been verified, never before, so a wrong-password probe can't be used to
learn whether an account is currently locked out (see the call site in
app/api/v1/endpoints/auth.py for the full enumeration-safety reasoning --
the same principle this codebase already applies to the MFA lockout).

Redis-backed, best-effort/fail-open like every other auxiliary Redis
mechanism in this codebase (session store, ACL ref-counts, the Module 5
failed-login burst counter, the token-revocation denylist, the MFA
lockout): a Redis outage lets a login through rather than locking every
account out over an infrastructure blip.

No admin "unlock" UI yet (deliberately deferred -- see Project status.md
and the project's account-risk-lockout plan doc). The documented fallback
if you get stuck (including as the only admin account) is clearing the
Redis keys by hand:

    redis-cli DEL ztsaacm:risk_lockout:<user_id> ztsaacm:risk_offense:<user_id>
"""
from __future__ import annotations

import redis

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.redis_client import get_redis

logger = get_logger(__name__)
settings = get_settings()


def _offense_key(user_id: int) -> str:
    return f"ztsaacm:risk_offense:{user_id}"


def _lockout_key(user_id: int) -> str:
    return f"ztsaacm:risk_lockout:{user_id}"


def _tier_duration_seconds(tier: int) -> int:
    """`tier` is 1-indexed -- the 1st, 2nd, 3rd(+) qualifying offense inside
    the current 24h-from-first-offense window. Tier 3 is the cap: a 4th,
    5th, ... offense in the same window also gets tier 3's duration, it
    never stops enforcing."""
    s = settings
    if tier <= 1:
        return max(1, s.risk_lockout_tier1_hours) * 3600
    if tier == 2:
        return max(1, s.risk_lockout_tier2_hours) * 3600
    return max(1, s.risk_lockout_tier3_hours) * 3600


def lockout_remaining_seconds(user_id: int) -> int | None:
    """None if the account is not currently risk-locked; otherwise how many
    seconds are left on the current lockout. Best-effort/fail-open -- see
    module docstring."""
    try:
        ttl = get_redis().ttl(_lockout_key(user_id))
    except redis.RedisError:
        logger.debug("redis risk lockout check failed for user_id=%s", user_id, exc_info=True)
        return None
    return ttl if ttl and ttl > 0 else None


def record_risk_offense(user_id: int) -> None:
    """Call exactly once per qualifying offense -- a session revoked because
    continuous evaluation pushed its live score straight into HIGH. Bumps
    the escalation counter (creating it, and starting its
    risk_lockout_window_hours TTL, on the first offense in a streak -- that
    TTL is never touched again by later increments, so the window stays
    anchored to the first offense) and sets/renews the lockout key for the
    resulting tier's duration. Best-effort/fail-open, same policy as
    lockout_remaining_seconds above -- a Redis outage means this offense
    simply isn't recorded, rather than raising and blocking the caller's
    own (already-decided) session revocation."""
    try:
        r = get_redis()
        key = _offense_key(user_id)
        tier = r.incr(key)
        if tier == 1:
            r.expire(key, max(1, settings.risk_lockout_window_hours) * 3600)
        duration = _tier_duration_seconds(tier)
        r.set(_lockout_key(user_id), str(tier), ex=duration)
        logger.warning(
            "account-level risk lockout tripped user_id=%s tier=%d duration_s=%d "
            "(session revoked for a direct HIGH-risk crossing)",
            user_id, tier, duration,
        )
    except redis.RedisError:
        logger.debug("redis risk offense record failed for user_id=%s", user_id, exc_info=True)
