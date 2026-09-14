"""
Account-level RISK lockout -- Module 7 hardening (2026-09-14) unit tests.

Exercises app.services.trust_score.risk_lockout directly (tier escalation,
the cap-and-repeat behaviour past the 3rd offense, the 24h-from-first-offense
reset window, and per-user scoping) against the fake Redis client the
`fake_redis` autouse fixture in conftest.py installs -- no HTTP/DB needed
for these. The integration-level tests (this actually firing off a direct
HIGH-risk crossing, NOT firing for a MEDIUM-reverify failure, the
enumeration-safe /auth/login ordering, and cross-device/User-Agent scope)
live in test_continuous_trust.py, alongside the rest of Module 7's
integration coverage.
"""
from __future__ import annotations

from app.core.config import get_settings
from app.services.trust_score import risk_lockout

settings = get_settings()


def test_first_offense_locks_for_tier1_duration():
    assert risk_lockout.lockout_remaining_seconds(1) is None

    risk_lockout.record_risk_offense(1)

    remaining = risk_lockout.lockout_remaining_seconds(1)
    assert remaining is not None
    assert remaining <= settings.risk_lockout_tier1_hours * 3600
    assert remaining > (settings.risk_lockout_tier1_hours - 1) * 3600


def test_escalates_through_tiers_then_caps_and_repeats():
    """1st -> tier1, 2nd -> tier2, 3rd -> tier3 (the cap), and a 4th offense
    in the same window ALSO gets tier3 -- it must never stop enforcing."""
    user_id = 2

    risk_lockout.record_risk_offense(user_id)
    assert risk_lockout.lockout_remaining_seconds(user_id) <= settings.risk_lockout_tier1_hours * 3600

    risk_lockout.record_risk_offense(user_id)
    remaining = risk_lockout.lockout_remaining_seconds(user_id)
    assert remaining > settings.risk_lockout_tier1_hours * 3600
    assert remaining <= settings.risk_lockout_tier2_hours * 3600

    risk_lockout.record_risk_offense(user_id)
    remaining = risk_lockout.lockout_remaining_seconds(user_id)
    assert remaining > settings.risk_lockout_tier2_hours * 3600
    assert remaining <= settings.risk_lockout_tier3_hours * 3600

    # 4th offense: still tier3's duration, not unlocked and not escalated
    # further -- the cap repeats rather than either giving up or growing.
    risk_lockout.record_risk_offense(user_id)
    remaining = risk_lockout.lockout_remaining_seconds(user_id)
    assert remaining is not None
    assert remaining <= settings.risk_lockout_tier3_hours * 3600
    assert remaining > (settings.risk_lockout_tier3_hours - 1) * 3600


def test_scoped_per_user():
    """Locking one account must never affect a different one."""
    risk_lockout.record_risk_offense(10)
    assert risk_lockout.lockout_remaining_seconds(10) is not None
    assert risk_lockout.lockout_remaining_seconds(11) is None


def test_escalation_window_resets_after_it_elapses():
    """The 24h (risk_lockout_window_hours) escalation window is anchored to
    the FIRST offense -- once it has elapsed, the very next offense must be
    treated as a fresh 1st offense (tier1 duration), not a continuation of
    the old streak. Simulated here by directly expiring the underlying
    Redis counter key (equivalent to real time having passed), the same
    technique used elsewhere in this suite for time-based Redis TTL
    behaviour, rather than actually waiting out the window."""
    from app.core.redis_client import get_redis

    user_id = 20
    risk_lockout.record_risk_offense(user_id)
    risk_lockout.record_risk_offense(user_id)
    remaining = risk_lockout.lockout_remaining_seconds(user_id)
    assert remaining > settings.risk_lockout_tier1_hours * 3600  # confirms it escalated to tier2

    # Simulate the 24h window having elapsed: the counter key expires.
    get_redis().delete(risk_lockout._offense_key(user_id))

    risk_lockout.record_risk_offense(user_id)
    remaining = risk_lockout.lockout_remaining_seconds(user_id)
    assert remaining is not None
    assert remaining <= settings.risk_lockout_tier1_hours * 3600
    assert remaining > (settings.risk_lockout_tier1_hours - 1) * 3600


def test_redis_outage_fails_open(monkeypatch):
    """Best-effort/fail-open, same policy as every other auxiliary Redis
    mechanism in this codebase -- a Redis error must never itself block a
    login, and must never crash the caller recording the offense."""
    import redis as redis_module

    class _BrokenRedis:
        def incr(self, *a, **k):
            raise redis_module.RedisError("simulated outage")

        def ttl(self, *a, **k):
            raise redis_module.RedisError("simulated outage")

        def expire(self, *a, **k):
            raise redis_module.RedisError("simulated outage")

        def set(self, *a, **k):
            raise redis_module.RedisError("simulated outage")

    monkeypatch.setattr(risk_lockout, "get_redis", lambda: _BrokenRedis())

    risk_lockout.record_risk_offense(30)  # must not raise
    assert risk_lockout.lockout_remaining_seconds(30) is None  # fails open, not locked
