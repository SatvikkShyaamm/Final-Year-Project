"""
Real Passive Network Detection -- Module 7 hardening, Section 18 of
MASTER_PROJECT_CONTEXT.docx (FINALIZED 2026-09-14, implemented 2026-09-15).

Closes the gap the rest of Module 7 (continuous.py) leaves open: nothing
passively watches a real user's own session and notices, on its own, that
their real IP changed, their real device is different, they're really on a
VPN, or their real request volume spiked. Before this module, the ONLY thing
that ever created a mid-session security event was an admin manually calling
POST /security/events. This module is the second, automatic caller of that
exact same ``continuous.record_event`` pipeline -- nothing about scoring, MFA
re-triggering, or revocation changes here; only *what causes* an event does.

Why not the WebSocket (see Section 18's own "Mechanism" writeup): the session
IS the WebSocket connection (Module 3) -- its real IP/User-Agent are read
exactly once, at that socket's handshake, and cannot change again on that
same connection without the connection itself dropping. So the frontend
instead polls a small authenticated HTTP endpoint (POST /security/heartbeat,
app/api/v1/endpoints/security.py) on its own timer while a session is open --
every such request naturally carries the browser's real, current IP/UA,
regardless of the long-lived WS connection's own fixed values.

Comparison is against "last observed at the previous heartbeat", NOT the
immutable login-time baseline (``sessions.ip_address`` / ``sessions.
user_agent``, set once at WS handshake and never touched here) -- so an
event fires once per actual change, not once per poll. The first heartbeat
of a session silently seeds this state and fires nothing (it is simply
confirming what the login baseline already established, in the common
case).

Storage: one Redis key per session for the last-observed IP/UA pair
(mirrors the Module 5 failed-login burst counter's style -- app.services.
trust_score.store -- and every other auxiliary Redis mechanism in this
codebase: best-effort / fail-open on a Redis outage, never fail closed and
never raise):

  ztsaacm:heartbeat:last:{session_id}   JSON {"ip": ..., "ua": ...} -- the
                                         last-observed IP/User-Agent pair.
                                         Absence means "never seeded yet"
                                         (this session's first heartbeat).

Carries a pure safety-net TTL (settings.heartbeat_state_ttl_seconds); the
AUTHORITATIVE clear happens the instant the session actually ends, via the
same session_closed hook Module 4's ACL layer already uses for its own
session-scoped Redis state -- wired in wiring.py alongside the existing
session_opened hook Module 5 registers there.

abnormal_request_rate itself (2026-09-15, redesigned the same day as this
module's initial implementation): the counting and "fire once per window"
bookkeeping now live in app.services.trust_score.request_rate, NOT here --
that module is instrumented from app.api.deps.get_current_user, so every
non-GET/HEAD/OPTIONS authenticated call anywhere in the app counts, not
only calls to the heartbeat endpoint (see request_rate.py's own docstring
for the full reasoning). This module's only remaining role for that
detector is asking request_rate.check_and_mark_fired() whether the current
window has just crossed the threshold, and firing the continuous-
evaluation event through the same pipeline as everything else here if so.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

import redis
from sqlalchemy.orm import Session as DbSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.redis_client import get_redis
from app.models.security_event import SecurityEventSource, SecurityEventType
from app.services.trust_score import continuous as continuous_service
from app.services.trust_score import request_rate
from app.services.trust_score.evaluator import in_any_cidr

logger = get_logger(__name__)
settings = get_settings()

_PREFIX = "ztsaacm"


def _last_key(session_id: str) -> str:
    return f"{_PREFIX}:heartbeat:last:{session_id}"


@dataclass
class HeartbeatResult:
    session_id: str
    seeded: bool
    events: list[continuous_service.ContinuousEvalResult] = field(default_factory=list)

    @property
    def session_terminated(self) -> bool:
        return any(e.should_close_session for e in self.events)


def _load_last_observed(session_id: str) -> tuple[str | None, str | None] | None:
    """None means "never seeded" (this session's first heartbeat). Otherwise
    (ip, ua) as last observed -- either element may itself be None if the
    real value genuinely was absent (e.g. no User-Agent header)."""
    try:
        raw = get_redis().get(_last_key(session_id))
    except redis.RedisError:
        logger.warning(
            "redis heartbeat last-observed read failed session=%s -- treating as unseeded",
            session_id, exc_info=True,
        )
        # Fail-open in the safe direction: worst case this re-seeds instead
        # of firing a spurious event on a Redis blip, matching this
        # codebase's established "never fail closed" auxiliary-Redis policy.
        return None
    if raw is None:
        return None
    try:
        data = json.loads(raw)
        return data.get("ip"), data.get("ua")
    except (ValueError, TypeError):
        logger.warning("corrupt heartbeat last-observed value session=%s", session_id)
        return None


def _store_last_observed(session_id: str, ip: str | None, ua: str | None) -> None:
    try:
        get_redis().set(
            _last_key(session_id),
            json.dumps({"ip": ip, "ua": ua}),
            ex=max(60, settings.heartbeat_state_ttl_seconds),
        )
    except redis.RedisError:
        logger.warning(
            "redis heartbeat last-observed write failed session=%s", session_id, exc_info=True
        )


def clear_session_state(session_id: str) -> None:
    """Called from the session_closed hook (see wiring.py) -- the
    authoritative clear of this module's Redis state AND request_rate's
    (2026-09-15: the request-rate counter moved to that module, but it is
    still scoped to the session's own lifetime, so it is still cleared from
    right here), mirroring the ACL ref-count pattern of tearing down
    session-scoped state the moment the session actually ends, rather than
    relying solely on the TTL."""
    try:
        get_redis().delete(_last_key(session_id))
    except redis.RedisError:
        logger.debug(
            "redis heartbeat state clear failed session=%s (TTL will still expire it)",
            session_id, exc_info=True,
        )
    request_rate.clear_session_state(session_id)


def _fire(
    db: DbSession, session_id: str, event_type: str, ip_address: str | None
) -> continuous_service.ContinuousEvalResult:
    return continuous_service.record_event(
        db,
        session_id=session_id,
        event_type=event_type,
        ip_address=ip_address,
        source=SecurityEventSource.AUTO,
    )


def record_heartbeat(
    db: DbSession, *, session_id: str, ip_address: str | None, user_agent: str | None
) -> HeartbeatResult:
    """
    The Section 18 detector proper. Compares this heartbeat's real IP/
    User-Agent against the session's own last-observed value (never the
    immutable login baseline), firing the matching continuous-evaluation
    event through the unchanged ``continuous.record_event`` pipeline on a
    genuine difference, then independently asks request_rate whether this
    session's request-rate window has just crossed its threshold (that
    counter itself is bumped elsewhere, on every non-GET authenticated call
    anywhere in the app -- see app.services.trust_score.request_rate -- not
    only by this heartbeat call).

    If an IP change lands on an address in either VPN CIDR list (Section 6's
    existing approved/known-bad lists, reused unchanged), the more specific
    ``vpn_detected`` classification is fired instead of a plain
    ``ip_change`` -- one event per genuine change, not two competing
    penalties for the same thing. An IP change and a User-Agent change in
    the same heartbeat are independent signals and both fire.

    Stops firing further events for this heartbeat the moment one of them
    revokes the session (SecurityEventAction.REVOKE) -- there is nothing
    left to re-evaluate once the session is gone; ``continuous.record_event``
    itself would raise SessionNotActive on the next call anyway, this just
    avoids relying on that as control flow.

    Raises ``continuous_service.SessionNotFound`` /
    ``continuous_service.SessionNotActive`` only if the session was already
    gone before this heartbeat even started (a race with a concurrent
    admin/idle/logout termination) -- the caller (the endpoint) is expected
    to have just resolved this exact session_id as the caller's own current
    ACTIVE session, so this should be rare in practice.
    """
    ua = (user_agent or "").strip() or None
    ip = ip_address or None

    events: list[continuous_service.ContinuousEvalResult] = []
    last = _load_last_observed(session_id)
    seeded = last is None

    if seeded:
        _store_last_observed(session_id, ip, ua)
    else:
        last_ip, last_ua = last  # type: ignore[misc]  # last is not None here
        terminated = False

        if ip is not None and ip != last_ip:
            if in_any_cidr(ip, settings.trust_approved_vpn_cidrs) or in_any_cidr(
                ip, settings.trust_known_vpn_cidrs
            ):
                event_type = SecurityEventType.VPN_DETECTED
            else:
                event_type = SecurityEventType.IP_CHANGE
            result = _fire(db, session_id, event_type, ip)
            events.append(result)
            terminated = result.should_close_session

        if not terminated and ua is not None and ua != last_ua:
            result = _fire(db, session_id, SecurityEventType.UNKNOWN_DEVICE, ip)
            events.append(result)
            terminated = result.should_close_session

        if not terminated:
            _store_last_observed(session_id, ip, ua)

    # Independent of the IP/UA comparison above -- this session's
    # request-rate window (counted continuously from every non-GET
    # authenticated call across the whole app, not just this heartbeat
    # call -- see app.services.trust_score.request_rate) may have crossed
    # its threshold since the last time anything checked. Skipped once this
    # same heartbeat has already ended the session.
    if not events or not events[-1].should_close_session:
        if request_rate.check_and_mark_fired(session_id):
            try:
                events.append(
                    _fire(db, session_id, SecurityEventType.ABNORMAL_REQUEST_RATE, ip)
                )
            except continuous_service.SessionNotActive:
                # Ended concurrently (e.g. an admin terminate landed between
                # the IP/UA branch above and here) -- nothing left to record.
                pass

    return HeartbeatResult(session_id=session_id, seeded=seeded, events=events)
