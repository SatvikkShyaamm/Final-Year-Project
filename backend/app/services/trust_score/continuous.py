"""
Continuous Trust Evaluation -- Module 7.

Composes the existing trust_score + mfa + session services to recalculate an
ACTIVE session's trust score in response to a security-relevant event
observed mid-session (Section 8 of MASTER_PROJECT_CONTEXT.docx: "converts the
initial/static Trust Score into a DYNAMIC Trust Score, recalculated during an
active session in response to security-relevant events (VPN change, IP
change, abnormal download, abnormal request rate, etc.)"), and carries out
the resulting risk-based action:

    action     new risk band   what happens
    --------   -------------   --------------------------------------------
    none       LOW             nothing beyond recording the event + new score
    reverify   MEDIUM          an mfa_challenges row (reason=risk_retrigger,
                                scoped to this session_id) is created and
                                emailed; the caller pushes it down the
                                session's live WebSocket. A re-verification
                                already pending for this session is reused,
                                not duplicated -- one outstanding challenge
                                per session at a time.
    revoke     HIGH            the session is terminated
                                (TerminationReason.RISK_REVOKED) -- ACL
                                removal and token revocation follow for free
                                via the existing session_closed hooks
                                (app/services/acl/wiring.py,
                                app/services/auth/wiring.py). A failed
                                re-verification email send is *also* treated
                                as revoke (fail safe, not fail open: if the
                                user can't be reached to re-verify, a
                                MEDIUM-risk session must not be left running
                                unchallenged). A DIRECT HIGH crossing (only
                                that -- not the reassigned email-failure
                                case just described) additionally trips the
                                account-level risk lockout added 2026-09-14
                                (see app.services.trust_score.risk_lockout),
                                blocking that account's next login(s) for an
                                escalating cool-down, AND (2026-09-16
                                hardening) cascades: every OTHER currently
                                active session on that same account is also
                                terminated immediately (TerminationReason.
                                ACCOUNT_LOCKED), not just the one that
                                crossed into HIGH -- an account the system
                                has just locked out of logging back in
                                shouldn't still have a live window open
                                somewhere else.

No separate service package -- per this project's own architectural note in
docs/architecture.md ("Continuous evaluation | Composition of trust_score +
mfa + acl services (Module 7), no separate service package"), this module
lives inside services/trust_score/ alongside the static engine it extends.

This module is sync, like every other service in this codebase. The caller
(the async POST /security/events endpoint, and /mfa/verify for the
failure/success side of an outstanding risk_retrigger challenge) is
responsible for the WebSocket push/close a result says to perform --
nothing here imports asyncio or ConnectionManager directly.

Re-verification reuses Module 6's email one-time-code mechanism
unchanged (``app.services.mfa.create_challenge``) -- per
MASTER_PROJECT_CONTEXT.docx Section 7 ("REVISED 2026-09-10") and
Project status.md section 11, TOTP is not reintroduced here or anywhere else.

Section 18 hardening (2026-09-15, "Real Passive Network Detection"): until
now the only thing that ever called ``record_event`` was an admin manually
posting to /security/events. ``app.services.trust_score.heartbeat`` is a new,
second caller -- a periodic authenticated heartbeat from the session's own
owner -- that calls this exact same function, unchanged, when it observes a
genuine mid-session IP/User-Agent change or an abnormal request rate. The
only new thing either caller must supply is ``source`` (audit-trail only,
see ``record_event``'s docstring) -- nothing about scoring, MFA
re-triggering, or revocation logic changed for this hardening pass.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.mfa import MFAChallenge, MFAChallengeReason, MFAChallengeStatus
from app.models.security_event import (
    SecurityEvent,
    SecurityEventAction,
    SecurityEventSource,
    SecurityEventType,
)
from app.models.session import SessionState, TerminationReason
from app.models.trust_score import FactorKind, RiskLevel, TrustScoreFactor
from app.services import mfa as mfa_service
from app.services import session as session_service
from app.services.trust_score import risk_lockout
from app.services.trust_score.evaluator import in_any_cidr
from app.services.trust_score.factors import Factor, classify_risk

logger = get_logger(__name__)
settings = get_settings()


class ContinuousTrustError(Exception):
    pass


class SessionNotFound(ContinuousTrustError):
    pass


class SessionNotActive(ContinuousTrustError):
    """The session already ended -- there is nothing left to re-evaluate."""


@dataclass
class ContinuousEvalResult:
    session_id: str
    user_id: int
    event_type: str
    weight_applied: int
    reason: str
    previous_score: int
    new_score: int
    previous_risk: str
    new_risk: str
    action: str
    security_event_id: str
    source: str  # "auto" (heartbeat detector) or "admin" (POST /security/events)
    mfa_challenge: MFAChallenge | None = None  # set when action == "reverify"

    @property
    def should_push_reverify(self) -> bool:
        return self.action == SecurityEventAction.REVERIFY and self.mfa_challenge is not None

    @property
    def should_close_session(self) -> bool:
        return self.action == SecurityEventAction.REVOKE


def classify_event(
    event_type: str, *, ip_address: str | None = None
) -> tuple[str, str, int, str]:
    """Map one Module 7 event type to (factor_name, factor_kind, SIGNED
    weight, reason). ip_address only matters for vpn_detected (classified
    against the same approved/known-bad VPN CIDR lists Module 5 checks at
    login -- app.core.config.trust_approved_vpn_cidrs /
    trust_known_vpn_cidrs); every other event type ignores it."""
    s = settings
    if event_type == SecurityEventType.IP_CHANGE:
        detail = f" to {ip_address}" if ip_address else ""
        return (
            Factor.IP_CHANGED, FactorKind.NEGATIVE, -s.trust_weight_ip_changed,
            f"Session IP changed{detail} mid-session",
        )
    if event_type == SecurityEventType.VPN_DETECTED:
        if ip_address and in_any_cidr(ip_address, s.trust_approved_vpn_cidrs):
            return (
                Factor.APPROVED_VPN, FactorKind.POSITIVE, s.trust_weight_approved_vpn,
                f"Traffic now routed through an approved VPN range ({ip_address})",
            )
        detail = f" ({ip_address})" if ip_address else ""
        return (
            Factor.UNKNOWN_VPN, FactorKind.NEGATIVE, -s.trust_weight_unknown_vpn,
            f"Traffic now routed through an unrecognised VPN/proxy{detail}",
        )
    if event_type == SecurityEventType.UNKNOWN_DEVICE:
        return (
            Factor.UNKNOWN_DEVICE, FactorKind.NEGATIVE, -s.trust_weight_unknown_device,
            "A new, unrecognised device signature was observed on this session",
        )
    if event_type == SecurityEventType.ABNORMAL_REQUEST_RATE:
        return (
            Factor.ABNORMAL_REQUEST_RATE, FactorKind.NEGATIVE,
            -s.trust_weight_abnormal_request_rate,
            "Request rate from this session is far above the user's normal pattern",
        )
    if event_type == SecurityEventType.LARGE_DOWNLOAD:
        return (
            Factor.LARGE_DOWNLOAD, FactorKind.NEGATIVE, -s.trust_weight_large_download,
            "An abnormally large data transfer was observed on this session",
        )
    if event_type == SecurityEventType.MULTIPLE_FAILED_LOGINS:
        return (
            Factor.FAILED_LOGINS, FactorKind.NEGATIVE, -s.trust_weight_failed_logins,
            "Multiple failed login attempts were observed for this user during an active session",
        )
    raise ValueError(f"unknown security event type: {event_type!r}")


def has_open_retrigger_challenge(db: DbSession, session_id: str) -> MFAChallenge | None:
    """The currently-pending Module 7 re-verification challenge for this
    session, if any -- used to avoid emailing a second code while one is
    already outstanding."""
    return db.scalar(
        select(MFAChallenge)
        .where(
            MFAChallenge.session_id == session_id,
            MFAChallenge.reason == MFAChallengeReason.RISK_RETRIGGER,
            MFAChallenge.status == MFAChallengeStatus.PENDING,
        )
        .order_by(MFAChallenge.created_at.desc())
        .limit(1)
    )


def pending_reverify_map(db: DbSession, session_ids: list[str]) -> dict[str, str]:
    """Batch lookup for the dashboard/session views: {session_id: "reverify_required"}
    for every session in `session_ids` that currently has an open risk_retrigger
    challenge. Mirrors app.services.acl.acl_status_map's batching shape."""
    if not session_ids:
        return {}
    rows = db.scalars(
        select(MFAChallenge.session_id).where(
            MFAChallenge.session_id.in_(session_ids),
            MFAChallenge.reason == MFAChallengeReason.RISK_RETRIGGER,
            MFAChallenge.status == MFAChallengeStatus.PENDING,
        )
    )
    return {sid: "reverify_required" for sid in rows if sid}


def record_event(
    db: DbSession,
    *,
    session_id: str,
    event_type: str,
    ip_address: str | None = None,
    source: str = SecurityEventSource.ADMIN,
) -> ContinuousEvalResult:
    """
    Ingest one security-relevant event for an ACTIVE session: recompute its
    trust score against its CURRENT value (not the static baseline -- this is
    the dynamic score Section 8 describes), persist the audit trail, and
    carry out the resulting risk-based action.

    `source` is purely an audit-trail tag (Section 18, 2026-09-15) --
    SecurityEventSource.ADMIN for the manual POST /security/events path
    (the default, matching this function's pre-2026-09-15 behaviour),
    SecurityEventSource.AUTO for the automatic heartbeat detector
    (app.services.trust_score.heartbeat). It changes nothing about the
    scoring, MFA re-triggering, or revocation logic below -- both paths call
    this exact function, unchanged, per Section 18's own design.

    Raises SessionNotFound / SessionNotActive if there is nothing left to
    re-evaluate (an unknown, or already-terminated, session).
    """
    session = session_service.get_session(db, session_id)
    if session is None:
        raise SessionNotFound(session_id)
    if session.state != SessionState.ACTIVE:
        raise SessionNotActive(session_id)
    if session.trust_score is None:
        # Should never happen (the session_opened hook always sets it before
        # the session is usable) -- a missing baseline must not crash
        # continuous evaluation.
        session.trust_score = settings.trust_score_baseline

    factor_name, factor_kind, weight, reason = classify_event(event_type, ip_address=ip_address)

    previous_score = session.trust_score
    previous_risk = session.risk_level or classify_risk(
        previous_score, low_min=settings.trust_risk_low_min,
        medium_min=settings.trust_risk_medium_min,
    )
    new_score = max(0, min(100, previous_score + weight))
    new_risk = classify_risk(
        new_score, low_min=settings.trust_risk_low_min, medium_min=settings.trust_risk_medium_min
    )

    session.trust_score = new_score
    session.risk_level = new_risk
    db.add(
        TrustScoreFactor(
            id=uuid.uuid4().hex,
            session_id=session.id,
            user_id=session.user_id,
            factor_name=factor_name,
            factor_kind=factor_kind,
            weight_applied=weight,
            reason=reason,
        )
    )

    action = SecurityEventAction.NONE
    mfa_challenge: MFAChallenge | None = None
    direct_high_crossing = False
    if new_risk == RiskLevel.HIGH:
        action = SecurityEventAction.REVOKE
        # Account-level risk lockout (2026-09-14 hardening): a direct HIGH
        # crossing -- not a MEDIUM reverify later reassigned to revoke, see
        # the DeliveryFailed branch below, which must NOT count -- is
        # exactly the "offense" the lockout escalates on. Recorded here,
        # before the DeliveryFailed reassignment further down even has a
        # chance to run, so that path can never be mistaken for this one.
        risk_lockout.record_risk_offense(session.user_id)
        direct_high_crossing = True
    elif new_risk == RiskLevel.MEDIUM:
        action = SecurityEventAction.REVERIFY
        mfa_challenge = has_open_retrigger_challenge(db, session.id)

    event = SecurityEvent(
        id=uuid.uuid4().hex,
        session_id=session.id,
        user_id=session.user_id,
        event_type=event_type,
        weight_applied=weight,
        reason=reason,
        previous_score=previous_score,
        new_score=new_score,
        previous_risk=previous_risk,
        new_risk=new_risk,
        action=action,
        source=source,
    )
    db.add(event)
    db.commit()
    db.refresh(session)
    db.refresh(event)

    logger.info(
        "continuous trust event session=%s type=%s score %s->%s risk %s->%s action=%s",
        session.id, event_type, previous_score, new_score, previous_risk, new_risk, action,
    )

    if action == SecurityEventAction.REVERIFY and mfa_challenge is None:
        try:
            mfa_challenge = mfa_service.create_challenge(
                db, user=session.user, reason=MFAChallengeReason.RISK_RETRIGGER,
                trust_score=new_score, risk_level=new_risk, session_id=session.id,
                ttl_minutes=settings.mfa_retrigger_ttl_minutes,
            )
        except mfa_service.DeliveryFailed:
            # Fail safe, not fail open: if the user can't be reached to
            # re-verify, a MEDIUM-risk session must not be left running
            # unchallenged.
            logger.warning(
                "risk re-verification email failed for session=%s -- revoking instead",
                session.id,
            )
            action = SecurityEventAction.REVOKE
            event.action = SecurityEventAction.REVOKE
            db.commit()

    if action == SecurityEventAction.REVOKE:
        session_service.terminate_session(db, session.id, reason=TerminationReason.RISK_REVOKED)
        # 2026-09-16 hardening: a direct HIGH crossing doesn't just end THIS
        # session -- it also just locked the whole account out of logging
        # back in (risk_lockout.record_risk_offense above). Leaving that
        # account's OTHER already-open sessions running would defeat the
        # point: an account the system has decided is too risky to let back
        # in shouldn't still have a live window open somewhere else. Called
        # AFTER this session's own terminate_session (not before): by the
        # time terminate_user_sessions below runs its own "still ACTIVE"
        # query, this session already flipped to TERMINATED with reason
        # RISK_REVOKED, so it's naturally excluded and keeps that reason --
        # terminate_session is idempotent and would otherwise have kept
        # whichever reason got there first. The DeliveryFailed-reassigned
        # revoke below (a MEDIUM reverify that couldn't even be emailed) is
        # NOT a direct crossing and correctly never sets
        # direct_high_crossing, so it never cascades either -- same scoping
        # risk_lockout.record_risk_offense already uses.
        if direct_high_crossing:
            session_service.terminate_user_sessions(
                db, session.user_id, reason=TerminationReason.ACCOUNT_LOCKED
            )

    return ContinuousEvalResult(
        session_id=session.id,
        user_id=session.user_id,
        event_type=event_type,
        weight_applied=weight,
        reason=reason,
        previous_score=previous_score,
        new_score=new_score,
        previous_risk=previous_risk,
        new_risk=new_risk,
        action=action,
        security_event_id=event.id,
        source=source,
        mfa_challenge=mfa_challenge,
    )


# --------------------------------------------------------------------------- #
# Reads (dashboard feed)
# --------------------------------------------------------------------------- #
def list_recent_events(
    db: DbSession,
    *,
    session_id: str | None = None,
    source: str | None = None,
    limit: int = 100,
) -> list[SecurityEvent]:
    stmt = select(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(limit)
    if session_id is not None:
        stmt = stmt.where(SecurityEvent.session_id == session_id)
    if source is not None:
        # Section 18 (2026-09-15): auto | admin -- filtered in SQL, before the
        # limit is applied, so this returns up to `limit` MATCHING rows
        # rather than filtering a limited, unfiltered page down further.
        stmt = stmt.where(SecurityEvent.source == source)
    return list(db.scalars(stmt))


def event_catalogue() -> dict:
    """The live event-type -> weight/action table, for the dashboard's
    reference view (mirrors trust_score.factor_catalogue / mfa_config)."""
    s = settings
    return {
        "event_types": list(SecurityEventType.ALL),
        "weights": {
            SecurityEventType.IP_CHANGE: -s.trust_weight_ip_changed,
            SecurityEventType.VPN_DETECTED: (
                f"+{s.trust_weight_approved_vpn} if the IP is in an approved VPN range, "
                f"else -{s.trust_weight_unknown_vpn}"
            ),
            SecurityEventType.UNKNOWN_DEVICE: -s.trust_weight_unknown_device,
            SecurityEventType.ABNORMAL_REQUEST_RATE: -s.trust_weight_abnormal_request_rate,
            SecurityEventType.LARGE_DOWNLOAD: -s.trust_weight_large_download,
            SecurityEventType.MULTIPLE_FAILED_LOGINS: -s.trust_weight_failed_logins,
        },
        "actions": {
            "none": "risk remains LOW after the event",
            "reverify": (
                "risk crosses into MEDIUM -- an emailed re-verification code is "
                "required (Module 6's email mechanism, reused; not TOTP)"
            ),
            "revoke": (
                "risk crosses into HIGH (or the re-verification email could not be "
                "sent) -- the session is terminated immediately (ACL removed, token "
                "revoked); a DIRECT HIGH crossing also locks the account out of "
                "future logins and immediately terminates every other active "
                "session on that same account"
            ),
        },
        "reverify_ttl_minutes": s.mfa_retrigger_ttl_minutes,
        # Section 18 (2026-09-15): the automatic heartbeat detector's own
        # timing, for the dashboard's reference view -- mirrors this
        # function's existing "live config, not hardcoded docs" purpose.
        "heartbeat": {
            "interval_seconds": s.heartbeat_interval_seconds,
        },
        # abnormal_request_rate counting (redesigned 2026-09-15, same day as
        # the initial implementation): split out of "heartbeat" above
        # because it is no longer heartbeat-specific -- every non-GET
        # authenticated call anywhere in the app counts now, not just calls
        # to the heartbeat endpoint. See app.services.trust_score.
        # request_rate for the mechanism.
        "request_rate": {
            "window_seconds": s.request_rate_window_seconds,
            "threshold": s.request_rate_threshold,
        },
    }
