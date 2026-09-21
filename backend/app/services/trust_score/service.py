"""
Trust Score control-plane logic — Module 5.

``evaluate_for_session`` is the ``session_opened`` hook target: it computes the
static score (Section 6), writes it onto the ``sessions`` row, and records the
per-factor breakdown in ``trust_score_factors``. It does NOT gate the session —
whether a MEDIUM/HIGH score means "require MFA" or "block" is Module 6's call.

No FastAPI imports. Called from the session hook (wiring.py), the failed-login
recorder (from the auth endpoint), and the trust endpoints.
"""
from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.session import Session as SessionModel
from app.models.session import utcnow
from app.models.trust_score import FactorKind, TrustScoreFactor
from app.services.auth import get_user_by_username
from app.services.trust_score import store
from app.services.trust_score.evaluator import evaluate
from app.services.trust_score.factors import Factor, TrustEvaluation

if TYPE_CHECKING:  # avoid the module-level circular-import risk noted below
    from app.services.trust_score.continuous import ContinuousEvalResult

logger = get_logger(__name__)
settings = get_settings()


# --------------------------------------------------------------------------- #
# session.opened hook target
# --------------------------------------------------------------------------- #
def evaluate_for_session(db: DbSession, session: SessionModel) -> TrustEvaluation | None:
    """Compute + persist the static trust score for a freshly-created session."""
    if session.trust_score is not None:
        return None  # idempotent — hook may fire twice

    evaluation = evaluate(
        db,
        user_id=session.user_id,
        ip_address=session.ip_address,
        user_agent=session.user_agent,
        login_time=session.created_at,
        exclude_session_id=session.id,
    )

    session.trust_score = evaluation.score
    session.risk_level = evaluation.risk_level
    for outcome in evaluation.outcomes:
        if not outcome.applied:
            continue
        db.add(
            TrustScoreFactor(
                id=uuid.uuid4().hex,
                session_id=session.id,
                user_id=session.user_id,
                factor_name=outcome.name,
                factor_kind=outcome.kind,
                weight_applied=outcome.weight,
                reason=outcome.reason,
            )
        )
    db.commit()
    return evaluation


def evaluate_login(
    db: DbSession, *, user_id: int, ip_address: str | None, user_agent: str | None
) -> TrustEvaluation:
    """Compute the static trust score for a *login attempt* — read-only, nothing
    persisted (the session-open hook stores the score when the WS connects a
    moment later). Module 6's /auth/login uses this to pick allow / MFA / block.
    Same algorithm and factors as ``evaluate_for_session``."""
    return evaluate(
        db,
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        login_time=utcnow(),
        exclude_session_id=None,
    )


def record_failed_login_attempt(
    db: DbSession, *, username: str
) -> list["ContinuousEvalResult"]:
    """Called from POST /auth/login on a credential failure. Only counts attempts
    against a *known* username (Section 6 keys the counter by user_id).

    Since 2026-09-17 (Module 7 hardening), this is also the single choke
    point for turning that same burst into a mid-session ``multiple_failed_
    logins`` security event against any of this user's currently ACTIVE
    sessions elsewhere -- an attacker guessing a live user's password
    should not be invisible to that user's already-open session, the same
    way Section 18's heartbeat detector made a real IP/device/VPN/rate
    change visible to it. Fires at most once per burst window
    (``store.check_and_mark_burst_fired``), exactly mirroring
    ``request_rate.check_and_mark_fired``'s own fire-once-per-window guard
    for ``abnormal_request_rate`` -- without it, every wrong password past
    the threshold within the same 15-minute window would re-fire the event
    again. Only affects sessions that are genuinely ACTIVE right now (read
    from the same Redis index ``request_rate.py`` already reuses); an
    account with nothing open anywhere simply has nothing this can touch,
    exactly as before this hardening pass.

    Returns the list of ``ContinuousEvalResult`` objects the caller
    (``POST /auth/login``) must push over each affected session's own
    WebSocket -- empty if the burst didn't just cross the threshold, or the
    account has no active session. This mirrors every other
    ``continuous.record_event`` call site (the manual admin Trigger, the
    heartbeat detector): the scoring/action logic itself stays fully sync
    and pushing the result is the async caller's job.

    ``continuous`` and ``session.store`` are imported locally, not at
    module level: this package's own ``__init__.py`` deliberately does not
    import ``continuous.py`` at all, to avoid eagerly pulling in the
    heavier ``mfa``/``session`` packages it composes at every import of
    *this* file (``service.py`` IS imported eagerly by ``__init__.py``) --
    the same precaution ``app.services.auth.wiring``'s ``on_session_closed``
    hook already takes for the identical reason (see that module)."""
    user = get_user_by_username(db, username)
    if user is None:
        return []
    count = store.record_failed_login(user.id)
    logger.info("failed login recorded user_id=%s count=%s", user.id, count)

    if not store.check_and_mark_burst_fired(user.id):
        return []

    from app.models.security_event import SecurityEventSource, SecurityEventType
    from app.services.session import store as session_store
    from app.services.trust_score import continuous

    results: list[continuous.ContinuousEvalResult] = []
    for session_id in session_store.active_session_ids_for_user(user.id):
        try:
            result = continuous.record_event(
                db,
                session_id=session_id,
                event_type=SecurityEventType.MULTIPLE_FAILED_LOGINS,
                source=SecurityEventSource.AUTO,
            )
        except (continuous.SessionNotFound, continuous.SessionNotActive):
            # Redis's active-session index and Postgres's own row can drift
            # by a moment (e.g. the session finished terminating in
            # between) -- skip it rather than raising past a failed login
            # attempt that must still return its ordinary 401 either way.
            continue
        logger.warning(
            "multiple-failed-logins auto-detected user_id=%s session_id=%s "
            "burst_count=%s new_score=%s new_risk=%s action=%s",
            user.id, session_id, count, result.new_score, result.new_risk, result.action,
        )
        results.append(result)
    return results


# --------------------------------------------------------------------------- #
# Reads (trust endpoints + session-list enrichment)
# --------------------------------------------------------------------------- #
def get_factors_for_session(db: DbSession, session_id: str) -> list[TrustScoreFactor]:
    return list(
        db.scalars(
            select(TrustScoreFactor)
            .where(TrustScoreFactor.session_id == session_id)
            .order_by(TrustScoreFactor.created_at.asc())
        )
    )


def get_user_score_history(
    db: DbSession, user_id: int, *, limit: int = 50
) -> list[SessionModel]:
    return list(
        db.scalars(
            select(SessionModel)
            .where(SessionModel.user_id == user_id)
            .order_by(SessionModel.created_at.desc())
            .limit(limit)
        )
    )


def average_trust_score(db: DbSession, *, active_only: bool = True) -> float | None:
    stmt = select(func.avg(SessionModel.trust_score)).where(
        SessionModel.trust_score.is_not(None)
    )
    if active_only:
        stmt = stmt.where(SessionModel.state == "active")
    value = db.scalar(stmt)
    return round(float(value), 2) if value is not None else None


# --------------------------------------------------------------------------- #
# Config catalogue (dashboard reference view)
# --------------------------------------------------------------------------- #
def factor_catalogue() -> list[dict]:
    s = settings
    return [
        {"factor_name": Factor.BASELINE, "factor_kind": FactorKind.BASELINE,
         "weight": s.trust_score_baseline, "applies_when": "always"},
        {"factor_name": Factor.KNOWN_DEVICE, "factor_kind": FactorKind.POSITIVE,
         "weight": s.trust_weight_known_device, "applies_when": "user has prior session history"},
        {"factor_name": Factor.KNOWN_IP, "factor_kind": FactorKind.POSITIVE,
         "weight": s.trust_weight_known_ip, "applies_when": "user has prior session history"},
        {"factor_name": Factor.TYPICAL_HOUR, "factor_kind": FactorKind.POSITIVE,
         "weight": s.trust_weight_typical_hour,
         "applies_when": f"user has >= {s.trust_typical_hour_min_sessions} prior sessions, "
                         "login within their learned typical-hour band"},
        {"factor_name": Factor.ATYPICAL_HOUR, "factor_kind": FactorKind.NEGATIVE,
         "weight": s.trust_weight_atypical_hour,
         "applies_when": f"user has >= {s.trust_typical_hour_min_sessions} prior sessions, "
                         "login outside their learned typical-hour band"},
        {"factor_name": Factor.APPROVED_VPN, "factor_kind": FactorKind.POSITIVE,
         "weight": s.trust_weight_approved_vpn, "applies_when": "always checked"},
        {"factor_name": Factor.UNKNOWN_DEVICE, "factor_kind": FactorKind.NEGATIVE,
         "weight": s.trust_weight_unknown_device, "applies_when": "user has prior session history"},
        {"factor_name": Factor.IP_CHANGED, "factor_kind": FactorKind.NEGATIVE,
         "weight": s.trust_weight_ip_changed, "applies_when": "user has prior session history"},
        {"factor_name": Factor.UNKNOWN_VPN, "factor_kind": FactorKind.NEGATIVE,
         "weight": s.trust_weight_unknown_vpn, "applies_when": "always checked"},
        {"factor_name": Factor.FAILED_LOGINS, "factor_kind": FactorKind.NEGATIVE,
         "weight": s.trust_weight_failed_logins,
         "applies_when": f">= {s.trust_failed_login_threshold} failed logins in "
                         f"{s.trust_failed_login_window_minutes} min"},
        {"factor_name": Factor.OFF_HOURS, "factor_kind": FactorKind.NEGATIVE,
         "weight": s.trust_weight_off_hours,
         "applies_when": f"login {s.trust_off_hours_start_hour:02d}:00-"
                         f"{s.trust_off_hours_end_hour:02d}:00 -- always checked "
                         "(org policy floor, independent of history)"},
    ]


def risk_bands() -> dict[str, str]:
    s = settings
    return {
        "LOW": f">= {s.trust_risk_low_min}",
        "MEDIUM": f"{s.trust_risk_medium_min}-{s.trust_risk_low_min - 1}",
        "HIGH": f"< {s.trust_risk_medium_min}",
    }
