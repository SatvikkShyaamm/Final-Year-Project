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


def record_failed_login_attempt(db: DbSession, *, username: str) -> None:
    """Called from POST /auth/login on a credential failure. Only counts attempts
    against a *known* username (Section 6 keys the counter by user_id)."""
    user = get_user_by_username(db, username)
    if user is None:
        return
    count = store.record_failed_login(user.id)
    logger.info("failed login recorded user_id=%s count=%s", user.id, count)


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
         "applies_when": f"user has >= {s.trust_typical_hour_min_sessions} prior sessions"},
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
                         f"{s.trust_off_hours_end_hour:02d}:00, fallback when no hour history"},
    ]


def risk_bands() -> dict[str, str]:
    s = settings
    return {
        "LOW": f">= {s.trust_risk_low_min}",
        "MEDIUM": f"{s.trust_risk_medium_min}-{s.trust_risk_low_min - 1}",
        "HIGH": f"< {s.trust_risk_medium_min}",
    }
