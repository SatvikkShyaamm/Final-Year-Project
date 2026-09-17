"""
Dashboard aggregation queries -- Module 8 (Security Dashboard).

Pure reads over Modules 2-7's own tables (plus their Redis-backed lockout
state) -- this module owns no state of its own and computes nothing that
isn't already true elsewhere in the system. No FastAPI imports; called from
app/api/v1/endpoints/dashboard.py.

Per Section 15 of MASTER_PROJECT_CONTEXT.docx ("Do NOT build only a static
dashboard with fake data"), every figure below is a real aggregate over
actual rows -- there is no synthetic/sample data path anywhere in this
module, including in the Analytics charts (a metric with no real historical
source, e.g. a multi-day failed-login trend, is simply not offered here
rather than fabricated -- see `login_activity`'s own docstring).
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from app.models.mfa import MFAChallengeStatus
from app.models.security_event import SecurityEvent, SecurityEventType
from app.models.session import Session as SessionModel
from app.models.session import SessionState, TerminationReason, utcnow
from app.models.trust_score import RiskLevel
from app.services import acl as acl_service
from app.services import mfa as mfa_service
from app.services import session as session_service
from app.services import trust_score as trust_score_service
from app.services.trust_score import risk_lockout


# --------------------------------------------------------------------------- #
# Dashboard Home (Section 5) -- one-shot stat cards
# --------------------------------------------------------------------------- #
def count_active_users(db: DbSession) -> int:
    return db.scalar(
        select(func.count(func.distinct(SessionModel.user_id))).where(
            SessionModel.state == SessionState.ACTIVE
        )
    ) or 0


def count_high_risk_sessions(db: DbSession) -> int:
    """ACTIVE sessions currently at HIGH risk.

    Expected to read near-zero in normal operation: Module 7 revokes a
    session the instant its live score crosses into HIGH (see
    app.services.trust_score.continuous.record_event), so a nonzero reading
    here is only ever the brief in-flight window before that revocation
    completes, not a steady-state population -- this is a live health signal
    ("is anything unrevoked slipping through"), not a count of ongoing
    incidents."""
    return db.scalar(
        select(func.count()).select_from(SessionModel).where(
            SessionModel.state == SessionState.ACTIVE,
            SessionModel.risk_level == RiskLevel.HIGH,
        )
    ) or 0


def count_revoked_sessions(db: DbSession) -> int:
    """All-time count of sessions ended specifically for RISK -- Module 7's
    direct-HIGH-crossing `risk_revoked`, or its `account_locked` cascade
    (Project status.md section 23). Deliberately NOT every termination:
    counting logout/idle/admin terminations too would dilute the one thing
    this stat is meant to show -- how much Module 7 has actually had to
    act -- into a number dominated by ordinary, harmless session endings."""
    return db.scalar(
        select(func.count()).select_from(SessionModel).where(
            SessionModel.termination_reason.in_(
                (TerminationReason.RISK_REVOKED, TerminationReason.ACCOUNT_LOCKED)
            )
        )
    ) or 0


def locked_accounts(db: DbSession) -> list[dict]:
    """Every account currently under the Module 6 MFA lockout or the Module 7
    risk lockout -- the admin "unlock" UI explicitly deferred from both of
    those hardening passes to "a natural fit for Module 8" (Project
    status.md sections 17b/18)."""
    return mfa_service.list_mfa_lockouts(db) + risk_lockout.list_risk_lockouts(db)


def clear_lockouts(user_id: int) -> dict:
    """Clear BOTH lockout types for one account -- the documented
    `redis-cli DEL ...` fallback for each, as one real button. Harmless to
    call for an account that only has one (or neither): each clear reports
    whether it actually removed anything."""
    return {
        "user_id": user_id,
        "cleared_mfa": mfa_service.clear_mfa_lockout(user_id),
        "cleared_risk": risk_lockout.clear_risk_lockout(user_id),
    }


def overview(db: DbSession) -> dict:
    auth_ms, revoke_ms = acl_service.average_latencies(db)
    mfa_counts = mfa_service.count_by_status(db)
    return {
        "active_users": count_active_users(db),
        "active_sessions": session_service.count_active(db),
        "average_trust_score": trust_score_service.average_trust_score(db, active_only=True),
        "high_risk_sessions": count_high_risk_sessions(db),
        "mfa_requests_pending": mfa_counts.get(MFAChallengeStatus.PENDING, 0),
        "revoked_sessions": count_revoked_sessions(db),
        "current_acl_rules": acl_service.count_active(db),
        "avg_authorization_latency_ms": auth_ms,
        "avg_revocation_latency_ms": revoke_ms,
        "locked_out_accounts": len(locked_accounts(db)),
    }


# --------------------------------------------------------------------------- #
# Analytics (Section 5) -- one bucket list per chart
# --------------------------------------------------------------------------- #
def login_activity(db: DbSession, *, days: int = 14) -> list[dict]:
    """Sessions opened per day, oldest first, over the last `days` days --
    the real, measurable proxy for "login activity": every successful login
    that reaches Module 3 opens exactly one session row (a page-refresh
    reattach, section 24's hardening, does NOT open a new one, so this
    counts genuine new logins, not every reconnect).

    Deliberately does not attempt a matching FAILED-login trend: Module 5's
    failed-login counter is a short-lived, 15-minute Redis burst counter
    with no historical Postgres record to trend over multiple days (see
    app.services.trust_score.store) -- there is no real multi-day failed-
    login data in this system to chart, so none is fabricated here."""
    today = utcnow().date()
    since_midnight = utcnow().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(
        days=days - 1
    )
    rows = db.scalars(
        select(SessionModel.created_at).where(SessionModel.created_at >= since_midnight)
    )
    counts = {(today - timedelta(days=days - 1 - i)).isoformat(): 0 for i in range(days)}
    for created_at in rows:
        day = created_at.date().isoformat()
        if day in counts:
            counts[day] += 1
    return [{"label": day, "count": n} for day, n in counts.items()]


def trust_score_distribution(db: DbSession) -> list[dict]:
    """ACTIVE sessions bucketed into 10-point trust-score ranges."""
    rows = db.scalars(
        select(SessionModel.trust_score).where(
            SessionModel.state == SessionState.ACTIVE,
            SessionModel.trust_score.is_not(None),
        )
    )
    buckets = {f"{lo}-{lo + 9}": 0 for lo in range(0, 100, 10)}
    for score in rows:
        lo = min(90, max(0, (score // 10) * 10))
        buckets[f"{lo}-{lo + 9}"] += 1
    return [{"label": label, "count": n} for label, n in buckets.items()]


def risk_level_breakdown(db: DbSession) -> list[dict]:
    """ACTIVE sessions by current risk band."""
    rows = db.execute(
        select(SessionModel.risk_level, func.count())
        .where(
            SessionModel.state == SessionState.ACTIVE,
            SessionModel.risk_level.is_not(None),
        )
        .group_by(SessionModel.risk_level)
    ).all()
    counts = {level: 0 for level in RiskLevel.ALL}
    for level, n in rows:
        if level in counts:
            counts[level] = int(n)
    return [{"label": level, "count": counts[level]} for level in RiskLevel.ALL]


def mfa_event_breakdown(db: DbSession) -> list[dict]:
    """mfa_challenges by status -- reuses Module 6's own tally exactly
    (app.services.mfa.count_by_status), the same numbers the Security
    Alerts page's stat row already shows."""
    counts = mfa_service.count_by_status(db)
    return [
        {"label": status_value, "count": counts.get(status_value, 0)}
        for status_value in MFAChallengeStatus.ALL
    ]


def revoked_sessions_breakdown(db: DbSession) -> list[dict]:
    """Terminated sessions by termination_reason -- every reason, not just
    the risk-related ones `count_revoked_sessions` above narrows to, so this
    chart shows the full picture (logout vs idle vs admin vs risk vs
    account-lockout-cascade) side by side."""
    rows = db.execute(
        select(SessionModel.termination_reason, func.count())
        .where(
            SessionModel.state == SessionState.TERMINATED,
            SessionModel.termination_reason.is_not(None),
        )
        .group_by(SessionModel.termination_reason)
    ).all()
    counts = {reason: 0 for reason in TerminationReason.ALL}
    for reason, n in rows:
        if reason in counts:
            counts[reason] = int(n)
    return [{"label": reason, "count": counts[reason]} for reason in TerminationReason.ALL]


def security_alert_breakdown(db: DbSession) -> list[dict]:
    """security_events by event_type -- Module 7's continuous-evaluation
    audit trail, aggregated (auto + admin sources combined; the Security
    Alerts page's own feed already lets an operator filter by source)."""
    rows = db.execute(
        select(SecurityEvent.event_type, func.count()).group_by(SecurityEvent.event_type)
    ).all()
    counts = {event_type: 0 for event_type in SecurityEventType.ALL}
    for event_type, n in rows:
        if event_type in counts:
            counts[event_type] = int(n)
    return [{"label": event_type, "count": counts[event_type]} for event_type in SecurityEventType.ALL]


def analytics(db: DbSession, *, days: int = 14) -> dict:
    auth_ms, revoke_ms = acl_service.average_latencies(db)
    return {
        "login_activity": login_activity(db, days=days),
        "trust_score_distribution": trust_score_distribution(db),
        "risk_levels": risk_level_breakdown(db),
        "mfa_events": mfa_event_breakdown(db),
        "revoked_sessions": revoked_sessions_breakdown(db),
        "security_alerts": security_alert_breakdown(db),
        "avg_authorization_latency_ms": auth_ms,
        "avg_revocation_latency_ms": revoke_ms,
    }
