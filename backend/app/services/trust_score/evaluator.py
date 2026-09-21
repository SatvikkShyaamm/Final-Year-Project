"""
The static trust-score algorithm — Module 5.

Implements Section 6 of the Master Project Context, verbatim:

    score = clamp(70 + Σ positive adjustments - Σ negative adjustments, 0, 100)

computed ONCE at session creation. First-time users (no session history) get
only the baseline plus the always-checked factors; history-dependent factors
are skipped, not penalised.

Pure over its inputs — the DB is read only for session history, Redis only for
the failed-login count. No writes here (the service layer persists the result).
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta

from sqlalchemy.orm import Session as DbSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.trust_score import store
from app.services.trust_score.factors import (
    Factor,
    FactorKind,
    FactorOutcome,
    TrustEvaluation,
    classify_risk,
)
from app.services.trust_score.history import ip_matches_recent, load_user_history

logger = get_logger(__name__)
settings = get_settings()


def _in_any_cidr(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def in_any_cidr(ip: str, cidrs: list[str]) -> bool:
    """Public alias of ``_in_any_cidr`` -- Module 7's continuous evaluation
    (app/services/trust_score/continuous.py) reuses this exact CIDR check to
    classify a ``vpn_detected`` event's IP against the same approved/known-bad
    VPN ranges Module 5 checks at login, instead of duplicating the logic."""
    return _in_any_cidr(ip, cidrs)


def _local_hour(login_time: datetime) -> int:
    return (login_time + timedelta(hours=settings.trust_local_utc_offset_hours)).hour


def _typical_hour_band(login_hours: list[int], s) -> tuple[float, float]:
    """Robust, self-decaying typical-hour band -- 2026-09-21 hardening.

    Replaces the original raw min/max range. min/max had two problems: (1) it
    was reward-only (falling outside it cost nothing), and (2) a single
    outlier hour permanently redefined the boundary the moment it happened,
    since the very next min/max recompute had to include it.

    This uses mean +/- k*stddev over the same `login_hours` the caller already
    has (history.py's rolling last-`_RECENT_WINDOW` (20) sessions) instead. A
    single new outlier only nudges the mean and stddev by 1/N -- it does not
    snap the band open to admit it -- and, because the input is already
    bounded to the last 20 sessions, an old outlier's influence fades out
    entirely once it ages out of that window rather than persisting forever
    the way a running min/max would. `trust_typical_hour_min_band_hours`
    keeps the band from collapsing to an unreasonably thin sliver when a
    user's recent history happens to be very consistent (stddev near 0).

    Paired with `evaluate()`'s new ATYPICAL_HOUR factor, which docks points
    when the login hour falls outside this band -- this factor is no longer
    reward-only.
    """
    n = len(login_hours)
    mean = sum(login_hours) / n
    if n > 1:
        variance = sum((h - mean) ** 2 for h in login_hours) / n
        stddev = variance ** 0.5
    else:
        stddev = 0.0
    half_width = max(
        s.trust_typical_hour_min_band_hours,
        s.trust_typical_hour_band_stddev_multiplier * stddev,
    )
    lo = max(0.0, mean - half_width)
    hi = min(23.0, mean + half_width)
    return lo, hi


def evaluate(
    db: DbSession,
    *,
    user_id: int,
    ip_address: str | None,
    user_agent: str | None,
    login_time: datetime,
    exclude_session_id: str | None = None,
) -> TrustEvaluation:
    s = settings
    ua = (user_agent or "").strip() or None
    ip = ip_address or ""

    history = load_user_history(
        db, user_id,
        exclude_session_id=exclude_session_id,
        offset_hours=s.trust_local_utc_offset_hours,
    )
    has_history = history.has_history
    can_learn_hours = history.session_count >= s.trust_typical_hour_min_sessions

    outcomes: list[FactorOutcome] = [
        FactorOutcome(
            Factor.BASELINE, FactorKind.BASELINE, s.trust_score_baseline,
            "Zero Trust neutral-positive baseline", True,
        )
    ]

    def add(name: str, kind: str, weight: int, reason: str, applied: bool) -> None:
        signed = weight if kind == FactorKind.POSITIVE else -weight
        outcomes.append(FactorOutcome(name, kind, signed, reason, applied))

    # ---- always-checked factors ----
    approved_vpn = bool(ip) and _in_any_cidr(ip, s.trust_approved_vpn_cidrs)
    add(
        Factor.APPROVED_VPN, FactorKind.POSITIVE, s.trust_weight_approved_vpn,
        "Source IP is in an organisation-approved VPN range" if approved_vpn
        else "Source IP is not in an approved VPN range",
        approved_vpn,
    )
    unknown_vpn = (
        bool(ip) and not approved_vpn and _in_any_cidr(ip, s.trust_known_vpn_cidrs)
    )
    add(
        Factor.UNKNOWN_VPN, FactorKind.NEGATIVE, s.trust_weight_unknown_vpn,
        "Source IP is in a known public VPN/proxy range" if unknown_vpn
        else "Source IP is not in a known public VPN/proxy range",
        unknown_vpn,
    )

    failed = store.failed_login_count(user_id)
    failed_burst = failed >= s.trust_failed_login_threshold
    add(
        Factor.FAILED_LOGINS, FactorKind.NEGATIVE, s.trust_weight_failed_logins,
        f"{failed} failed login attempt(s) in the last "
        f"{s.trust_failed_login_window_minutes} min",
        failed_burst,
    )

    # ---- 2026-09-21 hardening: static org-policy floor + dynamic per-user band ----
    # off_hours is now an ALWAYS-checked organizational baseline -- it used to
    # apply only as a fallback for users with no learned hour history yet.
    # Per the "adaptive by default, with a static backstop" design: no amount
    # of a user's own learned typical-hour history can suppress this floor: a
    # 3 AM login still adds this penalty even for a user who logs in every
    # night at 3 AM, though their own learned band (below) can independently
    # earn back a positive TYPICAL_HOUR factor alongside it.
    hour = _local_hour(login_time)
    off_hours = s.trust_off_hours_start_hour <= hour < s.trust_off_hours_end_hour
    add(
        Factor.OFF_HOURS, FactorKind.NEGATIVE, s.trust_weight_off_hours,
        f"Login at hour {hour:02d} falls inside the organization's off-hours "
        f"policy window ({s.trust_off_hours_start_hour:02d}:00-"
        f"{s.trust_off_hours_end_hour:02d}:00) -- applies regardless of history"
        if off_hours
        else f"Login at hour {hour:02d} is outside the off-hours policy window",
        off_hours,
    )

    # Dynamic, per-user typical-hour band (needs >= N prior sessions to learn).
    # TYPICAL_HOUR / ATYPICAL_HOUR are mutually exclusive, mirroring the
    # KNOWN_DEVICE/UNKNOWN_DEVICE pairing above: both rows are always recorded
    # once there's enough history (for a complete audit-trail breakdown), but
    # only one has `applied=True` and contributes to the score.
    if can_learn_hours:
        lo, hi = _typical_hour_band(history.login_hours, s)
        typical = lo <= hour <= hi
        add(
            Factor.TYPICAL_HOUR, FactorKind.POSITIVE, s.trust_weight_typical_hour,
            f"Login at hour {hour:02d} is within this user's learned typical "
            f"band ({lo:.1f}-{hi:.1f}, from their last {history.session_count} sessions)"
            if typical else "Login outside the user's learned typical band — n/a",
            typical,
        )
        add(
            Factor.ATYPICAL_HOUR, FactorKind.NEGATIVE, s.trust_weight_atypical_hour,
            f"Login at hour {hour:02d} falls outside this user's learned typical "
            f"band ({lo:.1f}-{hi:.1f}, from their last {history.session_count} sessions)"
            if not typical else "Login within the user's learned typical band — n/a",
            not typical,
        )

    # ---- history-dependent device / IP factors ----
    if has_history:
        known_device = ua is not None and ua in history.known_user_agents
        add(
            Factor.KNOWN_DEVICE, FactorKind.POSITIVE, s.trust_weight_known_device,
            "This device (User-Agent) has been seen for this user before"
            if known_device else "Device recognised — n/a",
            known_device,
        )
        unknown_device = ua is not None and ua not in history.known_user_agents
        add(
            Factor.UNKNOWN_DEVICE, FactorKind.NEGATIVE, s.trust_weight_unknown_device,
            "New device (User-Agent) not seen for this user before"
            if unknown_device else "Device is known — n/a",
            unknown_device,
        )

        known_ip = bool(ip) and ip_matches_recent(ip, history)
        add(
            Factor.KNOWN_IP, FactorKind.POSITIVE, s.trust_weight_known_ip,
            "IP matches (or shares a subnet with) a recent session"
            if known_ip else "IP not seen recently — n/a",
            known_ip,
        )
        ip_changed = (
            bool(ip) and history.last_ip is not None and ip != history.last_ip
        )
        add(
            Factor.IP_CHANGED, FactorKind.NEGATIVE, s.trust_weight_ip_changed,
            f"IP changed from the last session ({history.last_ip} -> {ip})"
            if ip_changed else "IP unchanged from last session — n/a",
            ip_changed,
        )

    delta = sum(o.weight for o in outcomes if o.applied and o.kind != FactorKind.BASELINE)
    raw = s.trust_score_baseline + delta
    score = max(0, min(100, raw))
    risk = classify_risk(
        score, low_min=s.trust_risk_low_min, medium_min=s.trust_risk_medium_min
    )

    logger.info(
        "trust score user_id=%s ip=%s score=%s risk=%s (baseline=%s delta=%s history=%s)",
        user_id, ip or "-", score, risk, s.trust_score_baseline, delta, history.session_count,
    )
    return TrustEvaluation(
        score=score, risk_level=risk, baseline=s.trust_score_baseline, outcomes=outcomes
    )
