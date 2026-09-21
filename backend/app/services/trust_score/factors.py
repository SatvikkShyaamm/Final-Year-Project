"""
Trust factor catalogue — Module 5.

Canonical factor names (stored verbatim in ``trust_score_factors.factor_name``)
and a small result type. The Section-6 weight table is the source of truth for
weights and *when* each factor applies; the weights themselves are read from
``app/core/config.py`` so Module 10 can tune them.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.models.trust_score import FactorKind, RiskLevel


class Factor:
    BASELINE = "baseline"
    KNOWN_DEVICE = "known_device"
    KNOWN_IP = "known_ip"
    TYPICAL_HOUR = "typical_hour"
    ATYPICAL_HOUR = "atypical_hour"  # 2026-09-21: dynamic counterpart of TYPICAL_HOUR
    UNKNOWN_DEVICE = "unknown_device"
    IP_CHANGED = "ip_changed"
    APPROVED_VPN = "approved_vpn"
    UNKNOWN_VPN = "unknown_vpn"
    FAILED_LOGINS = "failed_login_burst"
    OFF_HOURS = "off_hours"
    # Module 7 (Continuous Trust Evaluation) -- mid-session-only factors with
    # no login-time equivalent. The other continuous event types (ip_change,
    # vpn_detected, unknown_device, multiple_failed_logins) reuse the names
    # above -- see app/services/trust_score/continuous.py.
    ABNORMAL_REQUEST_RATE = "abnormal_request_rate"
    LARGE_DOWNLOAD = "large_download"


@dataclass
class FactorOutcome:
    name: str
    kind: str            # FactorKind.*
    weight: int          # signed contribution to the score (+70 baseline, +15, -10, ...)
    reason: str
    applied: bool


@dataclass
class TrustEvaluation:
    score: int                       # clamped 0-100
    risk_level: str                  # RiskLevel.*
    baseline: int
    outcomes: list[FactorOutcome] = field(default_factory=list)

    @property
    def applied(self) -> list[FactorOutcome]:
        return [o for o in self.outcomes if o.applied]


def classify_risk(score: int, *, low_min: int, medium_min: int) -> str:
    if score >= low_min:
        return RiskLevel.LOW
    if score >= medium_min:
        return RiskLevel.MEDIUM
    return RiskLevel.HIGH


__all__ = ["Factor", "FactorOutcome", "TrustEvaluation", "FactorKind", "RiskLevel", "classify_risk"]
