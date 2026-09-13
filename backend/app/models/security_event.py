"""
Security event ORM model -- Module 7 (Continuous Trust Evaluation).

One table:

  security_events   one row per mid-session security-relevant event ingested
                     by POST /security/events (admin today; Module 9's
                     simulation buttons will call the same endpoint later):
                     an IP change, a VPN/proxy source, an unrecognised
                     device signature, an abnormal request rate, an
                     abnormally large download, or a burst of failed logins
                     observed while the session is already ACTIVE. Records
                     the score/risk immediately before and after, and which
                     risk-based action (none / reverify / revoke) resulted.

This is deliberately a *new*, Module-7-owned audit table -- it does not
retrofit anything onto Module 5's ``trust_score_factors`` (the static,
session-open breakdown) or Module 6's ``mfa_challenges``. A continuous
re-evaluation still writes one ``trust_score_factors`` row per event (so the
per-session factor breakdown stays complete across the session's whole
lifetime, not just its opening moment) -- ``security_events`` additionally
records the event itself and the action taken, which trust_score_factors has
no column for.

Timestamps are naive UTC, matching sessions.py / acl.py / trust_score.py /
mfa.py.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.session import utcnow


class SecurityEventType:
    """The Module 7 event catalogue -- Section 8 of MASTER_PROJECT_CONTEXT.docx
    ("VPN change, IP change, abnormal download, abnormal request rate, etc."),
    rounded out to a fixed set of six so Module 9's simulation buttons have a
    stable contract to target."""

    IP_CHANGE = "ip_change"
    VPN_DETECTED = "vpn_detected"
    UNKNOWN_DEVICE = "unknown_device"
    ABNORMAL_REQUEST_RATE = "abnormal_request_rate"
    LARGE_DOWNLOAD = "large_download"
    MULTIPLE_FAILED_LOGINS = "multiple_failed_logins"

    ALL = (
        IP_CHANGE,
        VPN_DETECTED,
        UNKNOWN_DEVICE,
        ABNORMAL_REQUEST_RATE,
        LARGE_DOWNLOAD,
        MULTIPLE_FAILED_LOGINS,
    )


class SecurityEventAction:
    """The risk-based action a continuous re-evaluation resulted in."""

    NONE = "none"          # still LOW -- nothing beyond recording the event
    REVERIFY = "reverify"  # crossed into MEDIUM -- an emailed re-verification code was sent
    REVOKE = "revoke"      # crossed into HIGH -- the session was terminated

    ALL = (NONE, REVERIFY, REVOKE)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)

    session_id: Mapped[str] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), index=True, nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )

    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    # Signed contribution to the score (matches trust_score_factors.weight_applied).
    weight_applied: Mapped[int] = mapped_column(Integer, nullable=False)
    reason: Mapped[str] = mapped_column(String(256), nullable=False)

    previous_score: Mapped[int] = mapped_column(Integer, nullable=False)
    new_score: Mapped[int] = mapped_column(Integer, nullable=False)
    previous_risk: Mapped[str] = mapped_column(String(16), nullable=False)
    new_risk: Mapped[str] = mapped_column(String(16), nullable=False)
    action: Mapped[str] = mapped_column(String(16), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, default=utcnow,
        server_default=func.now(), index=True,
    )

    session = relationship("Session", lazy="selectin")

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<SecurityEvent session={self.session_id} type={self.event_type} "
            f"{self.previous_score}->{self.new_score} action={self.action}>"
        )
