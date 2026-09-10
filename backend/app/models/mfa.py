"""
MFA ORM models — Module 6 (Adaptive MFA).

Two tables:

  mfa_credentials  one TOTP secret per user (RFC 6238). `confirmed` flips true
                   the first time the user proves they can generate a code, so
                   the enrollment payload (secret / QR URI) is only handed back
                   until then.
  mfa_challenges   one row per "you must verify" event — created by /auth/login
                   when the risk band is MEDIUM, or by /mfa/challenge for a
                   step-up. Carries the trust_score / risk_level that triggered
                   it (dashboard "why"), an attempt counter, and an expiry.

Timestamps are naive UTC, matching sessions.py / acl.py / trust_score.py.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.session import utcnow


class MFAMethod:
    TOTP = "totp"
    ALL = (TOTP,)


class MFAChallengeStatus:
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"       # too many wrong codes
    EXPIRED = "expired"     # ran out of time

    ALL = (PENDING, VERIFIED, FAILED, EXPIRED)
    OPEN = (PENDING,)


class MFAChallengeReason:
    LOGIN_RISK = "login_risk"        # risk band == MEDIUM at /auth/login
    STEP_UP = "step_up"             # explicit re-verification of an authed user
    RISK_RETRIGGER = "risk_retrigger"  # reserved for Module 7

    ALL = (LOGIN_RISK, STEP_UP, RISK_RETRIGGER)


class MFACredential(Base):
    __tablename__ = "mfa_credentials"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        unique=True, index=True, nullable=False,
    )
    method: Mapped[str] = mapped_column(String(16), nullable=False, default=MFAMethod.TOTP)
    secret: Mapped[str] = mapped_column(String(64), nullable=False)
    confirmed: Mapped[bool] = mapped_column(
        default=False, server_default="false", nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, default=utcnow,
        server_default=func.now(),
    )
    confirmed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=False), nullable=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=False), nullable=True
    )

    user = relationship("User", lazy="joined")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<MFACredential user_id={self.user_id} confirmed={self.confirmed}>"


class MFAChallenge(Base):
    __tablename__ = "mfa_challenges"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    method: Mapped[str] = mapped_column(String(16), nullable=False, default=MFAMethod.TOTP)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=MFAChallengeStatus.PENDING,
        server_default=MFAChallengeStatus.PENDING, index=True,
    )
    reason: Mapped[str] = mapped_column(String(24), nullable=False)

    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False)

    trust_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, default=utcnow,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=False), nullable=True
    )

    user = relationship("User", lazy="joined")

    @property
    def username(self) -> str | None:
        return self.user.username if self.user is not None else None

    @property
    def attempts_remaining(self) -> int:
        return max(0, self.max_attempts - self.attempts)

    @property
    def is_open(self) -> bool:
        return self.status == MFAChallengeStatus.PENDING

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<MFAChallenge id={self.id} user_id={self.user_id} "
            f"status={self.status} reason={self.reason}>"
        )
