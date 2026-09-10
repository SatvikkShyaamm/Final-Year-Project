"""
MFA ORM models -- Module 6 (Adaptive MFA).

One table:

  mfa_challenges   one row per "you must verify" event -- created by
                   /auth/login when the risk band is MEDIUM, or by
                   /mfa/challenge for a step-up. Carries the trust_score /
                   risk_level that triggered it (dashboard "why"), an attempt
                   counter, an expiry, and the hashed one-time code.

Method is always email: a random numeric code is generated per challenge,
hashed (HMAC-SHA256 with a per-challenge random salt) for storage, and
emailed to the user's registered address via Gmail SMTP
(app/services/mfa/email_otp.py). There is no persistent per-user MFA
credential/secret -- unlike TOTP, an email code needs nothing durable to be
issued, so there is nothing to enroll and nothing to store between
challenges. (TOTP was removed 2026-09-10 at the user's explicit request --
see docs/architecture.md and Project status.md section 11. The prior
`mfa_credentials` table, which stored one TOTP secret per user, is dropped in
Alembic 0007.)

Timestamps are naive UTC, matching sessions.py / acl.py / trust_score.py.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.session import utcnow


class MFAMethod:
    EMAIL = "email"
    ALL = (EMAIL,)


class MFADeliveryStatus:
    """How the code actually reached (or didn't reach) the user -- shown on
    the admin MFA feed so a SOC operator can tell a real email send apart
    from the dev/test fallback."""

    SENT = "sent"              # handed to the SMTP server successfully
    DEV_LOGGED = "dev_logged"  # SMTP not configured -- logged server-side only
    FAILED = "failed"          # SMTP configured but the send raised

    ALL = (SENT, DEV_LOGGED, FAILED)


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
    RISK_RETRIGGER = "risk_retrigger"  # reserved for Module 7 (continuous
                                        # trust evaluation) -- will reuse this
                                        # same email challenge, not TOTP.

    ALL = (LOGIN_RISK, STEP_UP, RISK_RETRIGGER)


class MFAChallenge(Base):
    __tablename__ = "mfa_challenges"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    method: Mapped[str] = mapped_column(String(16), nullable=False, default=MFAMethod.EMAIL)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=MFAChallengeStatus.PENDING,
        server_default=MFAChallengeStatus.PENDING, index=True,
    )
    reason: Mapped[str] = mapped_column(String(24), nullable=False)

    # The code itself is never stored in plaintext -- only a salted HMAC of
    # it, checked with a constant-time compare in email_otp.verify_code().
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    code_salt: Mapped[str] = mapped_column(String(32), nullable=False)
    delivered_via: Mapped[str | None] = mapped_column(String(16), nullable=True)

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
