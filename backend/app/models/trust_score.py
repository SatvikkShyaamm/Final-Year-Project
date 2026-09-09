"""
Trust score audit model — Module 5 (Trust Score Engine).

The computed score + risk band live on the ``sessions`` row (columns added by
migration 0004). This table is the per-factor breakdown behind that number: one
row per factor that *actually adjusted* the score for a session (plus a
``baseline`` row), so the dashboard's "Factors affecting score" view can show
exactly how the score was reached and the numbers add up.

Section 6 of the Master Project Context is the authoritative weight table; the
weights themselves are configurable (``app/core/config.py``), this table just
records what was applied.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.session import utcnow


class FactorKind:
    BASELINE = "baseline"
    POSITIVE = "positive"
    NEGATIVE = "negative"

    ALL = (BASELINE, POSITIVE, NEGATIVE)


class RiskLevel:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    ALL = (LOW, MEDIUM, HIGH)


class TrustScoreFactor(Base):
    __tablename__ = "trust_score_factors"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)

    session_id: Mapped[str] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), index=True, nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )

    factor_name: Mapped[str] = mapped_column(String(64), nullable=False)
    factor_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    # Signed: the baseline row is +70, a positive factor +N, a negative factor -N.
    weight_applied: Mapped[int] = mapped_column(Integer, nullable=False)
    reason: Mapped[str] = mapped_column(String(256), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, default=utcnow,
        server_default=func.now(),
    )

    session = relationship("Session", lazy="selectin")

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<TrustScoreFactor session={self.session_id} "
            f"{self.factor_name}={self.weight_applied:+d}>"
        )
