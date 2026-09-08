"""
ACL rule ORM model — Module 4 (Dynamic ACL Management).

One row per session-bound network allow-list entry. This is the persisted,
authoritative record of the base paper's data-plane state: while the row is
ACTIVE, the session's client IP sits in the kernel ``ztsaacm_allowed`` /
``ztsaacm_allowed_v6`` ipset and can reach the protected resource; when the
session ends the row goes REMOVING -> REMOVED and the IP is pulled back out.

The row's lifecycle mirrors the enforcement task it spawns:

    PENDING   add task enqueued, not yet applied by the L-PEP
    ACTIVE    L-PEP applied the ipset entry (or bumped its ref-count)
    REMOVING  remove task enqueued, not yet applied
    REMOVED   L-PEP removed the ipset entry (or dropped the ref-count)
    FAILED    the enforcement command errored (see last_error)

Timestamps are naive UTC, matching sessions.py.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.session import utcnow


class ACLState:
    PENDING = "pending"
    ACTIVE = "active"
    REMOVING = "removing"
    REMOVED = "removed"
    FAILED = "failed"

    ALL = (PENDING, ACTIVE, REMOVING, REMOVED, FAILED)
    # States in which the allow-list entry is (meant to be) in the kernel.
    LIVE = (PENDING, ACTIVE, REMOVING)


class EnforcementBackend:
    IPSET = "ipset"
    SIMULATED = "simulated"


class ACLRule(Base):
    __tablename__ = "acl_rules"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)

    # One ACL rule per session — this is the paper's "session-to-ACL binding".
    session_id: Mapped[str] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"),
        unique=True, index=True, nullable=False,
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )

    client_ip: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    resource: Mapped[str] = mapped_column(String(128), nullable=False)
    ipset_name: Mapped[str] = mapped_column(String(64), nullable=False)

    state: Mapped[str] = mapped_column(
        String(16), nullable=False, default=ACLState.PENDING,
        server_default=ACLState.PENDING, index=True,
    )
    enforcement: Mapped[str] = mapped_column(String(16), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, default=utcnow,
        server_default=func.now(),
    )
    activated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=False), nullable=True
    )
    removed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=False), nullable=True
    )

    authorization_latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    revocation_latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    removal_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(256), nullable=True)

    session = relationship("Session", lazy="joined")
    user = relationship("User", lazy="joined")

    @property
    def username(self) -> str | None:
        return self.user.username if self.user is not None else None

    @property
    def is_live(self) -> bool:
        return self.state in ACLState.LIVE

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<ACLRule id={self.id} session={self.session_id} "
            f"ip={self.client_ip} state={self.state}>"
        )
