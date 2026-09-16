"""
Session ORM model — Module 3 (Session Lifecycle).

This is the base paper's application-layer session: network access permission
is bound to the *liveness* of one of these rows. A session is opened when a
client's signalling WebSocket connects (FSM S1 -> S2) and closed when that
socket drops, the user logs out, an admin terminates it, or it times out
(FSM S2 -> S3 -> gone). Module 4 will bind an ACL rule to the S2 state;
Module 7 will drive S2 -> S3 on unacceptable risk. Nothing here decides
*whether* a session may open — that gate is Modules 5/6.

Timestamps are stored as naive UTC (``DateTime`` without timezone) so the
idle/lifetime comparisons in the sweeper behave identically on Postgres and
on the SQLite used by the test suite.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def utcnow() -> datetime:
    """Naive UTC 'now' — the single time source for session timestamps."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class SessionState:
    """Allowed values for ``Session.state`` (the FSM position this row is in)."""

    ACTIVE = "active"        # base paper S2 — session live, (from Module 4) ACL active
    TERMINATED = "terminated"  # past S3 — socket closed, access revoked

    ALL = (ACTIVE, TERMINATED)


class TerminationReason:
    """Why a session left the ACTIVE state. Recorded for the dashboard + audit."""

    LOGOUT = "logout"
    WEBSOCKET_DISCONNECT = "websocket_disconnect"
    ADMIN_TERMINATED = "admin_terminated"
    IDLE_TIMEOUT = "idle_timeout"
    MAX_LIFETIME = "max_lifetime"
    RISK_REVOKED = "risk_revoked"  # reserved for Module 7
    # 2026-09-16: a DIFFERENT session on this same account had a direct HIGH
    # crossing (RISK_REVOKED) and tripped the account-level risk lockout --
    # every OTHER still-active session for that account is cascaded closed
    # for the same reason a locked-out account shouldn't still have other
    # windows open. See app.services.trust_score.continuous's revoke branch.
    ACCOUNT_LOCKED = "account_locked"

    ALL = (
        LOGOUT,
        WEBSOCKET_DISCONNECT,
        ADMIN_TERMINATED,
        IDLE_TIMEOUT,
        MAX_LIFETIME,
        RISK_REVOKED,
        ACCOUNT_LOCKED,
    )


class Session(Base):
    __tablename__ = "sessions"

    # Opaque random session id (uuid4 hex) — the "Session ID" the dashboard and
    # the WebSocket handshake pass around. Not the DB rowid on purpose.
    id: Mapped[str] = mapped_column(String(32), primary_key=True)

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )

    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)

    state: Mapped[str] = mapped_column(
        String(20), nullable=False, default=SessionState.ACTIVE,
        server_default=SessionState.ACTIVE, index=True,
    )
    # Whether a signalling WebSocket is attached *right now*. Display/telemetry
    # only — `state` is the source of truth for whether access is granted.
    ws_connected: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, default=utcnow,
        server_default=func.now(),
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, default=utcnow,
        server_default=func.now(),
    )
    terminated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=False), nullable=True
    )
    termination_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # ---- Trust Score (Module 5) ----
    # The static/initial trust score computed once at session creation, and its
    # risk band. Null until Module 5's session-open hook fills them in; Module 7
    # will later overwrite them as it recomputes the score in-session.
    trust_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # ---- Token revocation hardening (Module 2/3, added alongside Module 6) ----
    # The `jti` and `exp` of the access token that opened THIS session, so
    # terminating the session can revoke that specific token server-side (see
    # app.services.auth.revocation) instead of only ending the session row.
    # Null for a session opened before this column existed, or in the rare
    # case the opening token had no `jti` -- such a session simply can't be
    # targeted for token revocation, matching pre-existing behaviour.
    token_jti: Mapped[str | None] = mapped_column(String(32), nullable=True)
    token_exp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=False), nullable=True
    )

    user = relationship("User", lazy="joined")

    # ---- derived, read-only ----
    @property
    def username(self) -> str | None:
        return self.user.username if self.user is not None else None

    @property
    def is_active(self) -> bool:
        return self.state == SessionState.ACTIVE

    @property
    def duration_seconds(self) -> int:
        end = self.terminated_at or utcnow()
        return max(0, int((end - self.created_at).total_seconds()))

    def __repr__(self) -> str:  # pragma: no cover - debug aid only
        return f"<Session id={self.id} user_id={self.user_id} state={self.state}>"
