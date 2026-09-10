"""
Session lifecycle business logic — Module 3.

Sync functions over a SQLAlchemy Session, orchestrating the Postgres
``sessions`` table (source of truth), the Redis index/event bus
(``store``), and the FSM guard (``fsm``). No FastAPI imports: the WebSocket
endpoint, the ``/auth/logout`` handler, and the background sweeper all call
in here.
"""
from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session as DbSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.session import Session, SessionState, TerminationReason, utcnow
from app.services.session import store
from app.services.session.fsm import assert_transition
from app.services.session.hooks import emit_session_closed, emit_session_opened

logger = get_logger(__name__)
settings = get_settings()


# --------------------------------------------------------------------------- #
# Reads
# --------------------------------------------------------------------------- #
def get_session(db: DbSession, session_id: str) -> Session | None:
    return db.get(Session, session_id)


def list_sessions(
    db: DbSession, *, include_terminated: bool = False, limit: int = 200
) -> list[Session]:
    stmt = select(Session).order_by(Session.created_at.desc()).limit(limit)
    if not include_terminated:
        stmt = stmt.where(Session.state == SessionState.ACTIVE)
    return list(db.scalars(stmt))


def count_active(db: DbSession) -> int:
    return db.scalar(
        select(func.count()).select_from(Session).where(
            Session.state == SessionState.ACTIVE
        )
    ) or 0


def get_current_session_for_user(db: DbSession, user_id: int) -> Session | None:
    """The user's most recently opened still-active session (portal view)."""
    return db.scalar(
        select(Session)
        .where(Session.user_id == user_id, Session.state == SessionState.ACTIVE)
        .order_by(Session.created_at.desc())
        .limit(1)
    )


# --------------------------------------------------------------------------- #
# Writes
# --------------------------------------------------------------------------- #
def create_session(
    db: DbSession,
    *,
    user,
    ip_address: str | None,
    user_agent: str | None,
    token_jti: str | None = None,
    token_exp=None,
) -> Session:
    """
    Open a new session (FSM S1 -> S2).

    In the full system Modules 5/6 decide whether this is allowed *before*
    calling here, and Module 4 attaches an ACL rule *after*. Module 3 just
    creates the row and announces it.

    `token_jti` / `token_exp` are the `jti` and expiry of the access token
    that opened this session (from the WebSocket handshake's decoded claims —
    see app.ws.auth.resolve_ws_user). They are stored so that terminating this
    session can later revoke that specific token server-side (see
    app.services.auth.revocation) — Module 3 itself has no opinion on
    revocation, it just carries the data for whoever does. Optional/None for
    any caller that doesn't have a token to attach (e.g. a directly-created
    test session).
    """
    assert_transition(None, SessionState.ACTIVE)

    now = utcnow()
    session = Session(
        id=uuid.uuid4().hex,
        user_id=user.id,
        ip_address=ip_address,
        user_agent=(user_agent or "")[:512] or None,
        state=SessionState.ACTIVE,
        ws_connected=False,
        created_at=now,
        last_seen_at=now,
        token_jti=token_jti,
        token_exp=token_exp,
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    store.register_active(
        session_id=session.id,
        user_id=user.id,
        username=getattr(user, "username", None),
        ip_address=ip_address,
        created_at=now,
    )
    store.publish_event(
        "session.opened",
        {
            "session_id": session.id,
            "user_id": user.id,
            "username": getattr(user, "username", None),
            "state": SessionState.ACTIVE,
        },
    )
    logger.info("session opened id=%s user_id=%s ip=%s", session.id, user.id, ip_address)
    # Downstream reactions (Module 4 attaches an ACL rule here). Failures are
    # logged inside emit_* and never propagate — the session still opens.
    emit_session_opened(db, session)
    return session


def touch_session(db: DbSession, session_id: str) -> None:
    """Bump last_seen_at on an active session (called on every WS heartbeat)."""
    session = db.get(Session, session_id)
    if session is None or session.state != SessionState.ACTIVE:
        return
    session.last_seen_at = utcnow()
    db.commit()


def set_ws_connected(db: DbSession, session_id: str, connected: bool) -> None:
    session = db.get(Session, session_id)
    if session is None:
        return
    session.ws_connected = connected
    db.commit()
    store.set_ws_connected(session_id, connected)


def terminate_session(
    db: DbSession, session_id: str, *, reason: str
) -> Session | None:
    """
    Close a session (FSM S2 -> S3 -> gone). Idempotent: a session that is
    already terminated is returned unchanged, keeping its original reason — so
    e.g. an admin termination is not overwritten by the follow-up
    websocket-disconnect cleanup.
    """
    session = db.get(Session, session_id)
    if session is None:
        return None
    if session.state == SessionState.TERMINATED:
        return session

    assert_transition(session.state, SessionState.TERMINATED)
    session.state = SessionState.TERMINATED
    session.ws_connected = False
    session.terminated_at = utcnow()
    session.termination_reason = reason
    db.commit()
    db.refresh(session)

    store.deregister_active(session_id=session.id, user_id=session.user_id)
    store.publish_event(
        "session.closed",
        {
            "session_id": session.id,
            "user_id": session.user_id,
            "username": session.username,
            "state": SessionState.TERMINATED,
            "termination_reason": reason,
        },
    )
    logger.info("session closed id=%s user_id=%s reason=%s", session.id, session.user_id, reason)
    # Downstream reactions (Module 4 removes the session's ACL rule here).
    emit_session_closed(db, session.id, session.user_id, reason)
    return session


def terminate_user_sessions(
    db: DbSession, user_id: int, *, reason: str
) -> list[str]:
    """Terminate every active session for a user (used by /auth/logout)."""
    ids = list(
        db.scalars(
            select(Session.id).where(
                Session.user_id == user_id,
                Session.state == SessionState.ACTIVE,
            )
        )
    )
    for session_id in ids:
        terminate_session(db, session_id, reason=reason)
    return ids


def sweep_expired_sessions(db: DbSession) -> list[str]:
    """
    Terminate active sessions that have idled too long or exceeded the max
    lifetime. Runs from the background task in app.main; also directly
    unit-tested. Returns the ids it closed.
    """
    now = utcnow()
    idle_cutoff = now - timedelta(minutes=settings.session_idle_timeout_minutes)
    life_cutoff = now - timedelta(minutes=settings.session_max_lifetime_minutes)

    rows = db.execute(
        select(Session.id, Session.last_seen_at, Session.created_at).where(
            Session.state == SessionState.ACTIVE,
            or_(Session.last_seen_at < idle_cutoff, Session.created_at < life_cutoff),
        )
    ).all()

    closed: list[str] = []
    for session_id, last_seen_at, created_at in rows:
        reason = (
            TerminationReason.MAX_LIFETIME
            if created_at < life_cutoff
            else TerminationReason.IDLE_TIMEOUT
        )
        terminate_session(db, session_id, reason=reason)
        closed.append(session_id)
    if closed:
        logger.info("session sweeper closed %d session(s): %s", len(closed), closed)
    return closed
