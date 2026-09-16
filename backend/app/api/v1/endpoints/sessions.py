"""
Module 3 — Session Lifecycle.

    WS     /ws/session?token=<jwt>   signalling socket: open == session active
    GET    /sessions                 admin: live (and optionally past) sessions
    GET    /sessions/current         caller's own current active session
    GET    /sessions/{id}            one session (admin, or its owner)
    DELETE /sessions/{id}            admin: force-terminate a session

The socket is the base paper's SS-PDP signalling channel: its onopen drives
FSM S1 -> S2 (session active); its onclose drives S2 -> S3 -> gone, but
(2026-09-16) not instantly — an ordinary drop (tab closed, or a page refresh,
indistinguishable at the transport level) is held for a short
`session_reconnect_grace_seconds` window first, since a reconnect presenting
the SAME access token within that window is treated as the SAME browser tab
resuming, and reattaches to this exact session (see the handshake's
`get_active_session_by_token_jti` lookup and `_finalize_disconnect` below)
rather than opening a fresh one with a reset trust score. Logout (Module 2
endpoint), an admin DELETE here, and the idle sweeper (app.main) are the
other ways a session leaves S2 — all of them go through
``services.session.terminate_session`` so the FSM stays authoritative, and
none of them go through the reconnect-grace path (they've already recorded
a real reason before the socket closes, so the handler's `finally` block
finalizes them immediately, exactly as before this hardening pass).

The session-service calls below are synchronous (sync SQLAlchemy, as
everywhere in this codebase). They are single-row operations, so the async
handlers call them directly rather than pushing to a threadpool.
"""
from __future__ import annotations

import asyncio
import json
from contextlib import suppress
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, status
from sqlalchemy.orm import Session as DbSession
from starlette.websockets import WebSocketDisconnect

from app.api.deps import CurrentAdmin, CurrentUser, get_db
from app.core.config import get_settings
from app.core.database import SessionLocal
from app.core.logging import get_logger
from app.core.security import create_mfa_token
from app.models.session import SessionState, TerminationReason, utcnow
from app.schemas.session import (
    SessionListResponse,
    SessionRead,
    SessionTerminateResponse,
)
from app.services import acl as acl_service
from app.services import mfa as mfa_service
from app.services import session as session_service
from app.services.trust_score import continuous as continuous_service
from app.ws.auth import WsAuthError, resolve_ws_user
from app.ws.connection_manager import manager

router = APIRouter()
logger = get_logger(__name__)
settings = get_settings()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _with_acl(session_read: SessionRead, acl_state: str | None) -> SessionRead:
    """Populate the reserved acl_status field (Module 4) on a session view."""
    session_read.acl_status = acl_state or "none"
    return session_read


def _with_current_action(session_read: SessionRead, action: str | None) -> SessionRead:
    """Populate the reserved current_action field (Module 7) on a session view."""
    session_read.current_action = action
    return session_read


# --------------------------------------------------------------------------- #
# REST
# --------------------------------------------------------------------------- #
@router.get(
    "/sessions",
    tags=["sessions"],
    response_model=SessionListResponse,
    summary="List sessions (admin) — the dashboard's Live Sessions feed",
)
def list_sessions(
    _admin: CurrentAdmin,
    db: DbSession = Depends(get_db),
    include_terminated: bool = Query(
        default=False, description="Also include already-closed sessions"
    ),
) -> SessionListResponse:
    rows = session_service.list_sessions(db, include_terminated=include_terminated)
    session_ids = [row.id for row in rows]
    acl_map = acl_service.acl_status_map(db, session_ids)
    action_map = continuous_service.pending_reverify_map(db, session_ids)
    return SessionListResponse(
        sessions=[
            _with_current_action(
                _with_acl(SessionRead.model_validate(row), acl_map.get(row.id)),
                action_map.get(row.id),
            )
            for row in rows
        ],
        active_count=session_service.count_active(db),
    )


@router.get(
    "/sessions/current",
    tags=["sessions"],
    response_model=SessionRead | None,
    summary="The caller's own current active session (or null)",
)
def get_current_session(
    current_user: CurrentUser, db: DbSession = Depends(get_db)
) -> SessionRead | None:
    row = session_service.get_current_session_for_user(db, current_user.id)
    if row is None:
        return None
    rule = acl_service.get_rule_for_session(db, row.id)
    action = continuous_service.pending_reverify_map(db, [row.id]).get(row.id)
    return _with_current_action(
        _with_acl(SessionRead.model_validate(row), rule.state if rule else None), action
    )


@router.get(
    "/sessions/{session_id}",
    tags=["sessions"],
    response_model=SessionRead,
    summary="Inspect one session (admin, or the session's owner)",
)
def get_session(
    session_id: str, current_user: CurrentUser, db: DbSession = Depends(get_db)
) -> SessionRead:
    row = session_service.get_session(db, session_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    if not current_user.is_admin and row.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not your session")
    rule = acl_service.get_rule_for_session(db, row.id)
    action = continuous_service.pending_reverify_map(db, [row.id]).get(row.id)
    return _with_current_action(
        _with_acl(SessionRead.model_validate(row), rule.state if rule else None), action
    )


@router.delete(
    "/sessions/{session_id}",
    tags=["sessions"],
    response_model=SessionTerminateResponse,
    summary="Force-terminate a session (admin)",
)
async def terminate_session(
    session_id: str, _admin: CurrentAdmin, db: DbSession = Depends(get_db)
) -> SessionTerminateResponse:
    row = session_service.get_session(db, session_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    updated = session_service.terminate_session(
        db, session_id, reason=TerminationReason.ADMIN_TERMINATED
    )
    # Shut the live socket now if we hold it. The session.terminated message
    # MUST go out before the close frame -- ConnectionManager.close() sends it
    # first for exactly this reason: once the socket is closed, a send to it
    # silently fails, the client's SessionSocket sees an ordinary drop instead
    # of an intentional end, and its reconnect-with-backoff logic opens a
    # brand-new session right behind the one that was just terminated.
    await manager.close(
        session_id,
        code=status.WS_1000_NORMAL_CLOSURE,
        reason="admin_terminated",
        message={"type": "session.terminated", "reason": "admin_terminated"},
    )
    assert updated is not None  # row existed a line above
    return SessionTerminateResponse(
        id=updated.id, state=updated.state, termination_reason=updated.termination_reason
    )


# --------------------------------------------------------------------------- #
# WebSocket signalling channel
# --------------------------------------------------------------------------- #
def _client_ip(websocket: WebSocket) -> str | None:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return websocket.client.host if websocket.client else None


async def _send_json(websocket: WebSocket, payload: dict) -> None:
    with suppress(Exception):
        await websocket.send_json(payload)


async def _handle_client_message(websocket: WebSocket, raw: str) -> None:
    try:
        message = json.loads(raw)
    except (ValueError, TypeError):
        return
    if isinstance(message, dict) and message.get("type") == "ping":
        await _send_json(websocket, {"type": "pong", "server_time": _now_iso()})


async def _finalize_disconnect(session_id: str, disconnect_marker: datetime) -> None:
    """
    Runs `session_reconnect_grace_seconds` after an ordinary WS drop (see the
    handler's `finally` block below) and finalizes the close ONLY if nothing
    reattached in the meantime. 2026-09-16 hardening.

    Uses its own short-lived DB session via `SessionLocal` directly (the same
    pattern app.main's `_session_sweeper` background task already uses) --
    the request-scoped `db` the handler received is closed by the time this
    fires, since the handler itself has already returned.

    `disconnect_marker` is that session's `last_seen_at` AT THE MOMENT this
    particular drop was detected (captured by the caller, not read fresh
    here) -- guards against a subtle race: if the client reattaches and then
    disconnects AGAIN before this task's sleep finishes, `last_seen_at` will
    have moved past this marker (the reattach's own `touch_session` bumped
    it), so this stale task backs off and leaves finalizing to the SECOND
    drop's own, separately-scheduled `_finalize_disconnect` -- otherwise a
    slow first task could cut the second drop's own grace window short.
    """
    await asyncio.sleep(max(0.0, settings.session_reconnect_grace_seconds))
    db = SessionLocal()
    try:
        session = session_service.get_session(db, session_id)
        if session is None or session.state != SessionState.ACTIVE:
            return  # already terminated some other way (or never existed)
        if session.ws_connected:
            return  # reattached, and still connected right now
        if session.last_seen_at > disconnect_marker:
            return  # reattached, then dropped again -- that drop owns this
        session_service.terminate_session(
            db, session_id, reason=TerminationReason.WEBSOCKET_DISCONNECT
        )
        logger.info(
            "session finalized after reconnect grace window id=%s", session_id
        )
    finally:
        db.close()


@router.websocket("/ws/session")
async def session_ws(
    websocket: WebSocket,
    token: str | None = Query(default=None),
    db: DbSession = Depends(get_db),
) -> None:
    # --- handshake: verify the Module 2 JWT before accepting ---
    try:
        resolved = resolve_ws_user(token, db)
    except WsAuthError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="unauthenticated")
        return
    user = resolved.user

    await websocket.accept()

    # --- open or reattach the session (FSM S1 -> S2) ---
    # 2026-09-16: a page refresh (or any ordinary tab-drop-and-reconnect
    # within the grace window below) presents the SAME access token it
    # already had -- same `jti` -- unlike a genuine new login, which always
    # mints a fresh one. Reattaching to that still-ACTIVE session instead of
    # opening a brand-new one is what stops a refresh from silently resetting
    # an in-progress Module 7 trust score back to a fresh login-time
    # baseline, and from dropping a pending re-verify challenge on the floor.
    reattached = False
    existing = session_service.get_active_session_by_token_jti(db, resolved.token_jti)
    if existing is not None:
        session = existing
        reattached = True
        session_service.touch_session(db, session.id)
        session_service.set_ws_connected(db, session.id, True)
        logger.info(
            "ws reattached session=%s user_id=%s (reconnect within grace window)",
            session.id, user.id,
        )
    else:
        try:
            session = session_service.create_session(
                db,
                user=user,
                ip_address=_client_ip(websocket),
                user_agent=websocket.headers.get("user-agent"),
                token_jti=resolved.token_jti,
                token_exp=resolved.token_exp,
            )
        except Exception:  # noqa: BLE001
            logger.exception("failed to open session for user_id=%s", user.id)
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="session open failed")
            return
        session_service.set_ws_connected(db, session.id, True)

    session_id = session.id
    manager.register(session_id, websocket)
    await _send_json(
        websocket,
        {
            "type": "session.established",
            "session_id": session_id,
            "state": SessionState.ACTIVE,
            "server_time": _now_iso(),
            "user": {"id": user.id, "username": user.username, "role": user.role},
            # On a fresh session this is the static score Module 5 computed at
            # open. On a reattach it's whatever Module 7 last recomputed it to
            # -- deliberately NOT reset, that's the whole point of reattaching.
            "trust_score": session.trust_score,
            "risk_level": session.risk_level,
            "reconnected": reattached,
        },
    )
    logger.info("ws attached session=%s user_id=%s", session_id, user.id)

    if reattached:
        # A pending Module 7 re-verify challenge was pushed once, down the
        # NOW-DEAD socket this session had before the drop -- the client's
        # ReverifyModal has no way to know it's still outstanding unless this
        # resends it. Mirrors _push_result's own construction in
        # app/api/v1/endpoints/security.py exactly, so the client sees the
        # identical payload shape whether this is the first push or a resend
        # -- with one deliberate exception: `challenge.dev_code` (the SMTP-
        # unconfigured dev/demo convenience that echoes the raw code back)
        # only ever lives on the in-memory object `mfa_service.create_challenge`
        # returned at the moment of creation (`build_challenge_out` reads a
        # transient `_plaintext_code` attribute -- see mfa/service.py); it is
        # never persisted, by design, since storing a real OTP in cleartext
        # anywhere would be the actual security regression. A freshly
        # re-queried row here (has_open_retrigger_challenge runs its own
        # SELECT) is a different Python object without that attribute, so a
        # resent push always has `dev_code: null` even though the original
        # one didn't -- everything else about the challenge (id, reason,
        # expiry, remaining attempts) is identical. Acceptable: this only
        # affects the local/demo convenience code path in the first place,
        # and the original code is still sitting in that session's server log.
        pending_challenge = continuous_service.has_open_retrigger_challenge(db, session_id)
        if pending_challenge is not None:
            mfa_token = create_mfa_token(
                session.user_id, pending_challenge.id,
                expires_minutes=settings.mfa_challenge_ttl_minutes,
            )
            challenge_out = mfa_service.build_challenge_out(pending_challenge, mfa_token=mfa_token)
            await _send_json(
                websocket,
                {
                    "type": "trust.reverify_required",
                    "session_id": session_id,
                    "risk_level": session.risk_level,
                    "trust_score": session.trust_score,
                    "challenge": challenge_out.model_dump(mode="json"),
                },
            )
            logger.info(
                "resent pending reverify challenge on reattach session=%s", session_id
            )

    heartbeat = max(1, settings.session_ws_heartbeat_seconds)
    reason = TerminationReason.WEBSOCKET_DISCONNECT
    recv_task: asyncio.Task | None = asyncio.create_task(websocket.receive_text())
    try:
        while True:
            done, _pending = await asyncio.wait({recv_task}, timeout=heartbeat)

            # Closed out from under us? (logout / admin DELETE / idle sweep)
            current = session_service.get_session(db, session_id)
            if current is None or current.state != SessionState.ACTIVE:
                reason = (current.termination_reason if current else reason) or reason
                await _send_json(
                    websocket, {"type": "session.terminated", "reason": reason}
                )
                break

            if recv_task in done:
                try:
                    raw = recv_task.result()
                except WebSocketDisconnect:
                    reason = TerminationReason.WEBSOCKET_DISCONNECT
                    recv_task = None
                    break
                session_service.touch_session(db, session_id)
                await _handle_client_message(websocket, raw)
                recv_task = asyncio.create_task(websocket.receive_text())
            else:
                # heartbeat tick, no client message — socket alive, keep it warm
                session_service.touch_session(db, session_id)
    except WebSocketDisconnect:
        reason = TerminationReason.WEBSOCKET_DISCONNECT
    except Exception:  # noqa: BLE001
        logger.exception("ws loop error on session=%s", session_id)
    finally:
        if recv_task is not None:
            if not recv_task.done():
                recv_task.cancel()
            # consume the task's result/exception either way (no "never
            # retrieved" warning) whether it finished, errored, or was cancelled
            with suppress(asyncio.CancelledError, Exception):
                await recv_task
        manager.unregister(session_id)
        session_service.set_ws_connected(db, session_id, False)
        if reason == TerminationReason.WEBSOCKET_DISCONNECT:
            # 2026-09-16: don't finalize an ordinary drop immediately -- give
            # the same browser tab a short window (session_reconnect_grace_
            # seconds) to reconnect with the same token and reattach to THIS
            # session instead of losing its accumulated trust score / pending
            # reverify challenge to a freshly-scored new one (see the
            # reattach block above and _finalize_disconnect's own docstring).
            # A fresh read here (not the `current` from inside the loop,
            # which may be stale or never assigned if the WebSocketDisconnect
            # exception fired before the loop's own next iteration) is what
            # `_finalize_disconnect` compares its wake-up state against.
            current_row = session_service.get_session(db, session_id)
            disconnect_marker = current_row.last_seen_at if current_row else utcnow()
            asyncio.create_task(_finalize_disconnect(session_id, disconnect_marker))
        else:
            # Already ended for a real, already-recorded reason (logout /
            # admin / sweep / risk-revoke) -- this is just the idempotent
            # confirmation, not a fresh decision, so it happens immediately
            # exactly as before this hardening pass.
            session_service.terminate_session(db, session_id, reason=reason)
        with suppress(Exception):
            await websocket.close()
        logger.info(
            "ws detached session=%s reason=%s grace_scheduled=%s",
            session_id, reason, reason == TerminationReason.WEBSOCKET_DISCONNECT,
        )
