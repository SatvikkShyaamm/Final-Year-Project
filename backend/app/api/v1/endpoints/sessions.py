"""
Module 3 — Session Lifecycle.

    WS     /ws/session?token=<jwt>   signalling socket: open == session active
    GET    /sessions                 admin: live (and optionally past) sessions
    GET    /sessions/current         caller's own current active session
    GET    /sessions/{id}            one session (admin, or its owner)
    DELETE /sessions/{id}            admin: force-terminate a session

The socket is the base paper's SS-PDP signalling channel: its onopen drives
FSM S1 -> S2 (session active), its onclose drives S2 -> S3 -> gone. Logout
(Module 2 endpoint), an admin DELETE here, and the idle sweeper (app.main)
are the other ways a session leaves S2 — all of them go through
``services.session.terminate_session`` so the FSM stays authoritative.

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
from app.core.logging import get_logger
from app.models.session import SessionState, TerminationReason
from app.schemas.session import (
    SessionListResponse,
    SessionRead,
    SessionTerminateResponse,
)
from app.services import acl as acl_service
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

    # --- open the session (FSM S1 -> S2) ---
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

    session_id = session.id
    manager.register(session_id, websocket)
    session_service.set_ws_connected(db, session_id, True)
    await _send_json(
        websocket,
        {
            "type": "session.established",
            "session_id": session_id,
            "state": SessionState.ACTIVE,
            "server_time": _now_iso(),
            "user": {"id": user.id, "username": user.username, "role": user.role},
            # Static trust score, computed by the session_opened hook (Module 5).
            "trust_score": session.trust_score,
            "risk_level": session.risk_level,
        },
    )
    logger.info("ws attached session=%s user_id=%s", session_id, user.id)

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
        # Idempotent: if logout/admin/sweep already terminated it, this keeps
        # the original reason; otherwise this is the real S2 -> S3 close.
        session_service.terminate_session(db, session_id, reason=reason)
        with suppress(Exception):
            await websocket.close()
        logger.info("ws detached session=%s reason=%s", session_id, reason)
