"""
Module 8 -- Security Dashboard.

    GET    /dashboard/overview       admin: the Dashboard Home stat cards
                                      (Section 5) -- real aggregates over
                                      Modules 2-7's own state.
    GET    /dashboard/analytics      admin: the Analytics charts (Section 5)
                                      -- login activity, trust score
                                      distribution, risk levels, MFA events,
                                      revoked sessions, security alerts, plus
                                      the ACL latency averages.
    GET    /dashboard/lockouts       admin: every account currently under
                                      the Module 6 MFA lockout or the
                                      Module 7 risk lockout -- the admin
                                      "unlock" UI explicitly deferred from
                                      those hardening passes to "a natural
                                      fit for Module 8" (Project status.md
                                      sections 17b/18).
    DELETE /dashboard/lockouts/{id}  admin: clear BOTH lockout types for one
                                      account -- the documented
                                      `redis-cli DEL ...` fallback, as a
                                      real button.
    WS     /ws/dashboard?token=      admin-only: forwards the Redis pub/sub
                                      events every other module already
                                      publishes (`ztsaacm:events:session` M3,
                                      `ztsaacm:events:acl` M4,
                                      `ztsaacm:events:mfa` M6,
                                      `ztsaacm:events:security` M7) so the
                                      admin dashboard updates live instead of
                                      only on its own polling interval --
                                      Section 5's "real-time updates via
                                      WebSocket" requirement. Every admin
                                      page keeps its existing REST polling as
                                      the source of truth and fallback; this
                                      is a purely additive "something
                                      changed" signal layered on top, not a
                                      replacement data path.

The aggregation logic lives in app.services.dashboard (pure reads over
Modules 2-7's own tables/Redis state -- no new persisted state, no
migration). This endpoint's own job is the HTTP/WebSocket surface only.
"""
from __future__ import annotations

import asyncio
import json
from contextlib import suppress

from fastapi import APIRouter, Depends, Query, WebSocket, status
from sqlalchemy.orm import Session as DbSession
from starlette.websockets import WebSocketDisconnect

from app.api.deps import CurrentAdmin, get_db
from app.core.logging import get_logger
from app.core.redis_client import get_redis
from app.schemas.dashboard import (
    DashboardAnalyticsResponse,
    DashboardOverviewResponse,
    LockedAccountsResponse,
    LockoutClearedResponse,
)
from app.services import dashboard as dashboard_service
from app.ws.auth import WsAuthError, resolve_ws_user

router = APIRouter()
logger = get_logger(__name__)

# Every live event channel this codebase already publishes to (Modules 3/4/6)
# plus the one Module 7 gained alongside this module (see
# app.services.trust_score.continuous._EVENT_CHANNEL). Postgres remains the
# authoritative store for all of it -- this WebSocket only ever tells the
# client "something changed, you may want to refetch," never carries state
# of its own.
_CHANNELS = (
    "ztsaacm:events:session",
    "ztsaacm:events:acl",
    "ztsaacm:events:mfa",
    "ztsaacm:events:security",
)
# How often the WS loop checks for a client disconnect / pending pub/sub
# message. Short enough to feel live, long enough not to busy-loop.
_POLL_INTERVAL_SECONDS = 0.25


@router.get(
    "/dashboard/overview",
    tags=["dashboard"],
    response_model=DashboardOverviewResponse,
    summary="Dashboard Home stat cards (admin) -- Section 5",
)
def dashboard_overview(
    _admin: CurrentAdmin, db: DbSession = Depends(get_db)
) -> DashboardOverviewResponse:
    return DashboardOverviewResponse(**dashboard_service.overview(db))


@router.get(
    "/dashboard/analytics",
    tags=["dashboard"],
    response_model=DashboardAnalyticsResponse,
    summary="Analytics charts (admin) -- Section 5",
)
def dashboard_analytics(
    _admin: CurrentAdmin,
    db: DbSession = Depends(get_db),
    days: int = Query(
        default=14, ge=1, le=90, description="Login-activity window, in days"
    ),
) -> DashboardAnalyticsResponse:
    return DashboardAnalyticsResponse(**dashboard_service.analytics(db, days=days))


@router.get(
    "/dashboard/lockouts",
    tags=["dashboard"],
    response_model=LockedAccountsResponse,
    summary="Accounts currently under an MFA or risk lockout (admin)",
)
def dashboard_lockouts(
    _admin: CurrentAdmin, db: DbSession = Depends(get_db)
) -> LockedAccountsResponse:
    return LockedAccountsResponse(accounts=dashboard_service.locked_accounts(db))


@router.delete(
    "/dashboard/lockouts/{user_id}",
    tags=["dashboard"],
    response_model=LockoutClearedResponse,
    summary="Clear an account's MFA + risk lockouts (admin)",
)
def clear_dashboard_lockout(user_id: int, _admin: CurrentAdmin) -> LockoutClearedResponse:
    return LockoutClearedResponse(**dashboard_service.clear_lockouts(user_id))


def _forward_shape(message: dict) -> dict | None:
    """One raw redis-py pubsub message -> the shape pushed to the dashboard
    socket, or None for a message this loop shouldn't forward (subscribe/
    unsubscribe confirmations already filtered by `ignore_subscribe_messages`,
    kept here only as a defensive second check)."""
    if message.get("type") != "message":
        return None
    channel = str(message.get("channel") or "")
    # "ztsaacm:events:security" -> "security", etc. -- a short, stable tag the
    # frontend switches on, independent of this project's Redis key prefix.
    short_channel = channel.rsplit(":", 1)[-1]
    raw_data = message.get("data")
    try:
        data = json.loads(raw_data) if isinstance(raw_data, str) else raw_data
    except (TypeError, ValueError):
        data = raw_data
    return {"channel": short_channel, "data": data}


@router.websocket("/ws/dashboard")
async def dashboard_ws(
    websocket: WebSocket,
    token: str | None = Query(default=None),
    db: DbSession = Depends(get_db),
) -> None:
    # --- handshake: same JWT verification every other socket in this app
    # uses, plus an admin check this one alone needs (the dashboard's live
    # feed spans every user's sessions/events, not just the caller's own). ---
    try:
        resolved = resolve_ws_user(token, db)
    except WsAuthError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="unauthenticated")
        return
    if not resolved.user.is_admin:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="admin required")
        return

    await websocket.accept()

    pubsub = get_redis().pubsub()
    try:
        pubsub.subscribe(*_CHANNELS)
    except Exception:  # noqa: BLE001 - Redis down: the socket still opens, it just never pushes
        logger.warning("dashboard ws: redis subscribe failed", exc_info=True)

    logger.info("dashboard ws attached user_id=%s", resolved.user.id)
    recv_task: asyncio.Task | None = asyncio.create_task(websocket.receive_text())
    try:
        while True:
            done, _pending = await asyncio.wait({recv_task}, timeout=_POLL_INTERVAL_SECONDS)

            if recv_task in done:
                try:
                    recv_task.result()
                except WebSocketDisconnect:
                    break
                # The dashboard socket is push-only from the server's side; any
                # client message (e.g. a keepalive ping) is simply drained.
                recv_task = asyncio.create_task(websocket.receive_text())

            while True:
                try:
                    message = pubsub.get_message(ignore_subscribe_messages=True, timeout=0)
                except Exception:  # noqa: BLE001 - a transient Redis blip must not kill the socket
                    logger.debug("dashboard ws: redis get_message failed", exc_info=True)
                    break
                if message is None:
                    break
                shaped = _forward_shape(message)
                if shaped is not None:
                    await websocket.send_json(shaped)
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        logger.exception("dashboard ws loop error")
    finally:
        if recv_task is not None:
            if not recv_task.done():
                recv_task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await recv_task
        with suppress(Exception):
            pubsub.close()
        with suppress(Exception):
            await websocket.close()
        logger.info("dashboard ws detached user_id=%s", resolved.user.id)
