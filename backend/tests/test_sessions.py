"""
Module 3 — Session Lifecycle tests.

Exercises the deliverable end to end: WebSocket connect -> active session ->
(logout / disconnect / admin terminate / timeout) -> session terminated, plus
the admin REST feed the dashboard reads.
"""
from __future__ import annotations

import time
from contextlib import suppress
from datetime import timedelta

import pytest
from sqlalchemy.orm import sessionmaker
from starlette.websockets import WebSocketDisconnect

from app.core.security import create_access_token
from app.models.session import Session, SessionState, utcnow
from app.models.user import User
from app.services import session as session_service

ADMIN = {"username": "admin", "email": "admin@example.com", "password": "adminpass123"}
USER = {"username": "alice", "email": "alice@example.com", "password": "alicepass123"}

WS_PATH = "/api/v1/ws/session"


def _register(client, body: dict) -> dict:
    return client.post("/api/v1/auth/register", json=body).json()


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def admin_token(client) -> str:
    return _register(client, ADMIN)["access_token"]


@pytest.fixture()
def user_token(client, admin_token) -> str:
    # admin_token first so the first-user-is-admin rule makes 'alice' a plain user
    return _register(client, USER)["access_token"]


def _wait_terminated(client, session_id: str, admin_token: str, tries: int = 20):
    """Poll a session until it leaves the ACTIVE state (socket teardown is async)."""
    for _ in range(tries):
        body = client.get(
            f"/api/v1/sessions/{session_id}", headers=_bearer(admin_token)
        ).json()
        if body.get("state") == SessionState.TERMINATED:
            return body
        time.sleep(0.05)
    return body


# --------------------------------------------------------------------------- #
# WebSocket open == session active
# --------------------------------------------------------------------------- #
def test_ws_connect_opens_active_session(client, admin_token, user_token):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        established = ws.receive_json()
        assert established["type"] == "session.established"
        assert established["state"] == "active"
        session_id = established["session_id"]

        listing = client.get("/api/v1/sessions", headers=_bearer(admin_token)).json()
        assert listing["active_count"] == 1
        row = listing["sessions"][0]
        assert row["id"] == session_id
        assert row["state"] == "active"
        assert row["ws_connected"] is True
        assert row["username"] == "alice"
        # acl_status populated from Module 4; trust_score / risk_level from
        # Module 5 (static score computed at session open — first-ever session
        # for this user lands in the MEDIUM band, baseline 70 give or take the
        # off-hours factor).
        assert row["acl_status"] in ("pending", "active")
        assert 60 <= row["trust_score"] <= 100
        assert row["risk_level"] in ("LOW", "MEDIUM", "HIGH")


def test_ws_disconnect_terminates_session(client, admin_token, user_token):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]

    body = _wait_terminated(client, session_id, admin_token)
    assert body["state"] == "terminated"
    assert body["termination_reason"] == "websocket_disconnect"
    assert body["ws_connected"] is False


def test_ping_pong(client, user_token):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        ws.receive_json()  # session.established
        ws.send_json({"type": "ping"})
        reply = ws.receive_json()
        assert reply["type"] == "pong"
        assert "server_time" in reply


# --------------------------------------------------------------------------- #
# Reconnect-within-grace reattach (2026-09-16 hardening)
#
# The gap this closes: a page refresh drops the WS exactly like a closed tab
# does (indistinguishable at the transport level) -- before this, that ALWAYS
# meant "session over, open a fresh one," so refreshing mid-session silently
# reset an in-progress Module 7 trust score back to a brand-new login-time
# baseline and dropped any pending reverify challenge. Now an ordinary drop
# sits in a short grace window (`session_reconnect_grace_seconds`, monkey-
# patched short for this whole suite -- see conftest.py's
# `_fast_reconnect_grace`) during which a reconnect presenting the SAME
# access token (same `jti` -- a genuine new login always mints a fresh one)
# reattaches to that exact session instead.
# --------------------------------------------------------------------------- #
def test_refresh_reconnect_reattaches_without_resetting_the_score(
    client, admin_token, user_token, db_session
):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]

    # Simulate the session having already been marked down mid-session by
    # Module 7 (a real IP-change/VPN/etc. event -- see test_continuous_trust.py
    # for that path in full) BEFORE the "refresh" reconnects.
    row = db_session.get(Session, session_id)
    row.trust_score = 55
    row.risk_level = "MEDIUM"
    db_session.commit()

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws2:
        established = ws2.receive_json()
        assert established["type"] == "session.established"
        assert established["session_id"] == session_id  # the SAME session
        assert established["reconnected"] is True
        assert established["trust_score"] == 55   # NOT reset to a fresh baseline
        assert established["risk_level"] == "MEDIUM"

    # it was reattached, not closed-and-reopened -- the row stayed ACTIVE the
    # whole time this test has been running (well inside the grace window).
    row_after = client.get(
        f"/api/v1/sessions/{session_id}", headers=_bearer(admin_token)
    ).json()
    assert row_after["state"] == "active"


def test_reconnect_after_grace_window_opens_a_genuinely_new_session(
    client, admin_token, user_token
):
    """Reattachment is bounded, not permanent amnesty for a dead token. If
    nobody reconnects before the grace window elapses, the old session is
    finalized for real, and a LATER reconnect with the same (still-valid)
    token opens a brand-new session -- the pre-2026-09-16 behaviour, correctly
    preserved for a tab that's actually gone rather than just refreshing."""
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        first_id = ws.receive_json()["session_id"]

    _wait_terminated(client, first_id, admin_token)  # let the grace window lapse

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws2:
        established = ws2.receive_json()
        assert established["session_id"] != first_id
        assert established["reconnected"] is False

    first_row = client.get(
        f"/api/v1/sessions/{first_id}", headers=_bearer(admin_token)
    ).json()
    assert first_row["state"] == "terminated"
    assert first_row["termination_reason"] == "websocket_disconnect"


def test_a_different_token_never_reattaches_even_if_reconnecting_instantly(
    client, admin_token, user_token
):
    """Reattachment is scoped to the EXACT token (its `jti`), not "this user
    reconnected recently" -- a genuine second login (a different token, even
    for the same account) must always open its own independent session, same
    as before this hardening pass, regardless of timing."""
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        first_id = ws.receive_json()["session_id"]

    me = client.get("/api/v1/auth/me", headers=_bearer(user_token)).json()
    second_token = create_access_token(me["id"])

    # reconnect immediately (well inside the grace window) but with a
    # DIFFERENT token for the same account.
    with client.websocket_connect(f"{WS_PATH}?token={second_token}") as ws2:
        established = ws2.receive_json()
        assert established["session_id"] != first_id
        assert established["reconnected"] is False


# --------------------------------------------------------------------------- #
# Handshake auth
# --------------------------------------------------------------------------- #
def test_ws_rejects_missing_token(client):
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect(WS_PATH):
            pass
    assert excinfo.value.code == 1008


def test_ws_rejects_bad_token(client):
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect(f"{WS_PATH}?token=not-a-jwt"):
            pass
    assert excinfo.value.code == 1008


# --------------------------------------------------------------------------- #
# REST feed
# --------------------------------------------------------------------------- #
def test_list_sessions_requires_admin(client, admin_token, user_token):
    assert client.get("/api/v1/sessions").status_code == 401
    assert client.get("/api/v1/sessions", headers=_bearer(user_token)).status_code == 403
    assert client.get("/api/v1/sessions", headers=_bearer(admin_token)).status_code == 200


def test_get_current_session_for_caller(client, admin_token, user_token):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        current = client.get(
            "/api/v1/sessions/current", headers=_bearer(user_token)
        ).json()
        assert current["id"] == session_id

    # 2026-09-16: an ordinary socket close is no longer instantly final -- it
    # sits inside the reconnect-grace window (see sessions.py's WS handler)
    # in case the same tab reconnects, so the session is still "current"
    # immediately after the `with` block exits.
    current = client.get("/api/v1/sessions/current", headers=_bearer(user_token)).json()
    assert current is not None
    assert current["id"] == session_id

    # only once the grace window actually elapses with nobody reattaching
    # does it stop being the caller's current session.
    body = _wait_terminated(client, session_id, admin_token)
    assert body["state"] == "terminated"
    assert client.get("/api/v1/sessions/current", headers=_bearer(user_token)).json() is None


def test_get_other_users_session_is_forbidden(client, admin_token, user_token):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        # admin may look
        assert client.get(
            f"/api/v1/sessions/{session_id}", headers=_bearer(admin_token)
        ).status_code == 200
        # a different non-admin may not — register a second plain user
        other = _register(
            client,
            {"username": "bob", "email": "bob@example.com", "password": "bobpass12345"},
        )["access_token"]
        assert client.get(
            f"/api/v1/sessions/{session_id}", headers=_bearer(other)
        ).status_code == 403


# --------------------------------------------------------------------------- #
# Termination paths
# --------------------------------------------------------------------------- #
def test_admin_can_terminate_session(client, admin_token, user_token):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        resp = client.delete(
            f"/api/v1/sessions/{session_id}", headers=_bearer(admin_token)
        )
        assert resp.status_code == 200
        assert resp.json()["state"] == "terminated"
        assert resp.json()["termination_reason"] == "admin_terminated"
        with suppress(Exception):
            ws.receive_json()  # may deliver {"type": "session.terminated"} before close

    body = _wait_terminated(client, session_id, admin_token)
    assert body["termination_reason"] == "admin_terminated"


def test_terminate_unknown_session_404(client, admin_token):
    assert client.delete(
        "/api/v1/sessions/does-not-exist", headers=_bearer(admin_token)
    ).status_code == 404


def test_logout_terminates_active_sessions(client, admin_token, user_token):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        resp = client.post("/api/v1/auth/logout", headers=_bearer(user_token))
        assert resp.status_code == 200
        assert session_id in resp.json()["terminated_sessions"]
        with suppress(Exception):
            ws.receive_json()

    body = _wait_terminated(client, session_id, admin_token)
    assert body["termination_reason"] == "logout"


# --------------------------------------------------------------------------- #
# Idle / lifetime sweeper (unit-level)
# --------------------------------------------------------------------------- #
def test_sweeper_closes_idle_session(db_engine):
    TestingSessionLocal = sessionmaker(bind=db_engine, autoflush=False, future=True)
    db = TestingSessionLocal()
    try:
        user = User(
            username="stale", email="stale@example.com",
            hashed_password="x", role="user",
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        old = utcnow() - timedelta(hours=2)  # well past the 30-min idle timeout
        stale = Session(
            id="a" * 32, user_id=user.id, state=SessionState.ACTIVE,
            created_at=old, last_seen_at=old,
        )
        db.add(stale)
        db.commit()

        closed = session_service.sweep_expired_sessions(db)
        assert "a" * 32 in closed

        db.refresh(stale)
        assert stale.state == SessionState.TERMINATED
        assert stale.termination_reason == "idle_timeout"
    finally:
        db.close()
