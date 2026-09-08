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
        # trust_score / risk_level are still reserved (Module 5); acl_status is
        # populated from Module 4 on (an ACL rule was just requested).
        assert row["trust_score"] is None
        assert row["risk_level"] is None
        assert row["acl_status"] in ("pending", "active")


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

    # once the socket closes there is no active session
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
