"""
Module 8 -- Security Dashboard tests.

Covers the Dashboard Home overview aggregates, the Analytics chart buckets,
the admin lockout list/clear endpoints (the "natural fit for Module 8"
deferred from the Module 6/7 lockout hardening passes -- Project status.md
sections 17b/18), and the admin-only live `/ws/dashboard` feed -- all reading
real state produced by Modules 2-7, never mocked data.
"""
from __future__ import annotations

import time

import pytest
from starlette.websockets import WebSocketDisconnect

from app.core.config import get_settings
from app.models.security_event import SecurityEventType
from app.models.session import Session

settings = get_settings()

ADMIN = {"username": "admin", "email": "admin@example.com", "password": "adminpass123"}
USER = {"username": "alice", "email": "alice@example.com", "password": "alicepass123"}
WS_SESSION_PATH = "/api/v1/ws/session"
WS_DASHBOARD_PATH = "/api/v1/ws/dashboard"


def _register(client, body: dict) -> dict:
    return client.post("/api/v1/auth/register", json=body).json()


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _admin_token(client) -> str:
    return _register(client, ADMIN)["access_token"]


def _user_token(client) -> str:
    return _register(client, USER)["access_token"]


def _login(client) -> dict:
    return client.post(
        "/api/v1/auth/login", json={"username": USER["username"], "password": USER["password"]}
    ).json()


def _force_score(db_session, session_id: str, score: int, risk: str) -> None:
    row = db_session.get(Session, session_id)
    row.trust_score = score
    row.risk_level = risk
    db_session.commit()


def _post_event(client, admin_token: str, session_id: str, event_type: str, ip_address: str | None = None):
    body: dict = {"session_id": session_id, "event_type": event_type}
    if ip_address:
        body["ip_address"] = ip_address
    return client.post("/api/v1/security/events", json=body, headers=_bearer(admin_token))


def _wait_terminated(client, session_id: str, admin_token: str, tries: int = 40):
    """Poll past the (test-shortened, see conftest._fast_reconnect_grace)
    reconnect-grace window for an ordinary WS-drop termination to finalize."""
    for _ in range(tries):
        body = client.get(f"/api/v1/sessions/{session_id}", headers=_bearer(admin_token)).json()
        if body.get("state") == "terminated":
            return body
        time.sleep(0.05)
    return body


# --------------------------------------------------------------------------- #
# GET /dashboard/overview
# --------------------------------------------------------------------------- #
def test_dashboard_overview_is_admin_only(client):
    admin = _admin_token(client)
    user = _user_token(client)

    assert client.get("/api/v1/dashboard/overview").status_code == 401
    assert client.get("/api/v1/dashboard/overview", headers=_bearer(user)).status_code == 403
    assert client.get("/api/v1/dashboard/overview", headers=_bearer(admin)).status_code == 200


def test_dashboard_overview_reflects_real_session_and_acl_state(client):
    admin_token = _admin_token(client)
    user_token = _user_token(client)

    with client.websocket_connect(f"{WS_SESSION_PATH}?token={user_token}") as ws:
        ws.receive_json()  # session.established

        body = client.get("/api/v1/dashboard/overview", headers=_bearer(admin_token)).json()
        assert body["active_users"] == 1
        assert body["active_sessions"] == 1
        assert body["average_trust_score"] is not None
        assert 0 <= body["average_trust_score"] <= 100
        # First-ever login for this user -> a real ACL rule was requested.
        assert body["current_acl_rules"] >= 0
        assert body["high_risk_sessions"] == 0
        assert body["locked_out_accounts"] == 0


def test_dashboard_overview_counts_risk_revoked_sessions(client, db_session):
    admin_token = _admin_token(client)
    user_token = _user_token(client)

    with client.websocket_connect(f"{WS_SESSION_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 60, "MEDIUM")
        _post_event(client, admin_token, session_id, SecurityEventType.ABNORMAL_REQUEST_RATE)
        ws.receive_json()  # session.terminated (risk_revoked)

    body = client.get("/api/v1/dashboard/overview", headers=_bearer(admin_token)).json()
    assert body["revoked_sessions"] >= 1
    assert body["active_sessions"] == 0


# --------------------------------------------------------------------------- #
# GET /dashboard/analytics
# --------------------------------------------------------------------------- #
def test_dashboard_analytics_is_admin_only(client):
    admin = _admin_token(client)
    user = _user_token(client)

    assert client.get("/api/v1/dashboard/analytics").status_code == 401
    assert client.get("/api/v1/dashboard/analytics", headers=_bearer(user)).status_code == 403
    assert client.get("/api/v1/dashboard/analytics", headers=_bearer(admin)).status_code == 200


def test_dashboard_analytics_shape_and_login_activity(client):
    admin_token = _admin_token(client)
    user_token = _user_token(client)

    with client.websocket_connect(f"{WS_SESSION_PATH}?token={user_token}") as ws:
        ws.receive_json()

        body = client.get(
            "/api/v1/dashboard/analytics?days=7", headers=_bearer(admin_token)
        ).json()
        assert len(body["login_activity"]) == 7
        # Two sessions opened today (admin's own WS was never opened here --
        # only the registration; the user's WS above is the one real login).
        today_bucket = body["login_activity"][-1]
        assert today_bucket["count"] >= 1
        assert {b["label"] for b in body["risk_levels"]} == {"LOW", "MEDIUM", "HIGH"}
        assert sum(b["count"] for b in body["risk_levels"]) == 1  # the one active session
        assert {b["label"] for b in body["trust_score_distribution"]}
        assert {b["label"] for b in body["mfa_events"]} == {"pending", "verified", "failed", "expired"}


def test_dashboard_analytics_breaks_down_mfa_and_security_events(client, db_session):
    admin_token = _admin_token(client)
    user_token = _user_token(client)

    with client.websocket_connect(f"{WS_SESSION_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 95, "LOW")
        _post_event(client, admin_token, session_id, SecurityEventType.IP_CHANGE, ip_address="9.9.9.9")
        ws.receive_json()  # trust.updated

    _wait_terminated(client, session_id, admin_token)

    body = client.get("/api/v1/dashboard/analytics", headers=_bearer(admin_token)).json()
    alerts = {b["label"]: b["count"] for b in body["security_alerts"]}
    assert alerts["ip_change"] == 1
    revoked = {b["label"]: b["count"] for b in body["revoked_sessions"]}
    assert revoked["websocket_disconnect"] >= 1


# --------------------------------------------------------------------------- #
# GET /dashboard/lockouts + DELETE /dashboard/lockouts/{id}
# --------------------------------------------------------------------------- #
def test_dashboard_lockouts_is_admin_only(client):
    admin = _admin_token(client)
    user = _user_token(client)

    assert client.get("/api/v1/dashboard/lockouts").status_code == 401
    assert client.get("/api/v1/dashboard/lockouts", headers=_bearer(user)).status_code == 403
    assert client.delete("/api/v1/dashboard/lockouts/1").status_code == 401
    assert client.delete("/api/v1/dashboard/lockouts/1", headers=_bearer(user)).status_code == 403


def test_dashboard_lists_and_clears_an_mfa_lockout(client):
    admin_token = _admin_token(client)
    _user_token(client)

    mfa = _login(client)["mfa"]
    wrong = f"{(int(mfa['dev_code']) + 1) % 1_000_000:06d}"
    for _ in range(settings.mfa_lockout_threshold):
        client.post("/api/v1/mfa/verify", json={"mfa_token": mfa["mfa_token"], "code": wrong})

    body = client.get("/api/v1/dashboard/lockouts", headers=_bearer(admin_token)).json()
    entries = [a for a in body["accounts"] if a["lock_type"] == "mfa"]
    assert len(entries) == 1
    assert entries[0]["username"] == USER["username"]
    assert entries[0]["retry_after_seconds"] > 0
    user_id = entries[0]["user_id"]

    cleared = client.delete(
        f"/api/v1/dashboard/lockouts/{user_id}", headers=_bearer(admin_token)
    ).json()
    assert cleared == {"user_id": user_id, "cleared_mfa": True, "cleared_risk": False}

    body_after = client.get("/api/v1/dashboard/lockouts", headers=_bearer(admin_token)).json()
    assert body_after["accounts"] == []

    # The account can immediately verify again -- the lockout is really gone,
    # not just hidden from the listing.
    mfa2 = _login(client)["mfa"]
    verify = client.post(
        "/api/v1/mfa/verify", json={"mfa_token": mfa2["mfa_token"], "code": mfa2["dev_code"]}
    )
    assert verify.status_code == 200


def test_dashboard_lists_and_clears_a_risk_lockout(client, db_session):
    admin_token = _admin_token(client)
    user_token = _user_token(client)

    with client.websocket_connect(f"{WS_SESSION_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 60, "MEDIUM")
        _post_event(client, admin_token, session_id, SecurityEventType.ABNORMAL_REQUEST_RATE)
        ws.receive_json()  # session.terminated (risk_revoked)

    body = client.get("/api/v1/dashboard/lockouts", headers=_bearer(admin_token)).json()
    entries = [a for a in body["accounts"] if a["lock_type"] == "risk"]
    assert len(entries) == 1
    assert entries[0]["tier"] == 1
    assert entries[0]["username"] == USER["username"]
    user_id = entries[0]["user_id"]

    # Locked out of logging back in right now...
    assert client.post(
        "/api/v1/auth/login", json={"username": USER["username"], "password": USER["password"]}
    ).status_code == 423

    cleared = client.delete(
        f"/api/v1/dashboard/lockouts/{user_id}", headers=_bearer(admin_token)
    ).json()
    assert cleared == {"user_id": user_id, "cleared_mfa": False, "cleared_risk": True}

    # ...and no longer, once cleared.
    login_after = client.post(
        "/api/v1/auth/login", json={"username": USER["username"], "password": USER["password"]}
    )
    assert login_after.status_code != 423


# --------------------------------------------------------------------------- #
# WS /ws/dashboard
# --------------------------------------------------------------------------- #
def test_dashboard_ws_requires_admin(client):
    _admin_token(client)
    user_token = _user_token(client)

    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect(f"{WS_DASHBOARD_PATH}?token={user_token}"):
            pass
    assert excinfo.value.code == 1008


def test_dashboard_ws_rejects_a_missing_token(client):
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect(WS_DASHBOARD_PATH):
            pass
    assert excinfo.value.code == 1008


def test_dashboard_ws_forwards_a_live_security_event(client, db_session):
    admin_token = _admin_token(client)
    user_token = _user_token(client)

    with client.websocket_connect(f"{WS_SESSION_PATH}?token={user_token}") as user_ws:
        session_id = user_ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 95, "LOW")

        with client.websocket_connect(f"{WS_DASHBOARD_PATH}?token={admin_token}") as dash_ws:
            # Let the handler's synchronous accept()+subscribe() prefix run
            # before publishing -- a real Redis pub/sub channel (fakeredis
            # included) never replays a message published before a
            # subscriber attached, so this small allowance is what makes the
            # round trip deterministic rather than a real network race.
            time.sleep(0.2)

            _post_event(client, admin_token, session_id, SecurityEventType.IP_CHANGE, ip_address="9.9.9.9")
            user_ws.receive_json()  # drain the affected session's own trust.updated push

            pushed = dash_ws.receive_json()
            assert pushed["channel"] == "security"
            assert pushed["data"]["event_type"] == "ip_change"
            assert pushed["data"]["session_id"] == session_id
