"""
Module 9 -- Attack Simulation tests.

Every scenario is required to trigger REAL backend logic (Section 15: "these
should trigger the actual backend logic rather than simply changing text on
the UI"), so these tests assert on the actual resulting trust score/risk/
session state, not just a 200 status code -- exercising the exact same
continuous-evaluation pipeline (Module 7) and session-termination pipeline
(Module 3) the manual admin Trigger and the real automatic detectors already
use, per app.services.simulation's own docstring.
"""
from __future__ import annotations

import time

import pytest

from app.core.config import get_settings
from app.core.security import create_access_token
from app.models.session import Session, SessionState

settings = get_settings()

ADMIN = {"username": "admin", "email": "admin@example.com", "password": "adminpass123"}
USER = {"username": "alice", "email": "alice@example.com", "password": "alicepass123"}
WS_PATH = "/api/v1/ws/session"

ALL_SCENARIOS = (
    "ip_change",
    "approved_vpn",
    "unknown_vpn",
    "unknown_device",
    "large_download",
    "abnormal_requests",
    "failed_login",
    "session_termination",
)


def _register(client, body: dict) -> dict:
    return client.post("/api/v1/auth/register", json=body).json()


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def admin_token(client) -> str:
    return _register(client, ADMIN)["access_token"]


@pytest.fixture()
def user_token(client, admin_token) -> str:
    return _register(client, USER)["access_token"]


def _second_token_for(client, existing_token: str) -> str:
    """A second, independently-minted token for the same account -- see
    test_continuous_trust.py's identical helper for the full rationale
    (avoids a real second /auth/login's own Adaptive MFA risk evaluation)."""
    user_id = client.get("/api/v1/auth/me", headers=_bearer(existing_token)).json()["id"]
    return create_access_token(user_id)


def _force_score(db_session, session_id: str, score: int, risk: str) -> None:
    row = db_session.get(Session, session_id)
    row.trust_score = score
    row.risk_level = risk
    db_session.commit()


def _simulate(client, admin_token: str, scenario: str, session_id: str):
    return client.post(
        f"/api/v1/simulate/{scenario}",
        json={"session_id": session_id},
        headers=_bearer(admin_token),
    )


# --------------------------------------------------------------------------- #
# GET /simulate/scenarios
# --------------------------------------------------------------------------- #
def test_scenarios_endpoint_is_admin_only(client):
    admin = _register(client, ADMIN)["access_token"]
    user = _register(client, USER)["access_token"]

    assert client.get("/api/v1/simulate/scenarios").status_code == 401
    assert client.get("/api/v1/simulate/scenarios", headers=_bearer(user)).status_code == 403
    assert client.get("/api/v1/simulate/scenarios", headers=_bearer(admin)).status_code == 200


def test_scenarios_lists_all_eight(client, admin_token):
    body = client.get("/api/v1/simulate/scenarios", headers=_bearer(admin_token)).json()
    keys = {s["scenario"] for s in body["scenarios"]}
    assert keys == set(ALL_SCENARIOS)
    labels = {s["label"] for s in body["scenarios"]}
    assert "Simulate Approved VPN" in labels
    assert "Simulate Unknown VPN" in labels
    assert "Simulate Session Termination" in labels


# --------------------------------------------------------------------------- #
# validation / RBAC
# --------------------------------------------------------------------------- #
def test_simulate_is_admin_only(client, admin_token, user_token):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]

        resp_no_auth = client.post(
            "/api/v1/simulate/ip_change", json={"session_id": session_id}
        )
        assert resp_no_auth.status_code == 401
        resp_user = client.post(
            "/api/v1/simulate/ip_change",
            json={"session_id": session_id},
            headers=_bearer(user_token),
        )
        assert resp_user.status_code == 403


def test_simulate_unknown_scenario_is_rejected(client, admin_token, user_token):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        resp = _simulate(client, admin_token, "totally_bogus_scenario", session_id)
        assert resp.status_code == 400


def test_simulate_against_unknown_session_is_404(client, admin_token):
    resp = _simulate(client, admin_token, "ip_change", "does-not-exist")
    assert resp.status_code == 404


def test_simulate_against_a_terminated_session_is_409(client, admin_token, user_token):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]

    # An ordinary disconnect isn't finalized instantly (2026-09-16's
    # reconnect-grace hardening -- see conftest._fast_reconnect_grace) --
    # wait past the (test-shortened) grace window before this session is
    # genuinely no longer ACTIVE.
    for _ in range(40):
        row = client.get(f"/api/v1/sessions/{session_id}", headers=_bearer(admin_token)).json()
        if row.get("state") == "terminated":
            break
        time.sleep(0.05)

    resp = _simulate(client, admin_token, "ip_change", session_id)
    assert resp.status_code == 409


# --------------------------------------------------------------------------- #
# each scenario triggers the real backend logic
# --------------------------------------------------------------------------- #
def test_simulate_ip_change_applies_the_real_weight(client, admin_token, user_token, db_session):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 95, "LOW")

        resp = _simulate(client, admin_token, "ip_change", session_id)
        assert resp.status_code == 200
        body = resp.json()
        assert body["scenario"] == "ip_change"
        assert body["event_type"] == "ip_change"
        assert body["previous_score"] == 95
        assert body["new_score"] == 95 - settings.trust_weight_ip_changed
        assert body["source"] == "admin"

        push = ws.receive_json()
        assert push["type"] == "trust.updated"
        assert push["trust_score"] == body["new_score"]


def test_simulate_approved_vpn_picks_a_real_ip_and_scores_positive(
    client, admin_token, user_token, db_session
):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 70, "MEDIUM")

        resp = _simulate(client, admin_token, "approved_vpn", session_id)
        assert resp.status_code == 200
        body = resp.json()
        assert body["event_type"] == "vpn_detected"
        assert body["weight_applied"] == settings.trust_weight_approved_vpn
        assert body["new_score"] == 70 + settings.trust_weight_approved_vpn
        assert "approved" in body["reason"].lower()


def test_simulate_unknown_vpn_picks_a_real_ip_and_scores_negative(
    client, admin_token, user_token, db_session
):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 95, "LOW")

        resp = _simulate(client, admin_token, "unknown_vpn", session_id)
        assert resp.status_code == 200
        body = resp.json()
        assert body["event_type"] == "vpn_detected"
        assert body["new_score"] == 95 - settings.trust_weight_unknown_vpn


def test_simulate_unknown_device_applies_the_real_weight(
    client, admin_token, user_token, db_session
):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 95, "LOW")

        body = _simulate(client, admin_token, "unknown_device", session_id).json()
        assert body["event_type"] == "unknown_device"
        assert body["new_score"] == 95 - settings.trust_weight_unknown_device


def test_simulate_large_download_applies_the_real_weight(
    client, admin_token, user_token, db_session
):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 95, "LOW")

        body = _simulate(client, admin_token, "large_download", session_id).json()
        assert body["event_type"] == "large_download"
        assert body["new_score"] == 95 - settings.trust_weight_large_download


def test_simulate_abnormal_requests_applies_the_real_weight(
    client, admin_token, user_token, db_session
):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 95, "LOW")

        body = _simulate(client, admin_token, "abnormal_requests", session_id).json()
        assert body["event_type"] == "abnormal_request_rate"
        assert body["new_score"] == 95 - settings.trust_weight_abnormal_request_rate


def test_simulate_failed_login_fires_the_real_detector_against_every_active_session(
    client, admin_token, user_token, db_session
):
    user_token_b = _second_token_for(client, user_token)

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws_a:
        session_a = ws_a.receive_json()["session_id"]
        _force_score(db_session, session_a, 95, "LOW")

        with client.websocket_connect(f"{WS_PATH}?token={user_token_b}") as ws_b:
            session_b = ws_b.receive_json()["session_id"]
            _force_score(db_session, session_b, 95, "LOW")

            resp = _simulate(client, admin_token, "failed_login", session_a)
            assert resp.status_code == 200
            body = resp.json()
            assert body["event_type"] == "multiple_failed_logins"
            # The REAL detector -- unlike the other six scenarios -- is
            # auto-tagged, since it runs through the exact same code path a
            # genuine password-guessing attacker would trip.
            assert body["source"] == "auto"
            assert body["new_score"] == 95 - settings.trust_weight_failed_logins

            # Every other active session on the account was hit too.
            push_a = ws_a.receive_json()
            assert push_a["trust_score"] == body["new_score"]
            push_b = ws_b.receive_json()
            assert push_b["trust_score"] == 95 - settings.trust_weight_failed_logins

            events = client.get(
                "/api/v1/security/events", headers=_bearer(admin_token)
            ).json()["events"]
            fired = [e for e in events if e["event_type"] == "multiple_failed_logins"]
            assert len(fired) == 2
            assert all(e["source"] == "auto" for e in fired)


def test_simulate_failed_login_only_fires_once_per_window(
    client, admin_token, user_token, db_session
):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 95, "LOW")

        first = _simulate(client, admin_token, "failed_login", session_id)
        assert first.json()["new_score"] == 95 - settings.trust_weight_failed_logins
        ws.receive_json()  # trust.updated

        # The burst window already fired -- a second simulate call for the
        # same window produces no further event (mirrors request_rate.py's
        # identical fire-once-per-window guard for abnormal_request_rate).
        second = _simulate(client, admin_token, "failed_login", session_id)
        assert second.status_code == 200
        body = second.json()
        assert body["event_type"] is None
        assert body["new_score"] is None


def test_simulate_session_termination_terminates_the_real_session(
    client, admin_token, user_token
):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]

        resp = _simulate(client, admin_token, "session_termination", session_id)
        assert resp.status_code == 200
        body = resp.json()
        assert body["state"] == "terminated"
        assert body["termination_reason"] == "admin_terminated"

        push = ws.receive_json()
        assert push == {"type": "session.terminated", "reason": "admin_terminated"}

    row = client.get(f"/api/v1/sessions/{session_id}", headers=_bearer(admin_token)).json()
    assert row["state"] == "terminated"
    assert row["termination_reason"] == "admin_terminated"
    # server-side token revocation follows for free via app.services.auth.wiring
    assert client.get("/api/v1/auth/me", headers=_bearer(user_token)).status_code == 401


def test_simulate_crossing_into_high_revokes_and_locks_the_account(
    client, admin_token, user_token, db_session
):
    """Confirms Module 9's scenarios drive the exact same real pipeline as
    every other continuous-evaluation trigger -- including the Section 18
    account-level risk lockout -- not a simplified/parallel code path."""
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 55, "MEDIUM")

        resp = _simulate(client, admin_token, "abnormal_requests", session_id)
        assert resp.status_code == 200
        body = resp.json()
        assert body["action"] == "revoke"
        assert body["new_risk"] == "HIGH"

        terminated = ws.receive_json()
        assert terminated == {"type": "session.terminated", "reason": "risk_revoked"}

    locked = client.post(
        "/api/v1/auth/login", json={"username": USER["username"], "password": USER["password"]}
    )
    assert locked.status_code == 423
