"""
Module 7 -- Continuous Trust Evaluation tests.

Exercises the deliverable end to end: ingest a mid-session security event ->
trust score recomputed against its CURRENT value -> risk-based action (none /
reverify / revoke) -> the resulting WebSocket push/close and session/ACL/
token state. Re-verification reuses Module 6's email one-time-code mechanism
unchanged (no TOTP -- see docs/architecture.md and Project status.md
section 11).
"""
from __future__ import annotations

import time

import pytest

from app.core.config import get_settings
from app.models.security_event import SecurityEventType
from app.models.session import Session, SessionState

settings = get_settings()

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
    return _register(client, USER)["access_token"]


def _force_score(db_session, session_id: str, score: int, risk: str) -> None:
    """Directly set a live session's current score/risk, bypassing the need
    to simulate realistic login-time history just to reach a starting band."""
    row = db_session.get(Session, session_id)
    row.trust_score = score
    row.risk_level = risk
    db_session.commit()


def _post_event(client, admin_token: str, session_id: str, event_type: str, ip_address: str | None = None):
    body: dict = {"session_id": session_id, "event_type": event_type}
    if ip_address:
        body["ip_address"] = ip_address
    return client.post("/api/v1/security/events", json=body, headers=_bearer(admin_token))


def _wait_terminated(client, session_id: str, admin_token: str, tries: int = 20):
    for _ in range(tries):
        body = client.get(f"/api/v1/sessions/{session_id}", headers=_bearer(admin_token)).json()
        if body.get("state") == SessionState.TERMINATED:
            return body
        time.sleep(0.05)
    return body


# --------------------------------------------------------------------------- #
# action: none
# --------------------------------------------------------------------------- #
def test_event_with_small_impact_keeps_low_risk_and_takes_no_action(client, admin_token, user_token, db_session):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 95, "LOW")

        resp = _post_event(client, admin_token, session_id, SecurityEventType.IP_CHANGE, ip_address="9.9.9.9")
        assert resp.status_code == 200
        body = resp.json()
        assert body["action"] == "none"
        assert body["previous_score"] == 95
        assert body["new_score"] == 85
        assert body["new_risk"] == "LOW"
        assert body["mfa_challenge_id"] is None

        row = client.get(f"/api/v1/sessions/{session_id}", headers=_bearer(admin_token)).json()
        assert row["trust_score"] == 85
        assert row["current_action"] is None


# --------------------------------------------------------------------------- #
# action: reverify
# --------------------------------------------------------------------------- #
def test_event_crossing_into_medium_triggers_reverify_and_pushes_ws_message(
    client, admin_token, user_token, db_session
):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 85, "LOW")

        # 185.220.100.7 is in the default TRUST_KNOWN_VPN_CIDRS_RAW sample -> -15
        resp = _post_event(
            client, admin_token, session_id, SecurityEventType.VPN_DETECTED, ip_address="185.220.100.7"
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["action"] == "reverify"
        assert body["new_score"] == 70
        assert body["new_risk"] == "MEDIUM"
        assert body["mfa_challenge_id"]

        push = ws.receive_json()
        assert push["type"] == "trust.reverify_required"
        assert push["session_id"] == session_id
        assert push["risk_level"] == "MEDIUM"
        challenge = push["challenge"]
        assert challenge["challenge_id"] == body["mfa_challenge_id"]
        assert challenge["mfa_token"]
        assert challenge["reason"] == "risk_retrigger"
        assert challenge["dev_code"]  # no SMTP configured in tests

        row = client.get(f"/api/v1/sessions/{session_id}", headers=_bearer(admin_token)).json()
        assert row["current_action"] == "reverify_required"

        listing = client.get("/api/v1/sessions", headers=_bearer(admin_token)).json()
        listed = next(r for r in listing["sessions"] if r["id"] == session_id)
        assert listed["current_action"] == "reverify_required"


def test_second_medium_event_reuses_the_pending_challenge_no_spam(
    client, admin_token, user_token, db_session
):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 85, "LOW")

        first = _post_event(
            client, admin_token, session_id, SecurityEventType.VPN_DETECTED, ip_address="185.220.100.7"
        )
        challenge_id = first.json()["mfa_challenge_id"]
        ws.receive_json()  # trust.reverify_required

        second = _post_event(client, admin_token, session_id, SecurityEventType.IP_CHANGE, ip_address="1.2.3.4")
        body2 = second.json()
        assert body2["action"] == "reverify"
        assert body2["mfa_challenge_id"] == challenge_id  # reused, not a fresh email

        push2 = ws.receive_json()
        assert push2["challenge"]["challenge_id"] == challenge_id


def test_reverify_success_keeps_session_alive_without_restoring_score(
    client, admin_token, user_token, db_session
):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 85, "LOW")

        _post_event(client, admin_token, session_id, SecurityEventType.VPN_DETECTED, ip_address="185.220.100.7")
        challenge = ws.receive_json()["challenge"]

        verify = client.post(
            "/api/v1/mfa/verify",
            json={"mfa_token": challenge["mfa_token"], "code": challenge["dev_code"]},
        )
        assert verify.status_code == 200
        assert verify.json()["access_token"]

        reverified = ws.receive_json()
        assert reverified == {"type": "trust.reverified", "session_id": session_id}

        row = client.get(f"/api/v1/sessions/{session_id}", headers=_bearer(admin_token)).json()
        assert row["state"] == "active"
        assert row["trust_score"] == 70  # NOT restored -- passing MFA doesn't erase the signal
        assert row["current_action"] is None  # no longer pending


def test_reverify_exhaustion_revokes_the_session(client, admin_token, user_token, db_session, monkeypatch):
    monkeypatch.setattr(get_settings(), "mfa_max_attempts", 1)
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 85, "LOW")

        _post_event(client, admin_token, session_id, SecurityEventType.VPN_DETECTED, ip_address="185.220.100.7")
        challenge = ws.receive_json()["challenge"]

        wrong = f"{(int(challenge['dev_code']) + 1) % 1_000_000:06d}"
        r = client.post("/api/v1/mfa/verify", json={"mfa_token": challenge["mfa_token"], "code": wrong})
        assert r.status_code == 403
        assert r.json()["detail"]["code"] == "exhausted"

        terminated = ws.receive_json()
        assert terminated == {"type": "session.terminated", "reason": "risk_revoked"}

    body = _wait_terminated(client, session_id, admin_token)
    assert body["termination_reason"] == "risk_revoked"
    # server-side token revocation follows for free via app.services.auth.wiring
    assert client.get("/api/v1/auth/me", headers=_bearer(user_token)).status_code == 401


def test_reverify_expiry_revokes_the_session_via_the_sweeper(client, admin_token, user_token, db_session):
    from app.models.mfa import MFAChallenge
    from app.models.session import utcnow
    from datetime import timedelta

    from app.services import mfa as mfa_service

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 85, "LOW")

        resp = _post_event(
            client, admin_token, session_id, SecurityEventType.VPN_DETECTED, ip_address="185.220.100.7"
        )
        challenge_id = resp.json()["mfa_challenge_id"]
        ws.receive_json()  # trust.reverify_required

        challenge = db_session.get(MFAChallenge, challenge_id)
        challenge.expires_at = utcnow() - timedelta(seconds=1)
        db_session.commit()

        # Same sweeper logic app.main's background task runs periodically --
        # called directly here rather than waiting on a real asyncio.sleep.
        expired = mfa_service.expire_overdue_challenges(db_session)
        assert any(c.id == challenge_id for c in expired)

        from app.models.session import TerminationReason
        from app.services import session as session_service

        session_service.terminate_session(db_session, session_id, reason=TerminationReason.RISK_REVOKED)

    body = _wait_terminated(client, session_id, admin_token)
    assert body["termination_reason"] == "risk_revoked"


def test_reverify_email_failure_revokes_instead_of_leaving_it_unchallenged(
    client, admin_token, user_token, db_session, monkeypatch
):
    import app.services.mfa.email_otp as email_otp

    monkeypatch.setattr(get_settings(), "smtp_username", "bot@example.com")
    monkeypatch.setattr(get_settings(), "smtp_password", "app-password")

    def fake_send(**kwargs):
        raise email_otp.EmailDeliveryError("smtp connection refused")

    monkeypatch.setattr(email_otp, "send_verification_email", fake_send)

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 85, "LOW")

        resp = _post_event(
            client, admin_token, session_id, SecurityEventType.VPN_DETECTED, ip_address="185.220.100.7"
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["action"] == "revoke"
        assert body["new_risk"] == "MEDIUM"       # the risk band is still MEDIUM...
        assert body["mfa_challenge_id"] is None   # ...but no challenge could be delivered

        terminated = ws.receive_json()
        assert terminated == {"type": "session.terminated", "reason": "risk_revoked"}


# --------------------------------------------------------------------------- #
# action: revoke (direct HIGH crossing)
# --------------------------------------------------------------------------- #
def test_event_crossing_into_high_revokes_session_immediately(client, admin_token, user_token, db_session):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 60, "MEDIUM")

        resp = _post_event(client, admin_token, session_id, SecurityEventType.ABNORMAL_REQUEST_RATE)
        assert resp.status_code == 200
        body = resp.json()
        assert body["action"] == "revoke"
        assert body["new_score"] == 40
        assert body["new_risk"] == "HIGH"

        terminated = ws.receive_json()
        assert terminated == {"type": "session.terminated", "reason": "risk_revoked"}

    row = client.get(f"/api/v1/sessions/{session_id}", headers=_bearer(admin_token)).json()
    assert row["state"] == "terminated"
    assert row["termination_reason"] == "risk_revoked"
    assert row["acl_status"] in ("removed", "removing")
    assert client.get("/api/v1/auth/me", headers=_bearer(user_token)).status_code == 401


# --------------------------------------------------------------------------- #
# validation / RBAC
# --------------------------------------------------------------------------- #
def test_unknown_event_type_is_rejected(client, admin_token, user_token):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        assert _post_event(client, admin_token, session_id, "totally_bogus_event").status_code == 400


def test_event_for_unknown_session_is_404(client, admin_token):
    assert _post_event(client, admin_token, "does-not-exist", SecurityEventType.IP_CHANGE).status_code == 404


def test_event_for_terminated_session_is_409(client, admin_token, user_token):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
    _wait_terminated(client, session_id, admin_token)

    assert _post_event(client, admin_token, session_id, SecurityEventType.IP_CHANGE).status_code == 409


def test_security_endpoints_are_admin_only(client, admin_token, user_token):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]

        assert client.get("/api/v1/security/events").status_code == 401
        assert client.get("/api/v1/security/events", headers=_bearer(user_token)).status_code == 403

        payload = {"session_id": session_id, "event_type": "ip_change"}
        assert client.post("/api/v1/security/events", json=payload).status_code == 401
        assert client.post(
            "/api/v1/security/events", json=payload, headers=_bearer(user_token)
        ).status_code == 403

        assert client.get("/api/v1/security/config").status_code == 401
        assert client.get("/api/v1/security/config", headers=_bearer(admin_token)).status_code == 200


def test_security_events_feed_records_the_ingested_event(client, admin_token, user_token, db_session):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 95, "LOW")
        _post_event(client, admin_token, session_id, SecurityEventType.IP_CHANGE, ip_address="9.9.9.9")

        feed = client.get("/api/v1/security/events", headers=_bearer(admin_token)).json()
        assert len(feed["events"]) == 1
        row = feed["events"][0]
        assert row["event_type"] == "ip_change"
        assert row["previous_score"] == 95
        assert row["new_score"] == 85
        assert row["action"] == "none"

        filtered = client.get(
            f"/api/v1/security/events?session_id={session_id}", headers=_bearer(admin_token)
        ).json()
        assert len(filtered["events"]) == 1


# --------------------------------------------------------------------------- #
# units
# --------------------------------------------------------------------------- #
def test_classify_event_vpn_detected_approved_vs_unknown():
    from app.services.trust_score.continuous import classify_event
    from app.services.trust_score.factors import Factor, FactorKind

    name, kind, weight, _reason = classify_event(
        SecurityEventType.VPN_DETECTED, ip_address="10.8.0.5"  # in the default approved-VPN sample
    )
    assert name == Factor.APPROVED_VPN and kind == FactorKind.POSITIVE and weight > 0

    name, kind, weight, _reason = classify_event(
        SecurityEventType.VPN_DETECTED, ip_address="185.220.100.7"  # in the default known-bad sample
    )
    assert name == Factor.UNKNOWN_VPN and kind == FactorKind.NEGATIVE and weight < 0

    name, kind, weight, _reason = classify_event(SecurityEventType.LARGE_DOWNLOAD)
    assert kind == FactorKind.NEGATIVE and weight == -settings.trust_weight_large_download


def test_classify_event_rejects_unknown_type():
    from app.services.trust_score.continuous import classify_event

    with pytest.raises(ValueError):
        classify_event("bogus")
