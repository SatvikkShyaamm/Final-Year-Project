"""
Module 7 hardening -- Real Passive Network Detection (Section 18 of
MASTER_PROJECT_CONTEXT.docx, FINALIZED 2026-09-14, implemented 2026-09-15;
abnormal_request_rate counting redesigned to Option A the same day -- see
app/services/trust_score/request_rate.py).

Exercises the deliverable end to end: a real HTTP heartbeat call (real IP/
User-Agent faked via X-Forwarded-For / User-Agent headers, per Section 18's
own confirmed testing plan -- no real network needed) -> the last-observed
comparison -> the identical continuous.record_event pipeline (source=auto)
-> the resulting risk-based action and WebSocket push, exactly as a manual
admin Trigger (test_continuous_trust.py) already gets covered for. Also
covers the request-rate counter (a tight loop of heartbeat calls, per
Section 18's testing plan, PLUS non-heartbeat endpoints counting the same
way and GET calls never counting -- the Option A redesign), the auto/admin
audit-trail source tag, and the Redis state's session-scoped lifetime.
"""
from __future__ import annotations

import time

import pytest

from app.core.config import get_settings
from app.models.security_event import SecurityEventSource
from app.models.session import Session, SessionState

settings = get_settings()

ADMIN = {"username": "admin", "email": "admin@example.com", "password": "adminpass123"}
USER = {"username": "alice", "email": "alice@example.com", "password": "alicepass123"}
WS_PATH = "/api/v1/ws/session"
HEARTBEAT_PATH = "/api/v1/security/heartbeat"


def _register(client, body: dict) -> dict:
    return client.post("/api/v1/auth/register", json=body).json()


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _heartbeat(client, token: str, *, ip: str | None = None, ua: str | None = None):
    headers = _bearer(token)
    if ip is not None:
        headers["X-Forwarded-For"] = ip
    if ua is not None:
        headers["User-Agent"] = ua
    return client.post(HEARTBEAT_PATH, headers=headers)


def _force_score(db_session, session_id: str, score: int, risk: str) -> None:
    row = db_session.get(Session, session_id)
    row.trust_score = score
    row.risk_level = risk
    db_session.commit()


def _wait_terminated(client, session_id: str, admin_token: str, tries: int = 20):
    for _ in range(tries):
        body = client.get(f"/api/v1/sessions/{session_id}", headers=_bearer(admin_token)).json()
        if body.get("state") == SessionState.TERMINATED:
            return body
        time.sleep(0.05)
    return body


@pytest.fixture()
def admin_token(client) -> str:
    return _register(client, ADMIN)["access_token"]


@pytest.fixture()
def user_token(client, admin_token) -> str:
    return _register(client, USER)["access_token"]


# --------------------------------------------------------------------------- #
# seeding / "last observed, not the login baseline"
# --------------------------------------------------------------------------- #
def test_first_heartbeat_seeds_silently(client, admin_token, user_token, db_session):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 100, "LOW")

        resp = _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/1")
        assert resp.status_code == 200
        body = resp.json()
        assert body["session_id"] == session_id
        assert body["seeded"] is True
        assert body["events"] == []
        assert body["session_terminated"] is False

    feed = client.get("/api/v1/security/events", headers=_bearer(admin_token)).json()
    assert feed["events"] == []  # nothing was ever recorded -- silently seeded only


def test_repeated_heartbeat_with_unchanged_ip_and_ua_fires_nothing(
    client, admin_token, user_token, db_session
):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 100, "LOW")

        first = _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/1")
        assert first.json()["seeded"] is True

        second = _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/1")
        assert second.json()["seeded"] is False
        assert second.json()["events"] == []

        row = client.get(f"/api/v1/sessions/{session_id}", headers=_bearer(admin_token)).json()
        assert row["trust_score"] == 100  # never touched


# --------------------------------------------------------------------------- #
# ip_change / vpn_detected / unknown_device detection
# --------------------------------------------------------------------------- #
def test_ip_change_fires_ip_change_with_auto_source_and_pushes_trust_updated(
    client, admin_token, user_token, db_session
):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 100, "LOW")

        _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/1")  # seed

        resp = _heartbeat(client, user_token, ip="8.8.8.8", ua="Agent/1")  # real change
        assert resp.status_code == 200
        body = resp.json()
        assert body["seeded"] is False
        assert body["events"] == ["ip_change"]
        assert body["session_terminated"] is False

        push = ws.receive_json()
        assert push == {
            "type": "trust.updated", "session_id": session_id,
            "risk_level": "LOW", "trust_score": 100 - settings.trust_weight_ip_changed,
        }

    feed = client.get(
        f"/api/v1/security/events?session_id={session_id}", headers=_bearer(admin_token)
    ).json()
    assert len(feed["events"]) == 1
    assert feed["events"][0]["event_type"] == "ip_change"
    assert feed["events"][0]["source"] == SecurityEventSource.AUTO


def test_ip_change_into_known_bad_vpn_cidr_fires_vpn_detected_not_ip_change(
    client, admin_token, user_token, db_session
):
    """185.220.100.7 is in the default TRUST_KNOWN_VPN_CIDRS_RAW sample (same
    address the manual-Trigger VPN tests in test_continuous_trust.py use) --
    the more specific vpn_detected classification wins over a plain
    ip_change for the same underlying address change."""
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 100, "LOW")

        _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/1")  # seed
        resp = _heartbeat(client, user_token, ip="185.220.100.7", ua="Agent/1")
        body = resp.json()
        assert body["events"] == ["vpn_detected"]

        ws.receive_json()  # trust.updated

    feed = client.get(
        f"/api/v1/security/events?session_id={session_id}", headers=_bearer(admin_token)
    ).json()
    assert feed["events"][0]["event_type"] == "vpn_detected"
    assert feed["events"][0]["new_score"] == 100 - settings.trust_weight_unknown_vpn


def test_ip_change_into_approved_vpn_cidr_is_positive(
    client, admin_token, user_token, db_session
):
    """10.8.0.5 is in the default TRUST_APPROVED_VPN_CIDRS_RAW sample."""
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 70, "LOW")

        _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/1")  # seed
        resp = _heartbeat(client, user_token, ip="10.8.0.5", ua="Agent/1")
        body = resp.json()
        assert body["events"] == ["vpn_detected"]
        ws.receive_json()

    row = client.get(f"/api/v1/sessions/{session_id}", headers=_bearer(admin_token)).json()
    assert row["trust_score"] == 70 + settings.trust_weight_approved_vpn


def test_user_agent_change_fires_unknown_device(client, admin_token, user_token, db_session):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 100, "LOW")

        _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/1")  # seed
        resp = _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/2 -- a different browser")
        assert resp.json()["events"] == ["unknown_device"]
        ws.receive_json()

    row = client.get(f"/api/v1/sessions/{session_id}", headers=_bearer(admin_token)).json()
    assert row["trust_score"] == 100 - settings.trust_weight_unknown_device


def test_ip_and_user_agent_change_together_fire_both_events_in_order(
    client, admin_token, user_token, db_session
):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 100, "LOW")

        _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/1")  # seed
        resp = _heartbeat(client, user_token, ip="8.8.8.8", ua="Agent/2")
        body = resp.json()
        assert body["events"] == ["ip_change", "unknown_device"]

        first_push = ws.receive_json()
        second_push = ws.receive_json()
        assert first_push["trust_score"] == 100 - settings.trust_weight_ip_changed
        assert second_push["trust_score"] == (
            100 - settings.trust_weight_ip_changed - settings.trust_weight_unknown_device
        )

    feed = client.get(
        f"/api/v1/security/events?session_id={session_id}", headers=_bearer(admin_token)
    ).json()
    assert [e["event_type"] for e in reversed(feed["events"])] == ["ip_change", "unknown_device"]


def test_ip_change_that_revokes_stops_further_events_this_heartbeat(
    client, admin_token, user_token, db_session
):
    """A single heartbeat can carry both an IP change and a UA change -- if
    the IP change alone pushes the session into HIGH and revokes it, the UA
    change must not also try to fire against a now-terminated session."""
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/1")  # seed (no score touched)

        # Set up so the ip_change alone lands the score at exactly 39 (< the
        # medium_min=50 floor -> HIGH -> revoke) regardless of the configured
        # weight value: (40 + W - 1) - W == 39.
        _force_score(db_session, session_id, 40 + settings.trust_weight_ip_changed - 1, "HIGH")

        resp = _heartbeat(client, user_token, ip="8.8.8.8", ua="Agent/2")
        body = resp.json()
        assert body["events"] == ["ip_change"]  # unknown_device never attempted
        assert body["session_terminated"] is True

        terminated = ws.receive_json()
        assert terminated == {"type": "session.terminated", "reason": "risk_revoked"}

    row = _wait_terminated(client, session_id, admin_token)
    assert row["termination_reason"] == "risk_revoked"


# --------------------------------------------------------------------------- #
# abnormal_request_rate -- tight-loop, per Section 18's own testing plan
# --------------------------------------------------------------------------- #
def test_abnormal_request_rate_trips_on_a_tight_loop_of_heartbeats(
    client, admin_token, user_token, db_session, monkeypatch
):
    monkeypatch.setattr(get_settings(), "request_rate_threshold", 3)

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 100, "LOW")

        first = _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/1")  # count=1, seeds
        assert first.json()["events"] == []

        second = _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/1")  # count=2
        assert second.json()["events"] == []

        third = _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/1")  # count=3 -- trips
        assert third.json()["events"] == ["abnormal_request_rate"]

        push = ws.receive_json()
        assert push["type"] == "trust.updated"
        assert push["trust_score"] == 100 - settings.trust_weight_abnormal_request_rate

    feed = client.get(
        f"/api/v1/security/events?session_id={session_id}", headers=_bearer(admin_token)
    ).json()
    assert feed["events"][0]["event_type"] == "abnormal_request_rate"
    assert feed["events"][0]["source"] == SecurityEventSource.AUTO


def test_abnormal_request_rate_fires_only_once_per_crossing(
    client, admin_token, user_token, db_session, monkeypatch
):
    monkeypatch.setattr(get_settings(), "request_rate_threshold", 2)

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 100, "LOW")

        _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/1")  # count=1
        second = _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/1")  # count=2 -- trips
        assert second.json()["events"] == ["abnormal_request_rate"]
        ws.receive_json()

        third = _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/1")  # count=3 -- past it
        assert third.json()["events"] == []  # not re-fired on every call past the threshold


def test_non_heartbeat_calls_also_count_toward_the_callers_own_session(
    client, admin_token, user_token, db_session, monkeypatch
):
    """Option A (2026-09-15 redesign): the request-rate counter is bumped
    by EVERY non-GET authenticated call anywhere in the app -- via
    app.api.deps.get_current_user -- not just calls to the heartbeat
    endpoint itself. Three DELETEs against an unrelated (nonexistent)
    session id count exactly like three heartbeat calls would; each still
    authenticates (and so still counts) even though the endpoint itself
    then 404s. The admin's own first-ever heartbeat afterwards observes the
    already-crossed threshold and fires -- proving attribution follows the
    CALLER's own session regardless of which endpoint did the counting."""
    monkeypatch.setattr(get_settings(), "request_rate_threshold", 3)

    with client.websocket_connect(f"{WS_PATH}?token={admin_token}") as admin_ws:
        admin_session = admin_ws.receive_json()["session_id"]
        _force_score(db_session, admin_session, 100, "LOW")

        for _ in range(3):
            resp = client.delete(
                "/api/v1/sessions/does-not-exist", headers=_bearer(admin_token)
            )
            assert resp.status_code == 404  # counts regardless of the outcome

        # The admin's OWN first heartbeat: the dependency bumps the counter
        # to 4 before the handler runs, so this one call both seeds
        # last-observed AND observes the already-crossed threshold.
        resp = _heartbeat(client, admin_token, ip="9.9.9.9", ua="Agent/1")
        body = resp.json()
        assert body["seeded"] is True
        assert body["events"] == ["abnormal_request_rate"]

        push = admin_ws.receive_json()
        assert push["type"] == "trust.updated"
        assert push["trust_score"] == 100 - settings.trust_weight_abnormal_request_rate

    feed = client.get(
        f"/api/v1/security/events?session_id={admin_session}", headers=_bearer(admin_token)
    ).json()
    assert feed["events"][0]["event_type"] == "abnormal_request_rate"


def test_get_requests_never_count_toward_request_rate(
    client, admin_token, user_token, db_session, monkeypatch
):
    """Reads -- including the kind of high-frequency polling a dashboard
    does constantly -- must never count towards the threshold at all, not
    merely count less: this is what stops an admin's own dashboard polling
    from dinging their own session (see request_rate.py's own docstring)."""
    monkeypatch.setattr(get_settings(), "request_rate_threshold", 2)

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 100, "LOW")

        for _ in range(5):
            resp = client.get(f"/api/v1/sessions/{session_id}", headers=_bearer(user_token))
            assert resp.status_code == 200

        # If the 5 GETs above had counted, this first heartbeat's own bump
        # (to 6) would already be past request_rate_threshold=2 and fire.
        first = _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/1")  # count=1, seeds
        assert first.json()["events"] == []

        second = _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/1")  # count=2 -- trips
        assert second.json()["events"] == ["abnormal_request_rate"]


def test_active_session_index_used_by_request_rate_is_populated_on_login(
    client, user_token, fake_redis
):
    """app.services.trust_score.request_rate resolves "the caller's current
    session" by reading app.services.session.store's existing per-user
    Redis index (ztsaacm:user:{user_id}:sessions) rather than a new cache --
    confirm that index actually contains the session id once a session is
    open, independent of any request-rate behaviour of its own."""
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        current = client.get("/api/v1/sessions/current", headers=_bearer(user_token)).json()
        user_id = current["user_id"]

        assert fake_redis.smembers(f"ztsaacm:user:{user_id}:sessions") == {session_id}


# --------------------------------------------------------------------------- #
# no active session / RBAC
# --------------------------------------------------------------------------- #
def test_heartbeat_with_no_active_session_is_a_harmless_no_op(client, user_token):
    resp = _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/1")
    assert resp.status_code == 200
    body = resp.json()
    assert body == {
        "session_id": None, "seeded": False, "events": [], "session_terminated": False
    }


def test_heartbeat_requires_authentication(client):
    resp = client.post(HEARTBEAT_PATH)
    assert resp.status_code == 401


def test_heartbeat_only_ever_touches_the_caller_own_session(
    client, admin_token, user_token, db_session
):
    """The endpoint takes no session_id -- it always resolves the CALLER's
    own current session server-side, so one user's heartbeat can never be
    pointed at another user's session."""
    other_token = _register(
        client, {"username": "bob", "email": "bob@example.com", "password": "bobpass123"}
    )["access_token"]

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as alice_ws:
        alice_session = alice_ws.receive_json()["session_id"]

        with client.websocket_connect(f"{WS_PATH}?token={other_token}") as bob_ws:
            bob_session = bob_ws.receive_json()["session_id"]

            resp = _heartbeat(client, other_token, ip="1.1.1.1", ua="Agent/1")
            assert resp.json()["session_id"] == bob_session
            assert resp.json()["session_id"] != alice_session


# --------------------------------------------------------------------------- #
# Redis state lifetime -- cleared on session close (mirrors ACL ref-counts)
# --------------------------------------------------------------------------- #
def test_heartbeat_state_is_cleared_when_the_session_ends(
    client, admin_token, user_token, fake_redis
):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/1")
        assert fake_redis.exists(f"ztsaacm:heartbeat:last:{session_id}")
        # 2026-09-15: the request-rate counter itself now lives in
        # app.services.trust_score.request_rate under its own key prefix
        # (ztsaacm:reqrate:...), not ztsaacm:heartbeat:rate:... -- still
        # cleared from right here (heartbeat.clear_session_state delegates
        # to request_rate.clear_session_state).
        assert fake_redis.exists(f"ztsaacm:reqrate:{session_id}")

    _wait_terminated(client, session_id, admin_token)
    assert not fake_redis.exists(f"ztsaacm:heartbeat:last:{session_id}")
    assert not fake_redis.exists(f"ztsaacm:reqrate:{session_id}")
    assert not fake_redis.exists(f"ztsaacm:reqrate:fired:{session_id}")


# --------------------------------------------------------------------------- #
# audit trail source tag + config reference view
# --------------------------------------------------------------------------- #
def test_security_events_feed_filters_by_source(client, admin_token, user_token, db_session):
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        _force_score(db_session, session_id, 100, "LOW")

        client.post(
            "/api/v1/security/events",
            json={"session_id": session_id, "event_type": "ip_change", "ip_address": "1.2.3.4"},
            headers=_bearer(admin_token),
        )
        ws.receive_json()  # trust.updated for the admin-triggered event

        _heartbeat(client, user_token, ip="9.9.9.9", ua="Agent/1")  # seed, no event
        _heartbeat(client, user_token, ip="8.8.8.8", ua="Agent/1")  # auto ip_change
        ws.receive_json()  # trust.updated for the auto-detected event

    admin_only = client.get(
        f"/api/v1/security/events?session_id={session_id}&source=admin",
        headers=_bearer(admin_token),
    ).json()
    assert len(admin_only["events"]) == 1
    assert admin_only["events"][0]["source"] == "admin"

    auto_only = client.get(
        f"/api/v1/security/events?session_id={session_id}&source=auto",
        headers=_bearer(admin_token),
    ).json()
    assert len(auto_only["events"]) == 1
    assert auto_only["events"][0]["source"] == "auto"

    everything = client.get(
        f"/api/v1/security/events?session_id={session_id}", headers=_bearer(admin_token)
    ).json()
    assert len(everything["events"]) == 2


def test_security_events_feed_rejects_unknown_source(client, admin_token):
    resp = client.get(
        "/api/v1/security/events?source=bogus", headers=_bearer(admin_token)
    )
    assert resp.status_code == 400


def test_security_config_exposes_heartbeat_reference_settings(client, admin_token):
    body = client.get("/api/v1/security/config", headers=_bearer(admin_token)).json()
    assert body["heartbeat"] == {
        "interval_seconds": settings.heartbeat_interval_seconds,
    }
    # 2026-09-15: split out of "heartbeat" above -- request-rate counting is
    # no longer heartbeat-specific (see app.services.trust_score.request_rate).
    assert body["request_rate"] == {
        "window_seconds": settings.request_rate_window_seconds,
        "threshold": settings.request_rate_threshold,
    }
