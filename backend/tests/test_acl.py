"""
Module 4 — Dynamic ACL Management tests.

Exercises the deliverable end to end: session opens -> ACL rule created +
enforcement task enqueued -> L-PEP applies it (rule ACTIVE, IP in the allow
list) -> session ends -> rule removed, IP pulled back out. Plus ref-counting,
the admin read surface, and the enforcer backends.
"""
from __future__ import annotations

import time
from contextlib import suppress

from app.core.config import get_settings
from app.core.security import create_access_token
from app.models.acl import ACLState
from app.services import acl as acl_service
from app.services.acl import store as acl_store
from app.services.acl.enforcer import SimulatedEnforcer, get_enforcer

settings = get_settings()

ADMIN = {"username": "admin", "email": "admin@example.com", "password": "adminpass123"}
USER = {"username": "alice", "email": "alice@example.com", "password": "alicepass123"}
WS_PATH = "/api/v1/ws/session"


def _register(client, body: dict) -> dict:
    return client.post("/api/v1/auth/register", json=body).json()


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _admin_token(client) -> str:
    return _register(client, ADMIN)["access_token"]


def _user_token(client) -> str:
    return _register(client, USER)["access_token"]


def _rule_for_session(client, admin_token: str, session_id: str) -> dict | None:
    rules = client.get(
        "/api/v1/acl/rules?include_removed=true", headers=_bearer(admin_token)
    ).json()["rules"]
    return next((r for r in rules if r["session_id"] == session_id), None)


# --------------------------------------------------------------------------- #
# session open -> ACL created
# --------------------------------------------------------------------------- #
def test_session_open_creates_pending_acl_rule(client, db_session):
    admin_token = _admin_token(client)
    user_token = _user_token(client)

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]

        rule = _rule_for_session(client, admin_token, session_id)
        assert rule is not None
        assert rule["state"] == ACLState.PENDING
        assert rule["resource"] == settings.acl_protected_resource
        assert rule["enforcement"] == "simulated"
        assert acl_store.queue_depth() >= 1  # an "add" task is waiting


def test_drain_activates_rule_and_fills_allow_list(client, db_session):
    admin_token = _admin_token(client)
    user_token = _user_token(client)

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        acl_service.drain_queue(db_session)

        rule = _rule_for_session(client, admin_token, session_id)
        assert rule["state"] == ACLState.ACTIVE
        assert rule["activated_at"] is not None
        assert rule["authorization_latency_ms"] is not None
        assert rule["client_ip"] in acl_store.kernel_members(rule["ipset_name"])


def test_session_close_removes_acl_rule(client, db_session):
    admin_token = _admin_token(client)
    user_token = _user_token(client)

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        acl_service.drain_queue(db_session)
        rule_before = _rule_for_session(client, admin_token, session_id)
        ipset_name = rule_before["ipset_name"]
        client_ip = rule_before["client_ip"]

    # socket closed -> session terminated -> ACL remove task enqueued.
    # 2026-09-16: an ordinary disconnect now sits in a short reconnect-grace
    # window first (see sessions.py's WS handler) in case the same tab
    # reconnects, so the ACL isn't torn down until that window actually
    # lapses -- comfortably short in tests, see conftest.py's
    # `_fast_reconnect_grace`, but still real wall-clock time to wait out.
    time.sleep(get_settings().session_reconnect_grace_seconds + 0.2)
    acl_service.drain_queue(db_session)
    rule = _rule_for_session(client, admin_token, session_id)
    assert rule["state"] == ACLState.REMOVED
    assert rule["removed_at"] is not None
    assert rule["revocation_latency_ms"] is not None
    assert rule["removal_reason"] == "websocket_disconnect"
    assert client_ip not in acl_store.kernel_members(ipset_name)


# --------------------------------------------------------------------------- #
# ref-counting: two sessions, one IP
# --------------------------------------------------------------------------- #
def test_refcount_keeps_entry_until_last_session_closes(client, db_session):
    admin_token = _admin_token(client)
    user_token = _user_token(client)
    # 2026-09-16: a SECOND real login mints its own token/jti, so it opens
    # its own independent session -- exactly what two concurrent devices on
    # the same IP would do in reality. Reusing `user_token` for both sockets
    # would instead have the second one reattach to the first's session (same
    # jti), collapsing this test's whole "two sessions, one IP" premise; see
    # sessions.py's WS handler and get_active_session_by_token_jti.
    me = client.get("/api/v1/auth/me", headers=_bearer(user_token)).json()
    user_token_2 = create_access_token(me["id"])

    ws1 = client.websocket_connect(f"{WS_PATH}?token={user_token}")
    sock1 = ws1.__enter__()
    sid1 = sock1.receive_json()["session_id"]
    ws2 = client.websocket_connect(f"{WS_PATH}?token={user_token_2}")
    sock2 = ws2.__enter__()
    sock2.receive_json()

    acl_service.drain_queue(db_session)
    rule1 = _rule_for_session(client, admin_token, sid1)
    ip, ipset_name = rule1["client_ip"], rule1["ipset_name"]
    assert acl_store.get_refcount(ip) == 2
    assert ip in acl_store.kernel_members(ipset_name)

    # close the first — entry must stay for the second. An ordinary
    # disconnect now sits in a short reconnect-grace window before it's
    # actually finalized (2026-09-16) -- wait it out, same as
    # test_session_close_removes_acl_rule above.
    ws1.__exit__(None, None, None)
    time.sleep(get_settings().session_reconnect_grace_seconds + 0.2)
    acl_service.drain_queue(db_session)
    assert acl_store.get_refcount(ip) == 1
    assert ip in acl_store.kernel_members(ipset_name)

    # close the second — now it goes
    ws2.__exit__(None, None, None)
    time.sleep(get_settings().session_reconnect_grace_seconds + 0.2)
    acl_service.drain_queue(db_session)
    assert acl_store.get_refcount(ip) == 0
    assert ip not in acl_store.kernel_members(ipset_name)


# --------------------------------------------------------------------------- #
# other termination paths remove the ACL too
# --------------------------------------------------------------------------- #
def test_logout_removes_acl(client, db_session):
    admin_token = _admin_token(client)
    user_token = _user_token(client)

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        acl_service.drain_queue(db_session)
        client.post("/api/v1/auth/logout", headers=_bearer(user_token))
        with suppress(Exception):
            ws.receive_json()

    acl_service.drain_queue(db_session)
    rule = _rule_for_session(client, admin_token, session_id)
    assert rule["state"] == ACLState.REMOVED
    assert rule["removal_reason"] == "logout"


def test_admin_terminate_removes_acl(client, db_session):
    admin_token = _admin_token(client)
    user_token = _user_token(client)

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        acl_service.drain_queue(db_session)
        resp = client.delete(
            f"/api/v1/sessions/{session_id}", headers=_bearer(admin_token)
        )
        assert resp.status_code == 200
        with suppress(Exception):
            ws.receive_json()

    acl_service.drain_queue(db_session)
    rule = _rule_for_session(client, admin_token, session_id)
    assert rule["state"] == ACLState.REMOVED
    assert rule["removal_reason"] == "admin_terminated"


# --------------------------------------------------------------------------- #
# admin read surface
# --------------------------------------------------------------------------- #
def test_acl_rules_requires_admin(client):
    admin_token = _admin_token(client)
    user_token = _user_token(client)
    assert client.get("/api/v1/acl/rules").status_code == 401
    assert client.get("/api/v1/acl/rules", headers=_bearer(user_token)).status_code == 403
    assert client.get("/api/v1/acl/rules", headers=_bearer(admin_token)).status_code == 200


def test_acl_rules_listing_reports_backend_and_latency(client, db_session):
    admin_token = _admin_token(client)
    user_token = _user_token(client)
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        ws.receive_json()
        acl_service.drain_queue(db_session)
        body = client.get("/api/v1/acl/rules", headers=_bearer(admin_token)).json()

    assert body["enforcement_backend"] == "simulated"
    assert body["active_count"] >= 1
    assert isinstance(body["avg_authorization_latency_ms"], (int, float))


def test_acl_status_endpoint(client):
    admin_token = _admin_token(client)
    body = client.get("/api/v1/acl/status", headers=_bearer(admin_token)).json()
    assert body["enforcement_backend"] == "simulated"
    assert body["worker_enabled"] is False
    assert settings.acl_ipset_v4 in body["kernel_entries"]
    assert settings.acl_ipset_v6 in body["kernel_entries"]


def test_get_acl_rule_by_id_and_404(client, db_session):
    admin_token = _admin_token(client)
    user_token = _user_token(client)
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        rule = _rule_for_session(client, admin_token, session_id)
        one = client.get(
            f"/api/v1/acl/rules/{rule['id']}", headers=_bearer(admin_token)
        )
        assert one.status_code == 200
        assert one.json()["id"] == rule["id"]

    assert client.get(
        "/api/v1/acl/rules/nope", headers=_bearer(admin_token)
    ).status_code == 404


# --------------------------------------------------------------------------- #
# session list ACL column (Module 3 reserved field, now populated)
# --------------------------------------------------------------------------- #
def test_acl_status_shows_in_session_list(client, db_session):
    admin_token = _admin_token(client)
    user_token = _user_token(client)
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        ws.receive_json()
        acl_service.drain_queue(db_session)
        row = client.get("/api/v1/sessions", headers=_bearer(admin_token)).json()[
            "sessions"
        ][0]
        assert row["acl_status"] == "active"


# --------------------------------------------------------------------------- #
# enforcer backends (unit)
# --------------------------------------------------------------------------- #
def test_simulated_enforcer_roundtrip():
    enf = SimulatedEnforcer()
    ok, err = enf.add("ztsaacm_allowed", "203.0.113.7", ttl=60)
    assert ok and err is None
    assert "203.0.113.7" in acl_store.kernel_members("ztsaacm_allowed")
    enf.remove("ztsaacm_allowed", "203.0.113.7")
    assert "203.0.113.7" not in acl_store.kernel_members("ztsaacm_allowed")


def test_auto_enforcer_falls_back_to_simulated_without_ipset():
    # No `ipset` binary on the CI/dev box -> auto must pick the simulated one.
    assert get_enforcer().name == "simulated"
