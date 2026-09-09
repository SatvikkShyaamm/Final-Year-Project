"""
Module 5 — Trust Score Engine tests.

Covers the finalized Section-6 spec: baseline 70, the factor table, first-time
users landing in MEDIUM, the Redis failed-login penalty, the VPN CIDR factors,
risk classification, storage on the session + the per-factor audit table, and
the admin read surface.
"""
from __future__ import annotations

from datetime import datetime

from app.core.config import get_settings
from app.models.trust_score import RiskLevel
from app.models.user import User
from app.services.trust_score.evaluator import evaluate
from app.services.trust_score.factors import Factor, classify_risk

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


def _score_body(client, admin_token: str, session_id: str) -> dict:
    return client.get(
        f"/api/v1/trust-score/{session_id}", headers=_bearer(admin_token)
    ).json()


# --------------------------------------------------------------------------- #
# score at session creation
# --------------------------------------------------------------------------- #
def test_first_session_lands_in_medium_band(client):
    admin_token = _admin_token(client)
    user_token = _user_token(client)

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        established = ws.receive_json()
        session_id = established["session_id"]
        # score is on the establish message too
        assert established["risk_level"] == RiskLevel.MEDIUM
        assert 60 <= established["trust_score"] <= 70

        body = _score_body(client, admin_token, session_id)
        assert body["risk_level"] == RiskLevel.MEDIUM
        names = {f["factor_name"] for f in body["factors"]}
        assert Factor.BASELINE in names
        # a brand-new user has no history -> no device/IP-history factors stored
        assert Factor.KNOWN_DEVICE not in names
        assert Factor.UNKNOWN_DEVICE not in names


def test_factor_breakdown_sums_to_score(client):
    admin_token = _admin_token(client)
    user_token = _user_token(client)
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        body = _score_body(client, admin_token, session_id)
        total = sum(f["weight_applied"] for f in body["factors"])
        assert total == body["trust_score"]
        baseline = next(f for f in body["factors"] if f["factor_name"] == Factor.BASELINE)
        assert baseline["weight_applied"] == settings.trust_score_baseline


def test_second_session_is_recognised_as_known_device_and_ip(client):
    admin_token = _admin_token(client)
    user_token = _user_token(client)

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        first_id = ws.receive_json()["session_id"]
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        second_id = ws.receive_json()["session_id"]

    first = _score_body(client, admin_token, first_id)
    second = _score_body(client, admin_token, second_id)
    second_names = {f["factor_name"] for f in second["factors"]}
    assert Factor.KNOWN_DEVICE in second_names
    assert Factor.KNOWN_IP in second_names
    assert second["trust_score"] > first["trust_score"]
    assert second["risk_level"] == RiskLevel.LOW


def test_failed_login_burst_lowers_the_score(client):
    admin_token = _admin_token(client)
    user_token = _user_token(client)

    # 3 bad-password attempts for a known username -> Redis burst counter hits 3
    for _ in range(3):
        r = client.post(
            "/api/v1/auth/login", json={"username": "alice", "password": "WRONGWRONG"}
        )
        assert r.status_code == 401

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]

    body = _score_body(client, admin_token, session_id)
    burst = next(
        (f for f in body["factors"] if f["factor_name"] == Factor.FAILED_LOGINS), None
    )
    assert burst is not None
    assert burst["weight_applied"] == -settings.trust_weight_failed_logins
    assert (
        body["trust_score"]
        <= settings.trust_score_baseline - settings.trust_weight_failed_logins
    )


# --------------------------------------------------------------------------- #
# evaluator unit tests (VPN / off-hours / history)
# --------------------------------------------------------------------------- #
def _make_user(db_session, username="bob") -> User:
    user = User(
        username=username, email=f"{username}@example.com",
        hashed_password="x", role="user",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def test_evaluate_first_time_user_is_exactly_baseline(db_session):
    user = _make_user(db_session)
    noon = datetime(2026, 9, 9, 12, 0, 0)
    ev = evaluate(
        db_session, user_id=user.id, ip_address="203.0.113.10",
        user_agent="Mozilla/5.0", login_time=noon,
    )
    assert ev.score == settings.trust_score_baseline
    assert ev.risk_level == RiskLevel.MEDIUM
    applied = {o.name for o in ev.applied}
    assert applied == {Factor.BASELINE}  # nothing else engaged


def test_evaluate_off_hours_fallback(db_session):
    user = _make_user(db_session)
    three_am = datetime(2026, 9, 9, 3, 0, 0)
    ev = evaluate(
        db_session, user_id=user.id, ip_address="203.0.113.10",
        user_agent="Mozilla/5.0", login_time=three_am,
    )
    assert Factor.OFF_HOURS in {o.name for o in ev.applied}
    assert ev.score == settings.trust_score_baseline - settings.trust_weight_off_hours


def test_evaluate_approved_vpn_raises_unknown_vpn_lowers(db_session):
    user = _make_user(db_session)
    noon = datetime(2026, 9, 9, 12, 0, 0)
    approved_ip = str(next(_iter_hosts(settings.trust_approved_vpn_cidrs[0])))
    known_ip = str(next(_iter_hosts(settings.trust_known_vpn_cidrs[0])))

    good = evaluate(db_session, user_id=user.id, ip_address=approved_ip,
                    user_agent="UA", login_time=noon)
    bad = evaluate(db_session, user_id=user.id, ip_address=known_ip,
                   user_agent="UA", login_time=noon)
    assert good.score == settings.trust_score_baseline + settings.trust_weight_approved_vpn
    assert bad.score == settings.trust_score_baseline - settings.trust_weight_unknown_vpn


def _iter_hosts(cidr: str):
    import ipaddress
    return ipaddress.ip_network(cidr, strict=False).hosts()


def test_classify_risk_bands():
    assert classify_risk(85, low_min=80, medium_min=50) == RiskLevel.LOW
    assert classify_risk(80, low_min=80, medium_min=50) == RiskLevel.LOW
    assert classify_risk(79, low_min=80, medium_min=50) == RiskLevel.MEDIUM
    assert classify_risk(50, low_min=80, medium_min=50) == RiskLevel.MEDIUM
    assert classify_risk(49, low_min=80, medium_min=50) == RiskLevel.HIGH


# --------------------------------------------------------------------------- #
# read surface
# --------------------------------------------------------------------------- #
def test_trust_config_endpoint(client):
    admin_token = _admin_token(client)
    body = client.get("/api/v1/trust-score/config", headers=_bearer(admin_token)).json()
    assert body["baseline"] == settings.trust_score_baseline
    assert set(body["risk_bands"]) == {"LOW", "MEDIUM", "HIGH"}
    assert len(body["factors"]) == 10
    assert body["known_vpn_list_is_static_sample"] is True


def test_trust_config_requires_admin(client):
    admin_token = _admin_token(client)
    user_token = _user_token(client)
    assert client.get("/api/v1/trust-score/config").status_code == 401
    assert client.get(
        "/api/v1/trust-score/config", headers=_bearer(user_token)
    ).status_code == 403
    assert client.get(
        "/api/v1/trust-score/config", headers=_bearer(admin_token)
    ).status_code == 200


def test_session_trust_score_rbac(client):
    admin_token = _admin_token(client)
    user_token = _user_token(client)
    other_token = _register(
        client, {"username": "carol", "email": "c@example.com", "password": "carolpass1"}
    )["access_token"]

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        assert client.get(
            f"/api/v1/trust-score/{session_id}", headers=_bearer(user_token)
        ).status_code == 200
        assert client.get(
            f"/api/v1/trust-score/{session_id}", headers=_bearer(other_token)
        ).status_code == 403
        assert client.get(
            f"/api/v1/trust-score/{session_id}", headers=_bearer(admin_token)
        ).status_code == 200

    assert client.get(
        "/api/v1/trust-score/nonexistent", headers=_bearer(admin_token)
    ).status_code == 404


def test_user_trust_history(client):
    admin_token = _admin_token(client)
    user_token = _user_token(client)

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        ws.receive_json()
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        ws.receive_json()

    me = client.get("/api/v1/auth/me", headers=_bearer(user_token)).json()
    hist = client.get(
        f"/api/v1/trust-score/user/{me['id']}/history", headers=_bearer(admin_token)
    ).json()
    assert len(hist["entries"]) == 2
    assert isinstance(hist["average_trust_score"], (int, float))
    assert all(e["trust_score"] is not None for e in hist["entries"])

    # a different non-admin cannot read someone else's history
    other = _register(
        client, {"username": "dave", "email": "d@example.com", "password": "davepass12"}
    )["access_token"]
    assert client.get(
        f"/api/v1/trust-score/user/{me['id']}/history", headers=_bearer(other)
    ).status_code == 403
