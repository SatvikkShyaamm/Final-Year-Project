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
from app.core.security import create_access_token
from app.models.trust_score import RiskLevel
from app.models.user import User
from app.models.session import Session as SessionModel
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

    # 2026-09-16: this must be a genuinely SECOND login (its own token/jti),
    # not the same tab reconnecting -- reusing `user_token` here would now
    # reattach to the first session instead of opening a fresh one scored
    # from scratch by Module 5, which is exactly what this test needs to
    # observe (see sessions.py's WS handler and
    # get_active_session_by_token_jti).
    me = client.get("/api/v1/auth/me", headers=_bearer(user_token)).json()
    user_token_2 = create_access_token(me["id"])
    with client.websocket_connect(f"{WS_PATH}?token={user_token_2}") as ws:
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


def _seed_login_hours(db_session, user, hours: list[int], start_day: int = 1) -> None:
    """Insert one terminated prior session per hour in `hours`, oldest first,
    starting at `start_day` so repeated calls for the same user don't collide
    on the same calendar day. Mirrors what history.load_user_history actually
    reads (any state counts, ordering only matters once history exceeds the
    rolling window, which these tests stay well under)."""
    import uuid

    base_day = datetime(2026, 9, 1)
    for i, hour in enumerate(hours):
        db_session.add(SessionModel(
            id=uuid.uuid4().hex,
            user_id=user.id,
            ip_address="203.0.113.10",
            user_agent="Mozilla/5.0",
            created_at=base_day.replace(day=start_day + i, hour=hour),
        ))
    db_session.commit()


# --------------------------------------------------------------------------- #
# 2026-09-21 hardening: dynamic, self-decaying typical-hour band + static
# off-hours floor. See evaluator._typical_hour_band's docstring for the
# rationale (replaces the old raw min/max range).
# --------------------------------------------------------------------------- #
def test_evaluate_off_hours_is_a_static_floor_independent_of_learned_history(db_session):
    """OFF_HOURS is now an always-checked org-policy floor -- a user's own
    learned typical-hour history can earn back a positive TYPICAL_HOUR bonus
    alongside it, but can never suppress the floor itself."""
    user = _make_user(db_session)
    _seed_login_hours(db_session, user, [9, 9, 9, 9, 9])

    ev = evaluate(
        db_session, user_id=user.id, ip_address="203.0.113.10",
        user_agent="Mozilla/5.0", login_time=datetime(2026, 9, 20, 3, 0, 0),
    )
    applied = {o.name for o in ev.applied}
    assert Factor.OFF_HOURS in applied  # static floor still applies at 03:00
    assert Factor.ATYPICAL_HOUR in applied  # 03:00 is outside their 09:00 band
    assert Factor.TYPICAL_HOUR not in applied


def test_evaluate_typical_hour_is_dockable_not_reward_only(db_session):
    """TYPICAL_HOUR/ATYPICAL_HOUR are now a genuine mutually-exclusive pair
    (mirrors KNOWN_DEVICE/UNKNOWN_DEVICE) -- a login outside the learned band
    now costs points instead of merely failing to earn a bonus."""
    user = _make_user(db_session)
    _seed_login_hours(db_session, user, [9, 9, 9, 9, 9])

    within_band = evaluate(
        db_session, user_id=user.id, ip_address="203.0.113.10",
        user_agent="Mozilla/5.0", login_time=datetime(2026, 9, 20, 9, 0, 0),
    )
    applied_within = {o.name for o in within_band.applied}
    assert Factor.TYPICAL_HOUR in applied_within
    assert Factor.ATYPICAL_HOUR not in applied_within

    outside_band = evaluate(
        db_session, user_id=user.id, ip_address="203.0.113.10",
        user_agent="Mozilla/5.0", login_time=datetime(2026, 9, 20, 18, 0, 0),
    )
    applied_outside = {o.name for o in outside_band.applied}
    assert Factor.ATYPICAL_HOUR in applied_outside
    assert Factor.TYPICAL_HOUR not in applied_outside
    # dockable, not reward-only: the atypical login must score strictly lower
    # than the typical one, proving this is a real penalty.
    assert outside_band.score < within_band.score


def test_evaluate_typical_hour_band_resists_single_outlier_but_still_adapts(db_session):
    """A lone outlier hour must not immediately widen the learned band to
    admit it (the old min/max design's core flaw) -- but the band must still
    genuinely adapt once that pattern repeats often enough to become real
    evidence, proving the mechanism decays rather than becoming permanently
    rigid once hardened."""
    user = _make_user(db_session)
    # 5 typical logins at 09:00, then a single 03:00 outlier.
    _seed_login_hours(db_session, user, [9, 9, 9, 9, 9, 3], start_day=1)

    # Hand-calculated: mean=8.0, stddev=sqrt(5)~=2.236, half_width=
    # max(2.0, 1.5*2.236)~=3.354 -> band ~= [4.65, 11.35]. The single outlier
    # only nudged the band by a fraction of an hour, not out to admit hour 4.
    still_atypical = evaluate(
        db_session, user_id=user.id, ip_address="203.0.113.10",
        user_agent="Mozilla/5.0", login_time=datetime(2026, 9, 20, 4, 0, 0),
    )
    assert Factor.ATYPICAL_HOUR in {o.name for o in still_atypical.applied}

    # Now the "outlier" hour repeats enough times to genuinely become the
    # pattern -- the band must still be capable of shifting to reflect it.
    _seed_login_hours(db_session, user, [3, 3, 3, 3, 3, 3, 3, 3], start_day=20)
    now_typical = evaluate(
        db_session, user_id=user.id, ip_address="203.0.113.10",
        user_agent="Mozilla/5.0", login_time=datetime(2026, 9, 20, 4, 0, 0),
    )
    assert Factor.TYPICAL_HOUR in {o.name for o in now_typical.applied}


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
    assert len(body["factors"]) == 11  # 2026-09-21: +ATYPICAL_HOUR
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

    # 2026-09-16: a genuinely second login (its own token/jti) -- see the
    # comment in test_second_session_is_recognised_as_known_device_and_ip
    # above. Reusing `user_token` would reattach to the first session instead
    # of creating the second history entry this test expects.
    me = client.get("/api/v1/auth/me", headers=_bearer(user_token)).json()
    user_token_2 = create_access_token(me["id"])
    with client.websocket_connect(f"{WS_PATH}?token={user_token_2}") as ws:
        ws.receive_json()

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
