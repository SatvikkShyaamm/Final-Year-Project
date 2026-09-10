"""
Module 6 — Adaptive MFA tests.

Covers the Section-6 decision (LOW allow / MEDIUM MFA / HIGH block), the TOTP
challenge lifecycle (generation, enrollment, verification, expiry, retry /
exhaustion), the mfa_pending token's narrow scope, and the admin feed.
"""
from __future__ import annotations

from datetime import timedelta

from app.core.config import get_settings
from app.models.mfa import MFAChallenge
from app.models.session import Session, SessionState, utcnow

settings = get_settings()

ADMIN = {"username": "admin", "email": "admin@example.com", "password": "adminpass123"}
USER = {"username": "alice", "email": "alice@example.com", "password": "alicepass123"}


def _register(client, body: dict) -> dict:
    return client.post("/api/v1/auth/register", json=body).json()


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _admin_token(client) -> str:
    return _register(client, ADMIN)["access_token"]


def _user_token(client) -> str:
    return _register(client, USER)["access_token"]


def _login(client, **headers) -> dict:
    return client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": USER["password"]},
        headers=headers or None,
    ).json()


# --------------------------------------------------------------------------- #
# decision: LOW allow / MEDIUM MFA / HIGH block
# --------------------------------------------------------------------------- #
def test_first_login_requires_mfa(client):
    _admin_token(client)
    _user_token(client)

    resp = client.post(
        "/api/v1/auth/login", json={"username": "alice", "password": USER["password"]}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["mfa_required"] is True
    assert body["decision"] == "mfa"
    assert body["risk_level"] == "MEDIUM"
    assert 60 <= body["trust_score"] <= 70
    assert body["access_token"] is None

    mfa = body["mfa"]
    assert mfa["challenge_id"] and mfa["mfa_token"]
    assert mfa["method"] == "totp"
    assert mfa["reason"] == "login_risk"
    assert mfa["enrollment"]["secret"]
    assert mfa["enrollment"]["provisioning_uri"].startswith("otpauth://totp/")
    assert mfa["dev_code"]  # development environment


def test_mfa_verify_with_dev_code_returns_access_token(client):
    _admin_token(client)
    _user_token(client)
    mfa = _login(client)["mfa"]

    v = client.post(
        "/api/v1/mfa/verify",
        json={"mfa_token": mfa["mfa_token"], "code": mfa["dev_code"]},
    )
    assert v.status_code == 200
    tok = v.json()
    assert tok["token_type"] == "bearer" and tok["access_token"]

    me = client.get("/api/v1/auth/me", headers=_bearer(tok["access_token"]))
    assert me.status_code == 200 and me.json()["username"] == "alice"

    st = client.get(
        f"/api/v1/mfa/challenge/{mfa['challenge_id']}",
        headers=_bearer(tok["access_token"]),
    )
    assert st.json()["status"] == "verified"


def test_low_risk_login_skips_mfa(client, db_session):
    _admin_token(client)
    user_token = _user_token(client)
    alice_id = client.get("/api/v1/auth/me", headers=_bearer(user_token)).json()["id"]

    # seed a prior session for alice with a known device + IP
    db_session.add(
        Session(
            id="p" * 32, user_id=alice_id, ip_address="203.0.113.55",
            user_agent="Mozilla/5.0 (X11)", state=SessionState.TERMINATED,
            created_at=utcnow(), last_seen_at=utcnow(),
        )
    )
    db_session.commit()

    body = _login(
        client,
        **{"x-forwarded-for": "203.0.113.55", "user-agent": "Mozilla/5.0 (X11)"},
    )
    assert body["mfa_required"] is False
    assert body["decision"] == "allow"
    assert body["risk_level"] == "LOW"
    assert body["access_token"]


def test_high_risk_login_is_blocked(client):
    _admin_token(client)
    _user_token(client)

    for _ in range(settings.trust_failed_login_threshold):
        client.post(
            "/api/v1/auth/login", json={"username": "alice", "password": "WRONGWRONG"}
        )

    # failed-login burst (-15) + known-public-VPN source IP (-15) -> 40 -> HIGH
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": USER["password"]},
        headers={"x-forwarded-for": "185.220.100.7"},
    )
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert detail["decision"] == "block"
    assert detail["risk_level"] == "HIGH"
    assert detail["trust_score"] < settings.trust_risk_medium_min


def test_mfa_disabled_lets_medium_through(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "mfa_enabled", False)
    _admin_token(client)
    _user_token(client)

    body = _login(client)
    assert body["mfa_required"] is False
    assert body["decision"] == "allow"
    assert body["risk_level"] == "MEDIUM"  # still medium — just not challenged
    assert body["access_token"]


# --------------------------------------------------------------------------- #
# TOTP challenge lifecycle
# --------------------------------------------------------------------------- #
def test_wrong_code_decrements_then_exhausts(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "mfa_max_attempts", 3)
    _admin_token(client)
    _user_token(client)
    mfa = _login(client)["mfa"]
    wrong = f"{(int(mfa['dev_code']) + 1) % 1_000_000:06d}"

    for expected_left in (2, 1):
        r = client.post(
            "/api/v1/mfa/verify", json={"mfa_token": mfa["mfa_token"], "code": wrong}
        )
        assert r.status_code == 401
        assert r.json()["detail"]["attempts_remaining"] == expected_left

    r = client.post(
        "/api/v1/mfa/verify", json={"mfa_token": mfa["mfa_token"], "code": wrong}
    )
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "exhausted"

    # a failed challenge can't then be verified with a good code
    r = client.post(
        "/api/v1/mfa/verify",
        json={"mfa_token": mfa["mfa_token"], "code": mfa["dev_code"]},
    )
    assert r.status_code == 409


def test_expired_challenge_is_rejected(client, db_session):
    _admin_token(client)
    _user_token(client)
    mfa = _login(client)["mfa"]

    challenge = db_session.get(MFAChallenge, mfa["challenge_id"])
    challenge.expires_at = utcnow() - timedelta(seconds=1)
    db_session.commit()

    r = client.post(
        "/api/v1/mfa/verify",
        json={"mfa_token": mfa["mfa_token"], "code": mfa["dev_code"]},
    )
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "expired"


def test_confirmed_credential_stops_re_enrolling(client):
    _admin_token(client)
    _user_token(client)

    mfa1 = _login(client)["mfa"]
    client.post(
        "/api/v1/mfa/verify",
        json={"mfa_token": mfa1["mfa_token"], "code": mfa1["dev_code"]},
    )

    mfa2 = _login(client)["mfa"]  # still MEDIUM -> still MFA, but credential is confirmed now
    assert mfa2["enrollment"] is None
    assert mfa2["dev_code"]  # dev code still handed out for the demo


# --------------------------------------------------------------------------- #
# mfa_pending token scope
# --------------------------------------------------------------------------- #
def test_mfa_pending_token_is_not_an_access_token(client):
    _admin_token(client)
    _user_token(client)
    mfa = _login(client)["mfa"]

    r = client.get("/api/v1/auth/me", headers=_bearer(mfa["mfa_token"]))
    assert r.status_code == 401


def test_registration_is_not_gated_by_mfa(client):
    body = _register(client, USER)  # first account -> admin, straight token
    assert body["access_token"]
    assert "mfa_required" not in body


# --------------------------------------------------------------------------- #
# step-up + admin feed
# --------------------------------------------------------------------------- #
def test_step_up_challenge_for_authenticated_user(client):
    _admin_token(client)
    token = _user_token(client)

    resp = client.post("/api/v1/mfa/challenge", headers=_bearer(token))
    assert resp.status_code == 201
    body = resp.json()
    assert body["reason"] == "step_up"
    assert body["mfa_token"]

    v = client.post(
        "/api/v1/mfa/verify",
        json={"mfa_token": body["mfa_token"], "code": body["dev_code"]},
    )
    assert v.status_code == 200 and v.json()["access_token"]


def test_step_up_requires_a_real_access_token(client):
    _admin_token(client)
    _user_token(client)
    mfa = _login(client)["mfa"]
    # the mfa_pending token can't be used to open a step-up challenge either
    assert client.post(
        "/api/v1/mfa/challenge", headers=_bearer(mfa["mfa_token"])
    ).status_code == 401


def test_mfa_challenges_feed_is_admin_only(client):
    admin = _admin_token(client)
    user = _user_token(client)
    _login(client)  # creates a login_risk challenge

    assert client.get("/api/v1/mfa/challenges").status_code == 401
    assert client.get("/api/v1/mfa/challenges", headers=_bearer(user)).status_code == 403

    resp = client.get("/api/v1/mfa/challenges", headers=_bearer(admin))
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["challenges"]) >= 1
    assert body["challenges"][0]["reason"] == "login_risk"
    assert {"pending", "verified", "failed", "expired"} <= set(body["counts"])


def test_mfa_config_endpoint(client):
    admin = _admin_token(client)
    body = client.get("/api/v1/mfa/config", headers=_bearer(admin)).json()
    assert body["mfa_enabled"] is True
    assert body["max_attempts"] == settings.mfa_max_attempts
    assert body["totp"]["digits"] == settings.mfa_totp_digits
    assert client.get("/api/v1/mfa/config").status_code == 401


# --------------------------------------------------------------------------- #
# units
# --------------------------------------------------------------------------- #
def test_decide_maps_risk_bands():
    from app.services.mfa import Decision, decide

    assert decide("LOW") == Decision.ALLOW
    assert decide("MEDIUM") == Decision.MFA
    assert decide("HIGH") == Decision.BLOCK


def test_totp_verify_roundtrip():
    from app.services.mfa import totp

    secret = totp.new_secret()
    assert totp.verify(secret, totp.current_code(secret))
    wrong = f"{(int(totp.current_code(secret)) + 1) % 1_000_000:06d}"
    assert not totp.verify(secret, wrong)
