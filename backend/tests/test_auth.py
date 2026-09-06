"""
Module 2 — Authentication tests.

Covers the module's deliverable end to end: register -> JWT -> authenticated
user, plus the failure paths the "authentication middleware" must reject.
"""
from __future__ import annotations

import jwt

from app.core.config import get_settings

settings = get_settings()

ALICE = {"username": "alice", "email": "alice@example.com", "password": "sup3rsecret"}
BOB = {"username": "bob", "email": "bob@example.com", "password": "hunter2hunter"}


def _register(client, body):
    return client.post("/api/v1/auth/register", json=body)


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #
def test_register_returns_token_and_user(client):
    resp = _register(client, ALICE)
    assert resp.status_code == 201
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["expires_in"] == settings.access_token_expire_minutes * 60
    assert body["user"]["username"] == "alice"
    assert body["user"]["email"] == "alice@example.com"
    assert "password" not in body["user"] and "hashed_password" not in body["user"]


def test_first_user_is_admin_rest_are_users(client):
    first = _register(client, ALICE).json()
    second = _register(client, BOB).json()
    assert first["user"]["role"] == "admin"
    assert second["user"]["role"] == "user"


def test_register_rejects_duplicate_username(client):
    _register(client, ALICE)
    dup = _register(client, {**ALICE, "email": "other@example.com"})
    assert dup.status_code == 409


def test_register_rejects_duplicate_email(client):
    _register(client, ALICE)
    dup = _register(client, {**ALICE, "username": "alice2"})
    assert dup.status_code == 409


def test_register_rejects_short_password(client):
    resp = _register(client, {**ALICE, "password": "short"})
    assert resp.status_code == 422


def test_register_rejects_bad_username(client):
    resp = _register(client, {**ALICE, "username": "has spaces"})
    assert resp.status_code == 422


def test_register_rejects_password_over_72_bytes(client):
    # 40 chars but 80 UTF-8 bytes — under the char cap, over bcrypt's 72-byte
    # limit, which it would otherwise silently ignore.
    resp = _register(client, {**ALICE, "password": "é" * 40})
    assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# Login
# --------------------------------------------------------------------------- #
def test_login_success_returns_jwt_with_correct_subject(client):
    user_id = _register(client, ALICE).json()["user"]["id"]
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": ALICE["password"]},
    )
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    claims = jwt.decode(
        token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
    )
    assert claims["sub"] == str(user_id)
    assert claims["type"] == "access"


def test_login_wrong_password_is_401(client):
    _register(client, ALICE)
    resp = client.post(
        "/api/v1/auth/login", json={"username": "alice", "password": "wrongwrong"}
    )
    assert resp.status_code == 401


def test_login_unknown_user_is_401(client):
    resp = client.post(
        "/api/v1/auth/login", json={"username": "ghost", "password": "whatever12"}
    )
    assert resp.status_code == 401


def test_login_updates_last_login_at(client):
    _register(client, ALICE)
    before = client.post(
        "/api/v1/auth/login", json={"username": "alice", "password": ALICE["password"]}
    )
    token = before.json()["access_token"]
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.json()["last_login_at"] is not None


# --------------------------------------------------------------------------- #
# Authentication middleware (get_current_user)
# --------------------------------------------------------------------------- #
def test_me_requires_token(client):
    assert client.get("/api/v1/auth/me").status_code == 401


def test_me_rejects_garbage_token(client):
    resp = client.get(
        "/api/v1/auth/me", headers={"Authorization": "Bearer not.a.jwt"}
    )
    assert resp.status_code == 401


def test_me_rejects_token_signed_with_wrong_secret(client):
    _register(client, ALICE)
    forged = jwt.encode(
        {"sub": "1", "type": "access"}, "the-wrong-secret", algorithm="HS256"
    )
    resp = client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"}
    )
    assert resp.status_code == 401


def test_me_returns_current_user(client):
    reg = _register(client, ALICE).json()
    token = reg["access_token"]
    resp = client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
    assert resp.json()["id"] == reg["user"]["id"]
    assert resp.json()["username"] == "alice"


def test_logout_acknowledges_authenticated_request(client):
    token = _register(client, ALICE).json()["access_token"]
    resp = client.post(
        "/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
