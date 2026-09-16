"""
Server-side access-token revocation tests (Project status.md section 6b fix).

Terminating a session must revoke the specific access token that opened it —
not just end the session row — so a copy of that token can't keep
authenticating REST calls or open a new WebSocket session afterward. A token
that never opened a session (or a different session entirely) must be
unaffected.
"""
from __future__ import annotations

from contextlib import suppress

from starlette.websockets import WebSocketDisconnect

WS_PATH = "/api/v1/ws/session"

ADMIN = {"username": "admin", "email": "admin@example.com", "password": "adminpass123"}
USER = {"username": "alice", "email": "alice@example.com", "password": "alicepass123"}
OTHER = {"username": "bob", "email": "bob@example.com", "password": "bobpass12345"}


def _register(client, body: dict) -> dict:
    return client.post("/api/v1/auth/register", json=body).json()


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_admin_terminate_revokes_the_sessions_own_token(client):
    admin_token = _register(client, ADMIN)["access_token"]
    user_token = _register(client, USER)["access_token"]

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]

        # the token authenticates normally while the session is alive
        assert client.get("/api/v1/auth/me", headers=_bearer(user_token)).status_code == 200

        resp = client.delete(
            f"/api/v1/sessions/{session_id}", headers=_bearer(admin_token)
        )
        assert resp.status_code == 200
        with suppress(Exception):
            ws.receive_json()

    # the same token that opened the now-terminated session is dead server-side
    me = client.get("/api/v1/auth/me", headers=_bearer(user_token))
    assert me.status_code == 401


def test_logout_revokes_the_sessions_own_token(client):
    _register(client, ADMIN)
    user_token = _register(client, USER)["access_token"]

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        ws.receive_json()
        resp = client.post("/api/v1/auth/logout", headers=_bearer(user_token))
        assert resp.status_code == 200
        with suppress(Exception):
            ws.receive_json()

    assert client.get("/api/v1/auth/me", headers=_bearer(user_token)).status_code == 401


def test_ordinary_disconnect_does_not_revoke_the_token(client):
    """An ordinary WEBSOCKET_DISCONNECT (tab closed, or a page refresh) must
    NOT revoke the token -- per docs/architecture.md and Project status.md
    section 6b, that same still-valid token being usable again afterward is
    documented, intended behaviour, not the gap this fix closes. Only a
    "terminated for cause" reason (logout / admin / idle / max-lifetime /
    risk-revoked / account-locked) revokes.

    2026-09-16: what that "usable again afterward" means changed shape, but
    not the property under test here -- see
    test_refresh_reconnect_reattaches_without_resetting_the_score and
    test_reconnect_after_grace_window_opens_a_genuinely_new_session in
    test_sessions.py for the now-reattaches-instead-of-always-fresh behavior
    itself. This test only asserts the token itself was never revoked."""
    _register(client, ADMIN)
    user_token = _register(client, USER)["access_token"]

    with client.websocket_connect(f"{WS_PATH}?token={user_token}"):
        pass  # `with` block exit closes the socket -> websocket_disconnect

    # the token still authenticates REST calls...
    assert client.get("/api/v1/auth/me", headers=_bearer(user_token)).status_code == 200
    # ...and can still open a socket again -- reconnecting instantly like
    # this reattaches to the very same (still-ACTIVE, grace-window) session
    # rather than opening a brand-new one (2026-09-16), but either way the
    # point of THIS test holds: the token was never revoked by the disconnect.
    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        assert ws.receive_json()["type"] == "session.established"


def test_idle_sweep_revokes_the_sessions_own_token(db_session):
    """Unit-level, mirroring test_sweeper_closes_idle_session in
    test_sessions.py: the idle sweeper's IDLE_TIMEOUT termination is a
    "for cause" reason and must revoke the session's token too."""
    from datetime import timedelta

    from app.core.security import create_access_token
    from app.models.session import Session, SessionState, utcnow
    from app.models.user import User
    from app.services import session as session_service
    from app.services.auth.revocation import is_token_revoked

    user = User(
        username="idluser", email="idluser@example.com",
        hashed_password="x", role="user",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_access_token(user.id)
    import jwt as pyjwt

    from app.core.config import get_settings

    settings = get_settings()
    claims = pyjwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    assert not is_token_revoked(claims["jti"])

    old = utcnow() - timedelta(hours=2)  # well past the 30-min idle timeout
    stale = Session(
        id="b" * 32, user_id=user.id, state=SessionState.ACTIVE,
        created_at=old, last_seen_at=old,
        token_jti=claims["jti"], token_exp=utcnow() + timedelta(minutes=30),
    )
    db_session.add(stale)
    db_session.commit()

    closed = session_service.sweep_expired_sessions(db_session)
    assert "b" * 32 in closed
    assert is_token_revoked(claims["jti"])


def test_revoked_token_cannot_open_a_new_websocket_session(client):
    admin_token = _register(client, ADMIN)["access_token"]
    user_token = _register(client, USER)["access_token"]

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        client.delete(f"/api/v1/sessions/{session_id}", headers=_bearer(admin_token))
        with suppress(Exception):
            ws.receive_json()

    # the now-revoked token can no longer open a brand-new session either
    try:
        with client.websocket_connect(f"{WS_PATH}?token={user_token}"):
            raised = False
    except WebSocketDisconnect as exc:
        raised = True
        assert exc.code == 1008
    assert raised


def test_terminating_one_session_does_not_revoke_a_different_one(client):
    """Multi-device use: ending session A must not silently sign session B's
    token out. Each session's token is revoked independently."""
    admin_token = _register(client, ADMIN)["access_token"]
    user_token = _register(client, USER)["access_token"]
    other_token = _register(client, OTHER)["access_token"]

    with client.websocket_connect(f"{WS_PATH}?token={user_token}") as ws_a:
        session_a = ws_a.receive_json()["session_id"]

        with client.websocket_connect(f"{WS_PATH}?token={other_token}") as ws_b:
            session_b = ws_b.receive_json()["session_id"]

            # end bob's session only; alice's token/session must be unaffected
            resp = client.delete(
                f"/api/v1/sessions/{session_b}", headers=_bearer(admin_token)
            )
            assert resp.status_code == 200
            with suppress(Exception):
                ws_b.receive_json()

        assert client.get(
            "/api/v1/sessions/current", headers=_bearer(user_token)
        ).json()["id"] == session_a

    # alice's own token still works after bob's session/socket closed
    assert client.get("/api/v1/auth/me", headers=_bearer(user_token)).status_code == 200
    # and bob's token, correctly, no longer does
    assert client.get("/api/v1/auth/me", headers=_bearer(other_token)).status_code == 401


def test_a_token_that_never_opened_a_session_is_unaffected_by_others_ending(client):
    admin_token = _register(client, ADMIN)["access_token"]
    user_token = _register(client, USER)["access_token"]  # never used to open a WS session
    carol_token = _register(
        client, {"username": "carol", "email": "carol@example.com", "password": "carolpass123"}
    )["access_token"]

    with client.websocket_connect(f"{WS_PATH}?token={carol_token}") as ws:
        session_id = ws.receive_json()["session_id"]
        assert client.delete(
            f"/api/v1/sessions/{session_id}", headers=_bearer(admin_token)
        ).status_code == 200
        with suppress(Exception):
            ws.receive_json()

    # alice's own never-a-session token is untouched by carol's session ending
    assert client.get("/api/v1/auth/me", headers=_bearer(user_token)).status_code == 200


def test_revocation_unit_roundtrip():
    from app.models.session import utcnow
    from app.services.auth.revocation import is_token_revoked, revoke_access_token
    from datetime import timedelta

    jti = "unit-test-jti-1234567890abcdef"
    assert is_token_revoked(jti) is False

    revoke_access_token(jti, utcnow() + timedelta(minutes=5))
    assert is_token_revoked(jti) is True

    # missing jti/exp is always a no-op / never revoked
    revoke_access_token(None, utcnow() + timedelta(minutes=5))
    assert is_token_revoked(None) is False
