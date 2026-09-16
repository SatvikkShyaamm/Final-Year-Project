"""
Shared pytest fixtures.

Tests run against an in-memory SQLite database (ORM schema created straight
from ``Base.metadata``) with ``get_db`` overridden, and against an in-memory
fake Redis — so the suite needs neither Postgres, Alembic, nor a Redis server
and stays hermetic in CI.
"""
from __future__ import annotations

from contextlib import suppress

import fakeredis
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401  (register all ORM models on Base.metadata)
from app.core.config import get_settings
from app.core.database import Base, SessionLocal, get_db
from app.main import app
from app.services.acl.enforcer import reset_enforcer


@pytest.fixture(autouse=True)
def fake_redis(monkeypatch):
    """Swap the shared Redis client for an in-memory fake for every test.

    The session store and the ACL store both go through
    ``app.core.redis_client.get_redis()``, which reads this module attribute at
    call time — so patching it here is enough.
    """
    client = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr("app.core.redis_client.redis_client", client)
    return client


@pytest.fixture(autouse=True)
def _no_real_smtp(monkeypatch):
    """Force SMTP "not configured" for every test, regardless of what a
    developer's real `backend/.env` has set locally.

    Settings.model_config points at `.env` (see app/core/config.py), and
    since Project status.md section 14, a real dev machine's `.env` carries a
    genuine Gmail App Password so MFA codes actually get emailed outside
    tests. Every MFA/auth test in this suite is written against the
    documented, load-bearing assumption that SMTP is unconfigured in the test
    environment (dev_logged delivery, `dev_code` echoed back) -- without this
    override, running the suite on a machine with real credentials configured
    makes it try to send real email (and, if those credentials are stale or
    Google rejects them, fail with a 503 instead of the expected 200/mfa
    payload) instead of exercising the code path the tests actually mean to
    cover. Scoped to settings only, not `.env` itself -- no file is touched.
    """
    settings = get_settings()
    monkeypatch.setattr(settings, "smtp_username", "", raising=False)
    monkeypatch.setattr(settings, "smtp_password", "", raising=False)


@pytest.fixture(autouse=True)
def _acl_test_env(monkeypatch):
    """Deterministic ACL layer for tests: no background L-PEP worker (tests
    drain the queue explicitly), and a fresh enforcer selection each test."""
    settings = get_settings()
    monkeypatch.setattr(settings, "l_pep_worker_enabled", False, raising=False)
    reset_enforcer()
    yield
    reset_enforcer()


@pytest.fixture(autouse=True)
def _fast_reconnect_grace(monkeypatch):
    """A short `session_reconnect_grace_seconds` for every test (2026-09-16
    hardening -- see app/api/v1/endpoints/sessions.py's WS handler).

    Production defaults to 5s, generous enough for a real page refresh over a
    slow connection. Tests need the opposite trade-off: existing polling
    helpers like `_wait_terminated` (tries=20, 0.05s sleep = a 1s budget) were
    written assuming an ordinary disconnect finalizes near-instantly, and
    keeping that budget correct without editing every one of those tests
    means the grace window here has to stay comfortably under it. 0.3s
    leaves 20x headroom (in-process ASGI transport reconnects in low single-
    digit milliseconds, no real network involved) for a reattach test's
    "reconnect immediately with the same token" step to land safely inside
    the window, while `_wait_terminated`'s 1s budget still lands safely
    outside it for tests that want the eventual finalize instead."""
    settings = get_settings()
    monkeypatch.setattr(settings, "session_reconnect_grace_seconds", 0.3, raising=False)


@pytest.fixture()
def db_engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    try:
        yield engine
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture()
def _testing_session_local(db_engine):
    return sessionmaker(
        bind=db_engine, autocommit=False, autoflush=False, future=True
    )


@pytest.fixture()
def db_session(_testing_session_local):
    """A plain DB session on the same engine the TestClient uses — for calling
    service/worker functions directly (e.g. acl.drain_queue)."""
    session = _testing_session_local()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(_testing_session_local, db_engine):
    def override_get_db():
        db = _testing_session_local()
        try:
            yield db
        finally:
            # suppress: a WebSocket handler's dependency generator can be
            # GC-closed by the portal shutdown after this fixture's engine is
            # already disposed — harmless test-teardown ordering, not a leak
            # (in-process FastAPI closes the WS session as soon as the handler
            # returns).
            with suppress(Exception):
                db.close()

    app.dependency_overrides[get_db] = override_get_db

    # 2026-09-16: dependency_overrides only reaches code that asks for the DB
    # via FastAPI's own Depends(get_db) resolution -- it has no effect on
    # code that opens its own session straight from app.core.database.
    # SessionLocal, which is exactly what app.main's idle/lifetime sweeper
    # background task already does, and what sessions.py's new reconnect-
    # grace `_finalize_disconnect` background task does too. SessionLocal is
    # a sessionmaker INSTANCE, not a plain reference, so every module that
    # did `from app.core.database import SessionLocal` holds the SAME object
    # -- reconfiguring its bind here (rather than swapping which object the
    # name points to) reaches all of them, including ones already imported
    # long before this fixture runs. Without this, those two background
    # paths try to reach the real (Postgres) database_url from settings,
    # which doesn't exist in CI, and silently never finish their job -- this
    # is the exact "OperationalError: Connection refused" this hardening
    # pass's own new tests surfaced; the sweeper had the identical latent gap
    # all along, just never exercised because it only wakes on a 30s timer
    # that essentially never fires within one fast test.
    SessionLocal.configure(bind=db_engine)
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
