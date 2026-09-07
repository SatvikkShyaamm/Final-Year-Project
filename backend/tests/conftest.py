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
from app.core.database import Base, get_db
from app.main import app


@pytest.fixture(autouse=True)
def fake_redis(monkeypatch):
    """Swap the shared Redis client for an in-memory fake for every test.

    Module 3's session store goes through ``app.core.redis_client.get_redis()``,
    which reads this module attribute at call time — so patching it here is
    enough.
    """
    client = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr("app.core.redis_client.redis_client", client)
    return client


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
def client(db_engine):
    TestingSessionLocal = sessionmaker(
        bind=db_engine, autocommit=False, autoflush=False, future=True
    )

    def override_get_db():
        db = TestingSessionLocal()
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
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
