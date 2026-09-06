"""
SQLAlchemy engine/session setup.

Module 1 only establishes connectivity and the declarative Base. Actual
tables (User, Session, ACLRule, TrustScoreEvent, MFAChallenge, SecurityAlert,
...) are added by the modules that own them (2, 3, 4, 5, 6, 7) via Alembic
migrations in backend/alembic/versions.
"""
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings

settings = get_settings()

engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""
    pass


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: yields a DB session and guarantees it is closed."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def db_session_scope() -> Generator[Session, None, None]:
    """Context-manager variant for use outside request handlers (e.g. WS handlers,
    background tasks in later modules)."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def check_database_connection() -> bool:
    """Used by the /health endpoint to report real DB connectivity."""
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        return True
    except Exception:
        return False
