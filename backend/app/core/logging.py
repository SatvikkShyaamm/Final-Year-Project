"""
Minimal structured logging setup shared by the whole backend.

Kept intentionally simple in Module 1. Modules that generate audit-relevant
events (Trust Score changes, MFA outcomes, ACL create/remove, session
revocation) should log through this logger so that, later, log shipping /
correlation for Module 10 (testing & evaluation) has one consistent source.
"""
import logging
import sys

from app.core.config import get_settings

settings = get_settings()


def configure_logging() -> None:
    level = logging.DEBUG if settings.environment == "development" else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        stream=sys.stdout,
    )


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
