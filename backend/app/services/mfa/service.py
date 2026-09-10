"""
Adaptive MFA business logic — Module 6.

Two responsibilities:

  1. DECIDE  map a trust-score risk band to allow / require-MFA / block
             (Section 6: LOW -> allow, MEDIUM -> MFA, HIGH -> block; the
             thresholds are Module 5's configurable trust_risk_* values).
  2. CHALLENGE  create / verify TOTP challenges — generation, expiry, retry
                handling, success/failure handling.

No FastAPI imports. Called from the /auth/login handler (the decision +
challenge creation) and the /mfa/* endpoints (verify, step-up, admin feed).
Module 7 will reuse ``create_challenge`` to re-trigger MFA mid-session.
"""
from __future__ import annotations

import json
import uuid
from datetime import timedelta

import redis
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.redis_client import get_redis
from app.models.mfa import (
    MFAChallenge,
    MFAChallengeReason,
    MFAChallengeStatus,
    MFACredential,
    MFAMethod,
)
from app.models.session import utcnow
from app.models.trust_score import RiskLevel
from app.schemas.mfa import MFAChallengeOut, MFAEnrollmentOut
from app.services.mfa import totp

logger = get_logger(__name__)
settings = get_settings()

_EVENT_CHANNEL = "ztsaacm:events:mfa"


# --------------------------------------------------------------------------- #
# Decision
# --------------------------------------------------------------------------- #
class Decision:
    ALLOW = "allow"
    MFA = "mfa"
    BLOCK = "block"


def decide(risk_level: str) -> str:
    """Section-6 risk band -> action. Honours the mfa_enabled master switch:
    when MFA is disabled, a MEDIUM band is allowed through (HIGH still blocks)."""
    if risk_level == RiskLevel.HIGH:
        return Decision.BLOCK
    if risk_level == RiskLevel.MEDIUM:
        return Decision.MFA if settings.mfa_enabled else Decision.ALLOW
    return Decision.ALLOW


# --------------------------------------------------------------------------- #
# Errors (mapped to HTTP by the endpoint layer)
# --------------------------------------------------------------------------- #
class MFAError(Exception):
    pass


class ChallengeNotFound(MFAError):
    pass


class ChallengeNotPending(MFAError):
    pass


class ChallengeExpired(MFAError):
    pass


class ChallengeExhausted(MFAError):
    pass


class InvalidCode(MFAError):
    def __init__(self, attempts_remaining: int) -> None:
        super().__init__("invalid code")
        self.attempts_remaining = attempts_remaining


# --------------------------------------------------------------------------- #
# Credentials
# --------------------------------------------------------------------------- #
def get_or_create_credential(db: DbSession, user) -> MFACredential:
    cred = db.scalar(
        select(MFACredential).where(MFACredential.user_id == user.id)
    )
    if cred is not None:
        return cred
    cred = MFACredential(
        id=uuid.uuid4().hex,
        user_id=user.id,
        method=MFAMethod.TOTP,
        secret=totp.new_secret(),
        confirmed=False,
    )
    db.add(cred)
    db.commit()
    db.refresh(cred)
    logger.info("mfa credential created user_id=%s", user.id)
    return cred


# --------------------------------------------------------------------------- #
# Challenges
# --------------------------------------------------------------------------- #
def create_challenge(
    db: DbSession,
    *,
    user,
    reason: str = MFAChallengeReason.LOGIN_RISK,
    trust_score: int | None = None,
    risk_level: str | None = None,
) -> MFAChallenge:
    now = utcnow()
    challenge = MFAChallenge(
        id=uuid.uuid4().hex,
        user_id=user.id,
        method=MFAMethod.TOTP,
        status=MFAChallengeStatus.PENDING,
        reason=reason,
        attempts=0,
        max_attempts=max(1, settings.mfa_max_attempts),
        trust_score=trust_score,
        risk_level=risk_level,
        created_at=now,
        expires_at=now + timedelta(minutes=max(1, settings.mfa_challenge_ttl_minutes)),
    )
    db.add(challenge)
    db.commit()
    db.refresh(challenge)
    logger.info(
        "mfa challenge created id=%s user_id=%s reason=%s risk=%s",
        challenge.id, user.id, reason, risk_level,
    )
    _publish("mfa.challenge.created", challenge)
    return challenge


def verify_challenge(db: DbSession, *, challenge: MFAChallenge, code: str) -> MFAChallenge:
    """Check one TOTP code against the challenge. Raises on any non-success."""
    if challenge.status != MFAChallengeStatus.PENDING:
        raise ChallengeNotPending(challenge.status)

    if utcnow() >= challenge.expires_at:
        challenge.status = MFAChallengeStatus.EXPIRED
        db.commit()
        _publish("mfa.challenge.expired", challenge)
        raise ChallengeExpired()

    cred = db.scalar(
        select(MFACredential).where(MFACredential.user_id == challenge.user_id)
    )
    if cred is not None and totp.verify(cred.secret, code):
        now = utcnow()
        challenge.status = MFAChallengeStatus.VERIFIED
        challenge.verified_at = now
        cred.confirmed = True
        cred.confirmed_at = cred.confirmed_at or now
        cred.last_used_at = now
        db.commit()
        db.refresh(challenge)
        logger.info("mfa challenge verified id=%s user_id=%s", challenge.id, challenge.user_id)
        _publish("mfa.challenge.verified", challenge)
        return challenge

    challenge.attempts += 1
    if challenge.attempts >= challenge.max_attempts:
        challenge.status = MFAChallengeStatus.FAILED
        db.commit()
        db.refresh(challenge)
        logger.info("mfa challenge failed (exhausted) id=%s user_id=%s", challenge.id, challenge.user_id)
        _publish("mfa.challenge.failed", challenge)
        raise ChallengeExhausted()

    db.commit()
    db.refresh(challenge)
    logger.info(
        "mfa challenge bad code id=%s user_id=%s attempts=%s/%s",
        challenge.id, challenge.user_id, challenge.attempts, challenge.max_attempts,
    )
    _publish("mfa.challenge.bad_code", challenge)
    raise InvalidCode(attempts_remaining=challenge.attempts_remaining)


# --------------------------------------------------------------------------- #
# Response shaping (shared by /auth/login and POST /mfa/challenge)
# --------------------------------------------------------------------------- #
def _dev_exposed() -> bool:
    return settings.mfa_dev_expose_code or settings.environment == "development"


def build_challenge_out(
    challenge: MFAChallenge, credential: MFACredential, *, mfa_token: str
) -> MFAChallengeOut:
    enrollment = None
    if not credential.confirmed:
        enrollment = MFAEnrollmentOut(
            secret=credential.secret,
            provisioning_uri=totp.provisioning_uri(
                credential.secret, challenge.username or f"user{challenge.user_id}"
            ),
            digits=settings.mfa_totp_digits,
            interval_seconds=settings.mfa_totp_interval_seconds,
        )
    return MFAChallengeOut(
        challenge_id=challenge.id,
        mfa_token=mfa_token,
        method=challenge.method,
        reason=challenge.reason,
        status=challenge.status,
        expires_at=challenge.expires_at,
        attempts_remaining=challenge.attempts_remaining,
        max_attempts=challenge.max_attempts,
        trust_score=challenge.trust_score,
        risk_level=challenge.risk_level,
        enrollment=enrollment,
        dev_code=totp.current_code(credential.secret) if _dev_exposed() else None,
    )


# --------------------------------------------------------------------------- #
# Reads (endpoints)
# --------------------------------------------------------------------------- #
def get_challenge(db: DbSession, challenge_id: str) -> MFAChallenge | None:
    return db.get(MFAChallenge, challenge_id)


def list_recent_challenges(
    db: DbSession, *, limit: int = 100, status: str | None = None
) -> list[MFAChallenge]:
    stmt = select(MFAChallenge).order_by(MFAChallenge.created_at.desc()).limit(limit)
    if status is not None:
        stmt = stmt.where(MFAChallenge.status == status)
    return list(db.scalars(stmt))


def count_by_status(db: DbSession) -> dict[str, int]:
    rows = db.execute(
        select(MFAChallenge.status, func.count()).group_by(MFAChallenge.status)
    ).all()
    counts = {s: 0 for s in MFAChallengeStatus.ALL}
    for status_value, n in rows:
        counts[status_value] = int(n)
    return counts


# --------------------------------------------------------------------------- #
# Events (best-effort, for the Module 8 dashboard)
# --------------------------------------------------------------------------- #
def _publish(event_type: str, challenge: MFAChallenge) -> None:
    payload = {
        "type": event_type,
        "challenge_id": challenge.id,
        "user_id": challenge.user_id,
        "username": challenge.username,
        "reason": challenge.reason,
        "status": challenge.status,
        "risk_level": challenge.risk_level,
        "trust_score": challenge.trust_score,
        "ts": utcnow().isoformat(),
    }
    try:
        get_redis().publish(_EVENT_CHANNEL, json.dumps(payload))
    except redis.RedisError:
        logger.debug("redis mfa publish %s failed", event_type, exc_info=True)
