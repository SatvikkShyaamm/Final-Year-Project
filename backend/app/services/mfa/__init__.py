"""
services/mfa/ -> Module 6: Adaptive MFA.

  totp.py     RFC 6238 TOTP wrapper (the only place pyotp is used)
  service.py  the risk-band decision + TOTP challenge lifecycle
              (create / verify / expiry / retry / success-failure)

There is no session hook here — the MFA gate is at /auth/login, before a
session exists. A MEDIUM-risk login gets an `mfa_pending` token that only
/mfa/verify accepts; a HIGH-risk login gets nothing. Module 7 will reuse
``create_challenge`` to re-challenge an active session.
"""
from app.services.mfa.service import (
    ChallengeExhausted,
    ChallengeExpired,
    ChallengeNotFound,
    ChallengeNotPending,
    Decision,
    InvalidCode,
    MFAError,
    build_challenge_out,
    count_by_status,
    create_challenge,
    decide,
    get_challenge,
    get_or_create_credential,
    list_recent_challenges,
    verify_challenge,
)

__all__ = [
    "ChallengeExhausted",
    "ChallengeExpired",
    "ChallengeNotFound",
    "ChallengeNotPending",
    "Decision",
    "InvalidCode",
    "MFAError",
    "build_challenge_out",
    "count_by_status",
    "create_challenge",
    "decide",
    "get_challenge",
    "get_or_create_credential",
    "list_recent_challenges",
    "verify_challenge",
]
