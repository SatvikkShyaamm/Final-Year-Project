"""
services/mfa/ -> Module 6: Adaptive MFA.

  email_otp.py  code generation, salted hashing, and Gmail-SMTP delivery
                (the only place `smtplib` is used; TOTP/pyotp were removed
                2026-09-10 at the user's explicit request)
  service.py    the risk-band decision + email challenge lifecycle
                (create / verify / expiry / retry / success-failure)

There is no session hook here -- the MFA gate is at /auth/login, before a
session exists. A MEDIUM-risk login gets an `mfa_pending` token that only
/mfa/verify accepts; a HIGH-risk login gets nothing. Module 7 will reuse
``create_challenge`` to re-challenge an active session, via this same email
path.
"""
from app.services.mfa.service import (
    ChallengeExhausted,
    ChallengeExpired,
    ChallengeNotFound,
    ChallengeNotPending,
    Decision,
    DeliveryFailed,
    InvalidCode,
    MFAError,
    build_challenge_out,
    count_by_status,
    create_challenge,
    decide,
    get_challenge,
    list_recent_challenges,
    verify_challenge,
)

__all__ = [
    "ChallengeExhausted",
    "ChallengeExpired",
    "ChallengeNotFound",
    "ChallengeNotPending",
    "Decision",
    "DeliveryFailed",
    "InvalidCode",
    "MFAError",
    "build_challenge_out",
    "count_by_status",
    "create_challenge",
    "decide",
    "get_challenge",
    "list_recent_challenges",
    "verify_challenge",
]
