"""
Thin TOTP (RFC 6238) wrapper — Module 6.

The one place `pyotp` is touched. Parameters (digits, interval, skew window,
issuer) come from config so Module 10 can tune them.
"""
from __future__ import annotations

import pyotp

from app.core.config import get_settings

settings = get_settings()


def new_secret() -> str:
    return pyotp.random_base32()


def _totp(secret: str) -> pyotp.TOTP:
    return pyotp.TOTP(
        secret,
        digits=settings.mfa_totp_digits,
        interval=settings.mfa_totp_interval_seconds,
    )


def provisioning_uri(secret: str, username: str) -> str:
    """`otpauth://` URI for an authenticator app / QR code."""
    return _totp(secret).provisioning_uri(
        name=username, issuer_name=settings.mfa_totp_issuer
    )


def verify(secret: str, code: str) -> bool:
    try:
        return _totp(secret).verify(
            (code or "").strip(), valid_window=settings.mfa_totp_valid_window
        )
    except Exception:  # noqa: BLE001 - a malformed code must never raise
        return False


def current_code(secret: str) -> str:
    """The code valid right now — dev/test convenience only."""
    return _totp(secret).now()
