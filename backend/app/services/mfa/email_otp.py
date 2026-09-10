"""
Email one-time-code generation, hashing, and delivery -- Module 6.

The one place `smtplib` is touched, and the only MFA "method" in this system
(TOTP was removed 2026-09-10 at the user's explicit request -- see
docs/architecture.md and Project status.md section 11). A challenge's code is
generated fresh every time (nothing persists between challenges -- there is
no per-user secret to enroll or store), hashed for storage, and emailed to
the user's registered address via Gmail SMTP.

Delivery has three outcomes, recorded on the challenge as `delivered_via`:

  SENT        SMTP is configured (settings.smtp_username/smtp_password set)
              and the send succeeded.
  DEV_LOGGED  SMTP is NOT configured -- the code is logged server-side
              (logger.info) instead of emailed, so local dev and the test
              suite work without a real mailbox. The API only echoes the
              code back as `dev_code` in this case, and only when
              `mfa_dev_expose_code` is true or `environment == "development"`.
  FAILED      SMTP is configured but the send raised. The caller
              (services/mfa/service.create_challenge) surfaces this as a 503
              rather than silently handing out a challenge nobody can ever
              complete -- unlike Redis's best-effort philosophy elsewhere in
              this codebase, a failed *code delivery* is not something a
              login attempt can safely continue past.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import smtplib
from email.message import EmailMessage

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


class EmailDeliveryError(Exception):
    """SMTP is configured but sending the code failed."""


def is_smtp_configured() -> bool:
    return bool(settings.smtp_username and settings.smtp_password)


def generate_code(length: int | None = None) -> str:
    """A cryptographically random numeric code, e.g. '048213' for length 6."""
    n = length or settings.mfa_otp_length
    return "".join(secrets.choice("0123456789") for _ in range(n))


def new_salt() -> str:
    return secrets.token_hex(16)  # 32 hex chars


def hash_code(code: str, salt: str) -> str:
    """Salted HMAC-SHA256 of the code, hex-encoded (64 chars). The salt is
    per-challenge and random, so two identical codes never hash the same,
    and JWT_SECRET_KEY doubles as the HMAC key (no new secret to manage)."""
    key = f"{salt}:{settings.jwt_secret_key}".encode("utf-8")
    return hmac.new(key, code.strip().encode("utf-8"), hashlib.sha256).hexdigest()


def verify_code(code: str, *, salt: str, expected_hash: str) -> bool:
    candidate = hash_code(code or "", salt)
    return hmac.compare_digest(candidate, expected_hash)


def send_verification_email(*, to_address: str, code: str, expires_minutes: int) -> str:
    """Send (or dev-log) one verification code. Returns the `delivered_via`
    value to store on the challenge. Raises EmailDeliveryError if SMTP is
    configured but the send itself fails."""
    if not is_smtp_configured():
        logger.info(
            "[DEV] MFA email not sent (SMTP not configured) -- to=%s code=%s "
            "(valid %s min)",
            to_address, code, expires_minutes,
        )
        return "dev_logged"

    message = EmailMessage()
    message["Subject"] = settings.mfa_email_subject
    message["From"] = f"{settings.mfa_email_from_name} <{settings.smtp_username}>"
    message["To"] = to_address
    message.set_content(
        "Your ZTSAACM verification code is:\n\n"
        f"    {code}\n\n"
        f"This code expires in {expires_minutes} minute"
        f"{'s' if expires_minutes != 1 else ''}. "
        "If you didn't request this, you can ignore this email."
    )

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
            if settings.smtp_use_tls:
                smtp.starttls()
            smtp.login(settings.smtp_username, settings.smtp_password)
            smtp.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        logger.warning("mfa email send failed to=%s: %s", to_address, exc, exc_info=True)
        raise EmailDeliveryError(str(exc)) from exc

    logger.info("mfa email sent to=%s", to_address)
    return "sent"
