"""
Standalone SMTP connectivity check for Module 6's email-OTP delivery.

    python -m app.services.mfa.smtp_check you@example.com

Sends one real verification-style email through the exact same function the
live app uses (``email_otp.send_verification_email``), completely outside
the login/trust-score/MFA-challenge flow: no database row is created, no
user account is touched, and nothing about the app's actual MFA state
changes. It exists purely so `backend/.env`'s SMTP_HOST/PORT/USE_TLS/
USERNAME/PASSWORD can be verified with one command, instead of registering
an account, logging in, and hoping a MEDIUM-risk decision happens to fire.

Exit codes:
  0  SMTP is configured and the send succeeded (real email sent to the
     given address -- go check that inbox).
  1  SMTP is NOT configured (SMTP_USERNAME/SMTP_PASSWORD blank in .env) --
     nothing was sent; this is the same dev_logged fallback the app itself
     would take.
  2  SMTP is configured but the send failed (bad App Password, 2-Step
     Verification not enabled, network/firewall block on port 587, etc.) --
     the underlying error is printed so the true cause is visible instead of
     the generic "delivery failed" the API layer would otherwise show.
"""
from __future__ import annotations

import sys

from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.services.mfa import email_otp

logger = get_logger(__name__)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: python -m app.services.mfa.smtp_check <recipient-email>")
        return 2

    to_address = sys.argv[1]
    settings = get_settings()

    if not email_otp.is_smtp_configured():
        print(
            "SMTP is NOT configured -- SMTP_USERNAME/SMTP_PASSWORD are blank "
            "in backend/.env. The app would dev-log the code instead of "
            "emailing it. Fill in those two values (plus SMTP_HOST/PORT/"
            "USE_TLS, which already default correctly for Gmail) and re-run "
            "this check."
        )
        return 1

    print(f"SMTP configured: {settings.smtp_host}:{settings.smtp_port} "
          f"(TLS={settings.smtp_use_tls}) as {settings.smtp_username}")
    print(f"Sending a real test code to {to_address} ...")

    code = email_otp.generate_code()
    try:
        delivered_via = email_otp.send_verification_email(
            to_address=to_address, code=code, expires_minutes=5,
        )
    except email_otp.EmailDeliveryError as exc:
        print(f"FAILED -- SMTP is configured but the send raised: {exc}")
        print(
            "Common causes: an App Password copied with a stray space, "
            "2-Step Verification not actually enabled on the sending "
            "account, or an outbound-port-587 block on this network."
        )
        return 2

    print(f"SENT (delivered_via={delivered_via}). Check {to_address}'s inbox "
          f"(and spam folder) for the code -- it expires in 5 minutes, but "
          f"this script's only purpose is confirming delivery, not the code "
          f"itself.")
    return 0


if __name__ == "__main__":
    configure_logging()
    raise SystemExit(main())
