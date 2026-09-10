"""
Centralized application configuration.

All settings are loaded from environment variables (see /.env.example and
/backend/.env.example). Nothing here should be hard-coded for production —
this module exists precisely so that Module 5/6/7 thresholds, JWT secrets,
and infrastructure hosts can be tuned without touching code.
"""
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ---- General ----
    project_name: str = "ZTSAACM Security Dashboard"
    environment: str = "development"

    # ---- PostgreSQL ----
    postgres_user: str = "ztsaacm"
    postgres_password: str = "change_me_dev_password"
    postgres_db: str = "ztsaacm_db"
    postgres_host: str = "localhost"
    postgres_port: int = 5432

    # ---- Redis ----
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str | None = None

    # ---- Backend ----
    backend_port: int = 8000
    jwt_secret_key: str = "change_me_dev_secret_key"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # ---- Session lifecycle (Module 3) ----
    # An application session ends when its WebSocket closes; these bound how
    # long an *idle* or *very old* session may linger if the socket somehow
    # stays half-open. All tunable for Module 10's evaluation.
    session_idle_timeout_minutes: int = 30
    session_max_lifetime_minutes: int = 480
    session_sweep_interval_seconds: int = 30
    session_ws_heartbeat_seconds: int = 20

    # ---- Dynamic ACL (Module 4) ----
    # Which enforcement backend the L-PEP worker uses:
    #   auto      - use real ipset if the `ipset` command works, else simulate
    #   ipset     - always shell out to ipset/ip6tables (needs a Linux host +
    #               NET_ADMIN; this is what the standalone infra/l-pep runs)
    #   simulated - record the kernel allow-list in Redis only (dev / Docker / CI)
    acl_enforcement_backend: str = "auto"
    # Label for what the allow-list entry grants reach to (the paper's
    # "protected resource" behind the enforcement point).
    acl_protected_resource: str = "protected-app"
    # ipset set names, matching the base paper's ztsaacm_allowed / _v6.
    acl_ipset_v4: str = "ztsaacm_allowed"
    acl_ipset_v6: str = "ztsaacm_allowed_v6"
    # Fail-safe TTL (seconds) on each kernel allow-list entry so a lost
    # revocation can't leave access open forever. 0 disables it.
    acl_entry_ttl_seconds: int = 900
    # Run the L-PEP task consumer inside this process (single-container dev /
    # demo). Set false when running the standalone infra/l-pep worker instead.
    l_pep_worker_enabled: bool = True
    l_pep_poll_timeout_seconds: int = 1

    # ---- Trust Score Engine (Module 5) ----
    # These are the FINALIZED Section-6 factor weights (approved). They live in
    # config so Module 10 can tune them for evaluation without touching code.
    # Formula: score = clamp(baseline + Σ positives - Σ negatives, 0, 100),
    # computed ONCE at session creation (static score). Dynamic in-session
    # recalculation is Module 7, not Module 5.
    trust_score_baseline: int = 70
    trust_weight_known_device: int = 15        # + : User-Agent seen before for this user
    trust_weight_known_ip: int = 10            # + : IP / same /24 (or /64) as a recent session
    trust_weight_typical_hour: int = 5         # + : login within the user's usual hour range
    trust_weight_unknown_device: int = 10      # - : new User-Agent, user has history
    trust_weight_ip_changed: int = 10          # - : IP differs from the most recent session
    trust_weight_approved_vpn: int = 10        # + : source IP in an org-approved VPN CIDR
    trust_weight_unknown_vpn: int = 15         # - : source IP in a known public VPN/proxy CIDR
    trust_weight_failed_logins: int = 15       # - : >= threshold failed logins in the window
    trust_weight_off_hours: int = 5            # - : login 00:00-05:00, fallback when no hour history
    trust_failed_login_threshold: int = 3
    trust_failed_login_window_minutes: int = 15
    trust_typical_hour_min_sessions: int = 5   # need this many prior sessions to learn a range
    trust_off_hours_start_hour: int = 0        # inclusive, local time (see offset below)
    trust_off_hours_end_hour: int = 5          # exclusive
    trust_local_utc_offset_hours: int = 0      # shift session timestamps for the hour-of-day checks
    # Risk bands (feed Module 6): score >= low_min -> LOW; >= medium_min -> MEDIUM; else HIGH.
    trust_risk_low_min: int = 80
    trust_risk_medium_min: int = 50
    # VPN CIDR allow/deny lists. STATIC DEMO SAMPLES, not a live threat feed —
    # named as a limitation in the writeup. Module 9's "Simulate Approved/Unknown
    # VPN" buttons draw a source IP from these ranges.
    trust_approved_vpn_cidrs_raw: str = "10.8.0.0/24,10.9.0.0/24"
    trust_known_vpn_cidrs_raw: str = "185.220.100.0/22,185.220.101.0/24,51.75.0.0/16,45.83.220.0/22"

    # ---- Adaptive MFA (Module 6) ----
    # Decision at login (Section 6 bands, reusing the trust_risk_* thresholds
    # above): risk LOW -> allow, MEDIUM -> require MFA, HIGH -> block.
    # mfa_enabled is the MFA-step master switch: when false, MEDIUM logins are
    # allowed straight through (HIGH is still blocked). For Module 10 perf runs.
    mfa_enabled: bool = True
    mfa_challenge_ttl_minutes: int = 5
    mfa_max_attempts: int = 5
    # Every MFA challenge (first login and every one after) is a one-time
    # numeric code emailed to the user's registered address. There is no
    # authenticator-app / TOTP path in this system (deliberately removed
    # 2026-09-10 -- see docs/architecture.md and Project status.md section 11;
    # Module 7's continuous re-verification will reuse this same email path,
    # not TOTP, when it is built).
    mfa_otp_length: int = 6

    # ---- Outbound email (Gmail SMTP) for MFA codes ----
    # smtp_username/smtp_password are the SENDING Gmail account (a Gmail App
    # Password, not the account password -- generate one at
    # https://myaccount.google.com/apppasswords). The RECIPIENT is always the
    # address the user registered with (users.email). Leave smtp_username /
    # smtp_password blank in dev: send_verification_email() then logs the code
    # server-side instead of emailing it (see mfa_dev_expose_code below), so
    # the suite and local dev work without real Gmail credentials.
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_use_tls: bool = True
    smtp_username: str = ""
    smtp_password: str = ""
    mfa_email_from_name: str = "ZTSAACM Security"
    mfa_email_subject: str = "Your ZTSAACM verification code"

    # When true (or environment == "development") AND SMTP is not configured,
    # the MFA challenge response also carries the plaintext code (`dev_code`)
    # so local dev/tests work without a real mailbox. The moment smtp_username
    # / smtp_password are set, real email is sent and dev_code is never
    # returned, regardless of this flag -- MUST be false (or SMTP must be
    # configured) in a real deployment.
    mfa_dev_expose_code: bool = False

    # Kept as a raw comma-separated string (not List[str]) because
    # pydantic-settings tries to JSON-decode list-typed env vars before any
    # validator runs, which breaks on a plain "http://a,http://b" value.
    # Use the `cors_origins` property below to get the parsed list.
    cors_origins_raw: str = Field(default="http://localhost:5173", validation_alias="CORS_ORIGINS")

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins_raw.split(",") if origin.strip()]

    @property
    def trust_approved_vpn_cidrs(self) -> list[str]:
        return [c.strip() for c in self.trust_approved_vpn_cidrs_raw.split(",") if c.strip()]

    @property
    def trust_known_vpn_cidrs(self) -> list[str]:
        return [c.strip() for c in self.trust_known_vpn_cidrs_raw.split(",") if c.strip()]

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg2://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def redis_url(self) -> str:
        auth = f":{self.redis_password}@" if self.redis_password else ""
        return f"redis://{auth}{self.redis_host}:{self.redis_port}/0"


@lru_cache
def get_settings() -> Settings:
    """Cached settings accessor — import and call this, don't instantiate directly."""
    return Settings()
