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
    # An application session ends when its WebSocket closes AND stays closed
    # past session_reconnect_grace_seconds (2026-09-16 -- see that setting);
    # session_idle_timeout_minutes/session_max_lifetime_minutes bound how long
    # an *idle* or *very old* session may otherwise linger if the socket
    # somehow stays half-open. All tunable for Module 10's evaluation.
    session_idle_timeout_minutes: int = 30
    session_max_lifetime_minutes: int = 480
    session_sweep_interval_seconds: int = 30
    session_ws_heartbeat_seconds: int = 20
    # 2026-09-16: how long an ordinary WebSocket drop (tab closed OR a page
    # refresh -- the two are indistinguishable at the transport level) is held
    # as still-ACTIVE-but-disconnected before being finalized as a genuine
    # close. A reconnect within this window that presents the SAME access
    # token (same jti -- see app.services.session.service.
    # get_active_session_by_token_jti) reattaches to this exact session
    # instead of opening a new one, so a page refresh no longer resets an
    # in-progress Module 7 trust score (or silently drops a pending re-verify
    # challenge) back to a fresh login-time baseline. Deliberately a short,
    # dedicated window -- NOT session_idle_timeout_minutes's 30 minutes -- so
    # a tab that's actually just closed still loses its ACL/session quickly,
    # matching this project's own "revoke fast" framing everywhere else.
    session_reconnect_grace_seconds: float = 5.0

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
    trust_weight_off_hours: int = 5            # - : login 00:00-05:00 -- ALWAYS checked (org policy
                                                #     floor), independent of any learned history; see
                                                #     trust_weight_atypical_hour below for the per-user
                                                #     dynamic layer on top of this static baseline
    trust_weight_atypical_hour: int = 8        # - : login outside the user's own learned typical-hour
                                                #     band (2026-09-21 hardening -- the dynamic
                                                #     counterpart of trust_weight_typical_hour; only
                                                #     applies once trust_typical_hour_min_sessions is met)
    # ---- Continuous Trust Evaluation (Module 7) -- mid-session event weights ----
    # Applied by app/services/trust_score/continuous.py against the session's
    # CURRENT score (not the baseline) when a security-relevant event is
    # ingested via POST /security/events. ip_change / vpn_detected /
    # unknown_device / multiple_failed_logins reuse the Module 5 weights above
    # (the same signal, observed mid-session instead of at login); these two
    # are new, since Module 5 has no login-time equivalent for them.
    trust_weight_abnormal_request_rate: int = 20  # - : request rate far above the user's norm
    trust_weight_large_download: int = 20         # - : abnormally large data transfer observed
    # How long a mid-session re-verification challenge (reason=risk_retrigger)
    # stays open before the sweeper treats an unanswered one as a failure and
    # revokes the session it guards (see app.main._session_sweeper and
    # app.services.mfa.expire_overdue_challenges). Deliberately SHORTER than
    # mfa_challenge_ttl_minutes (the login-time window, still 5 minutes) --
    # once a session is already active and a security event has knocked its
    # live trust score down, zero trust puts the burden of re-proving identity
    # on the user on a tighter clock than the initial login challenge gets.
    mfa_retrigger_ttl_minutes: int = 3
    trust_failed_login_threshold: int = 3
    trust_failed_login_window_minutes: int = 15
    trust_typical_hour_min_sessions: int = 5   # need this many prior sessions to learn a range
    # 2026-09-21 hardening: the learned typical-hour band is mean +/- k*stddev
    # over the user's recent login hours (history.py's rolling last-20-session
    # window), not a raw running min/max. A single outlier hour therefore only
    # nudges the mean/stddev a little instead of permanently redefining the
    # boundary, and its influence fades out entirely once it ages out of the
    # rolling window -- see evaluator._typical_hour_band's docstring.
    trust_typical_hour_band_stddev_multiplier: float = 1.5
    trust_typical_hour_min_band_hours: float = 2.0  # floor on the band's half-width
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
    # Module 7's continuous re-verification reuses this same email path,
    # not TOTP).
    mfa_otp_length: int = 6
    # ---- Account-level MFA lockout (Redis-backed, separate from the
    # per-challenge mfa_max_attempts above) ----
    # Per MASTER_PROJECT_CONTEXT.docx Section 7's original spec: a wrong-code
    # streak across ANY challenge for a user (login_risk / step_up /
    # risk_retrigger alike) -- not just one challenge's own attempt counter --
    # locks that user out of MFA entirely for a cool-down window. Two
    # independent knobs even though they default to the same value: how wide
    # a window the wrong attempts must fall within to count as a "streak"
    # (mfa_lockout_window_minutes), and how long the resulting lockout lasts
    # (mfa_lockout_duration_minutes). Redis-backed (`ztsaacm:mfa_failed:{id}` /
    # `ztsaacm:mfa_lockout:{id}`), best-effort like every other Redis-backed
    # counter in this codebase (session store, ACL ref-counts, the Module 5
    # failed-login burst counter, the token-revocation denylist) -- a
    # Redis outage fails OPEN (lets a real, correct code through rather than
    # locking every user out over an infrastructure blip), matching this
    # codebase's established policy for auxiliary Redis-backed protections.
    mfa_lockout_threshold: int = 3
    mfa_lockout_window_minutes: int = 15
    mfa_lockout_duration_minutes: int = 15

    # ---- Account-level RISK lockout (Redis-backed, Module 7 hardening,
    # 2026-09-14) ----
    # Distinct from the MFA lockout above: this tracks a session getting
    # forcibly revoked because continuous evaluation (Module 7) pushed its
    # LIVE score straight into HIGH -- a direct HIGH crossing, i.e.
    # TerminationReason.RISK_REVOKED with no reverify chance ever offered.
    # Deliberately does NOT count: a HIGH-risk *login* attempt (already
    # blocked per-attempt by its own 403), or a MEDIUM-risk reverify
    # challenge that was failed/exhausted/MFA-locked/left to expire (that's
    # a recoverable check the user didn't clear, not the same signal as an
    # outright HIGH crossing) -- see app.services.trust_score.risk_lockout's
    # module docstring for the full reasoning.
    #
    # Each qualifying offense blocks the ACCOUNT -- every device/User-Agent,
    # not just the one that misbehaved -- from logging in at all, for an
    # escalating cool-down: 1st offense -> risk_lockout_tier1_hours, 2nd ->
    # risk_lockout_tier2_hours, 3rd and every one after that (within the
    # same window) -> risk_lockout_tier3_hours (the cap -- it repeats, it
    # never stops enforcing). The whole streak resets to zero once
    # risk_lockout_window_hours have passed since the FIRST offense in it,
    # regardless of how many escalations happened inside that window.
    # Checked in POST /auth/login AFTER the password is verified, never
    # before (enumeration-safety, same principle as the MFA lockout).
    # Redis-backed (`ztsaacm:risk_offense:{id}` / `ztsaacm:risk_lockout:{id}`),
    # best-effort/fail-open like every other auxiliary Redis mechanism here.
    # No admin "unlock" UI yet (deliberately deferred) -- the documented
    # fallback is clearing the Redis key by hand.
    risk_lockout_tier1_hours: int = 1
    risk_lockout_tier2_hours: int = 4
    risk_lockout_tier3_hours: int = 7  # the cap -- every offense after the 2nd also gets this
    risk_lockout_window_hours: int = 24

    # ---- Real Passive Network Detection (Module 7 hardening -- Section 18 of
    # MASTER_PROJECT_CONTEXT.docx, FINALIZED 2026-09-14, implemented
    # 2026-09-15) ----
    # Everything above this point in Module 7 only ever *reacts* to an event
    # that already exists -- until now the only thing that ever created one
    # was an admin manually calling POST /security/events. This section is
    # what actually detects real mid-session network/device change from a
    # genuine user's own traffic and feeds it into that same, unchanged
    # pipeline. See app.services.trust_score.heartbeat for the mechanism.
    #
    # Deliberately a SECOND, INDEPENDENT channel from the WebSocket's own
    # ping (session_ws_heartbeat_seconds above): the session IS the WS
    # connection (Module 3) -- its real IP/User-Agent are read exactly once,
    # at that socket's handshake, and cannot change again on that same
    # connection without the connection itself dropping. A plain HTTP
    # request, by contrast, carries the browser's real, current IP/UA every
    # single time it's made -- so the frontend polls a small authenticated
    # endpoint on its own timer while a session is open. Env-configurable,
    # not hardcoded, per this project's standing convention for every timing
    # value (matches session_ws_heartbeat_seconds's own default of 20s).
    heartbeat_interval_seconds: int = 20
    # Pure safety-net TTL on the per-session "last observed" IP/UA state
    # (Redis-backed -- see app.services.trust_score.heartbeat). The
    # AUTHORITATIVE clear happens the instant the session actually ends,
    # via the same session_closed hook Module 4's ACL layer already uses
    # (app.services.acl.wiring) -- this TTL only guards against that hook
    # somehow not firing (a crash, a missed close). The request-rate
    # counter below (app.services.trust_score.request_rate) is a separate,
    # fixed-window key with its own TTL (request_rate_window_seconds) --
    # not governed by this setting -- but is cleared by that same
    # session_closed hook too.
    heartbeat_state_ttl_seconds: int = 3600
    # abnormal_request_rate (redesigned 2026-09-15, same day as the initial
    # heartbeat-only implementation): a rolling, fixed-window Redis counter
    # (same INCR + EXPIRE-if-new pattern as the Module 5 failed-login burst
    # counter -- app.services.trust_score.store), incremented once per
    # non-GET/HEAD/OPTIONS authenticated REST call anywhere in the app --
    # via app.api.deps.get_current_user -- and attributed to the caller's
    # own current session (app.services.trust_score.request_rate). Crossing
    # request_rate_threshold such calls within request_rate_window_seconds
    # fires the event exactly once per crossing (not on every call past
    # it). This is Option A of the two options Section 18 left open
    # (instrument every authenticated call, not just the heartbeat
    # endpoint) with reads excluded, so an admin's own dashboard polling
    # never counts against their own session -- see request_rate.py's own
    # docstring for the full reasoning. Default threshold is well above the
    # steady-state rate normal use of the dashboard would ever produce, so
    # normal use never trips it.
    request_rate_window_seconds: int = 60
    request_rate_threshold: int = 20

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
