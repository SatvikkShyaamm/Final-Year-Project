# Architecture Notes

This file is a short pointer, not a duplicate of the full context. The
authoritative project context lives in the Claude project's docs
(`MASTER PROJECT CONTEXT.docx`, `Project status.md`) and `Base Paper.pdf`
(Chang & Xu, "Design and Implementation of a Zero Trust Access Control
Model Driven by Session Lifecycle") — read those before making
architectural changes.

## One-paragraph summary

The base paper's ZTSAACM binds network-layer ACL permission to the
liveness of an application-layer WebSocket session via a 4-state FSM
(S0 denied → S1 authenticated → S2 authorized/ACL-active → S3
revocation-in-progress → back to S1), split into a control plane
(SS-PDP: JWT verification + FSM + task producer), an intermediate layer
(Redis: task queue + pub/sub receipts + logs), and a data plane (L-PEP:
`ipset add`/`del` executor). Our extension computes a **static Trust
Score** at login (Module 5), an **Adaptive MFA** policy that gates access
on the score's risk band (Module 6), and Continuous Trust Evaluation that
keeps recalculating the score during S2 and can force the same S2→S3
revocation path the base paper already defines (Module 7) — it does not
invent a new FSM state.

**Where the gate sits (Modules 5 + 6).** The trust score is evaluated at
`POST /auth/login`, before any session exists (Section 4/13 of the Master
Context: JWT → trust score → risk decision → *then* WebSocket). Module 6's
decision on the risk band: LOW → a real access token; MEDIUM → an
`mfa_pending` token to complete at `POST /mfa/verify`; HIGH → HTTP 403.
The WebSocket handshake only accepts a real access token, so a
MEDIUM/HIGH login simply cannot reach `create_session` until MFA is
passed — the FSM S1→S2 code itself is unchanged. Module 5's
`session_opened` hook still runs and persists the score onto the
`sessions` row (a re-evaluation moments later; normally identical). So:
Module 5 = "what is the score", Module 6 = "what do we do about it",
Module 3 stays purely session-lifecycle.

## Mapping paper concepts -> this codebase

| Paper concept        | This codebase (from the module that implements it)         |
|-----------------------|--------------------------------------------------------------|
| SS-PDP                | `backend/app/ws/` + `app/api/v1/endpoints/sessions.py` (M3) + `app/api` auth (M2) + `app/services/acl/service.py` task producer (M4) |
| L-PEP                 | `app/services/acl/worker.py` (in-process) / `app/lpep/` (standalone) + `infra/l-pep/` + `app/services/acl/enforcer.py` (ipset vs simulated) (Module 4) |
| Intermediate layer     | Redis — session active-set + `ztsaacm:events:session` (M3); ACL task queue `ztsaacm:acl:tasks` + ref-counts + receipts + `ztsaacm:events:acl` (M4). Postgres stays source of truth for both |
| FSM S0->S1 (`auth_success`) | Module 2 (Authentication) — plus, from Module 6, the risk gate on `POST /auth/login`: LOW → access token, MEDIUM → `mfa_pending` token (complete at `/mfa/verify`), HIGH → 403 |
| FSM S1->S2 (`session_open`) | Module 3 — WebSocket connect creates the `sessions` row; the `session_opened` hook fires Module 4's `request_acl_for_session` **and** Module 5's `evaluate_for_session` (persist the static score). The MEDIUM/HIGH gate is upstream at login, so this code is unconditional |
| FSM S2->S3 (`session_close`)| Module 3 — `terminate_session` (ws drop / logout / admin / idle+lifetime sweep); the `session_closed` hook fires Module 4's `remove_acl_for_session`. Additionally triggered by Module 7 on unacceptable risk |
| Trust Score            | `backend/app/services/trust_score/` (Module 5) — `evaluator.py` implements the finalized Section-6 formula `clamp(70 + Σ+ - Σ-, 0, 100)`; config-driven weights; `sessions.trust_score`/`risk_level` + `trust_score_factors` audit rows; Redis `ztsaacm:failed_logins:{user_id}` (15-min TTL) fed from `POST /auth/login` failures. `evaluate_login()` is the login-time (non-persisting) entry point Module 6 calls |
| Adaptive MFA            | `backend/app/services/mfa/` (Module 6) — `decide(risk_level)` (LOW/MEDIUM/HIGH → allow/mfa/block) + email one-time-code challenge lifecycle (`mfa_challenges` one row per prompt: create / verify / expiry / retry — code hashed, never stored plaintext). `mfa_pending` token type (`app/core/security.create_mfa_token`) is rejected by `decode_access_token`. Redis `ztsaacm:events:mfa` for the dashboard, plus (2026-09-13) `ztsaacm:mfa_failed:{id}`/`ztsaacm:mfa_lockout:{id}` for the account-level lockout |
| Continuous evaluation   | `backend/app/services/trust_score/continuous.py` (Module 7) -- composition of trust_score + mfa + session services, no separate service package. `record_event()` recomputes the session's CURRENT score (not the static baseline) and carries out none / reverify (email, reusing Module 6) / revoke (`TerminationReason.RISK_REVOKED`, already wired into token revocation) |
| Security Dashboard      | `backend/app/services/dashboard/` (Module 8) -- pure aggregation over every prior module's own tables/Redis state, no new persisted state. `GET /dashboard/overview` (Section 5's stat cards), `GET /dashboard/analytics` (its charts), `GET`/`DELETE /dashboard/lockouts` (the admin unlock UI deferred from Modules 6/7), `WS /ws/dashboard` (admin-only live forwarder over the session/ACL/MFA/security Redis event channels every earlier module already publishes) |
| Attack Simulation       | `backend/app/services/simulation/` (Module 9) -- thin, admin-only dispatch over Modules 3/5/7's own real functions (`continuous.record_event`, `trust_score_service.record_failed_login_attempt`, `session_service.terminate_session`); no new scoring/revocation logic. `GET /simulate/scenarios` (the live catalogue), `POST /simulate/{scenario}` (one of Section 5's eight named scenarios against one ACTIVE session) |

## Module -> folder map (Module 1 baseline)

```
backend/app/api/v1/endpoints/   one file per module's REST surface (+ the WS route in sessions.py)
backend/app/api/deps.py          shared deps: get_db, get_current_user, get_current_admin (Module 2)
backend/app/core/security.py     password hashing + JWT primitives (Module 2)
backend/app/services/            one sub-package per module (auth/ session/ acl/ trust_score/ M5, mfa/ M6)
backend/app/services/session/hooks.py   session_opened/closed callback registry — how M4 (ACL) and M5 (trust score) react without the session layer importing them
backend/app/services/trust_score/       evaluator (Section-6 algo) + factors + history + store (Redis) + service + wiring + continuous.py (M7: mid-session re-evaluation)
backend/app/services/mfa/               email_otp.py (smtplib/Gmail wrapper) + service.py (decide + challenge lifecycle, incl. Module 7's risk_retrigger reason) — NO session hook (the gate is at login; Module 7 calls create_challenge directly)
backend/app/models/              one file per module (user session acl trust_score M5, mfa M6, security_event M7)
backend/app/ws/                  connection_manager.py + handshake auth.py (Module 3)
backend/app/lpep/                `python -m app.lpep` — standalone L-PEP worker (Module 4)
frontend/src/auth/               token store, AuthProvider, useAuth, ProtectedRoute (Module 2)
frontend/src/session/            SessionProvider, useSession (Module 3)
frontend/src/ws/socket.ts        SessionSocket signalling client (Module 3)
frontend/src/pages/admin/        one page per Module 8 dashboard section
backend/app/services/dashboard/  pure aggregation queries over Modules 2-7's own state -- no persisted state of its own, no migration (Module 8)
frontend/src/ws/dashboardSocket.ts + useDashboardSocket.ts   admin-only live "something changed" feed (Module 8) -- see its own section below
backend/app/services/simulation/ thin admin-only dispatch over Modules 3/5/7's real functions -- no scoring/revocation logic of its own, no persisted state, no migration (Module 9)
infra/l-pep/                     setup-ipset.sh + run notes for the standalone L-PEP (Module 4)
```

Status: Modules 1-7 implemented. Every login runs a trust-score risk decision;
MEDIUM logins are email-code-gated, HIGH refused. Once a session is open, a
mid-session security event can still recompute its trust score and re-trigger
the same email challenge, or revoke it outright (Module 7). The SS-PDP's "JWT verification" is
`app/core/security.decode_access_token` (REST `get_current_user` M2 /
`app/ws/auth.resolve_ws_user` M3), and it now also rejects the `mfa_pending`
token. Session, ACL, trust-score and MFA state all live in Postgres
(authoritative); Redis is the intermediate layer — session active-set + events
(M3), ACL task queue + ref-counts + receipts + events (M4), failed-login burst
counter (M5), MFA event stream (M6).

Modules 4 and 5 both react to session lifecycle via
`app/services/session/hooks.py`, not by importing anything into the session
layer: dependency direction is `acl -> session` and `trust_score -> session`
only. Each package registers its `session_opened` hook at import time
(`app/services/acl/wiring.py`, `app/services/trust_score/wiring.py`); the ACL
and trust hooks are independent and order does not matter in Module 5 (the
trust score is informational until Module 6 gates on it).

Do not add cross-module imports that blur these boundaries (e.g. the MFA
service should not import ACL internals directly — it returns a decision;
the session/continuous-evaluation layer acts on it). This mirrors the
project's explicit instruction to keep Authentication, Authorization,
Session Management, Trust Evaluation, Adaptive MFA, and ACL Enforcement
conceptually separate.

## Module 5 — Trust Score Engine (as implemented)

Authoritative spec: Section 6 of `MASTER_PROJECT_CONTEXT.docx` ("Trust Score
Concept — FINALIZED"). The code implements it verbatim.

- **When**: once, at session creation (static/initial score). In-session
  re-scoring is Module 7. `app/services/trust_score/service.evaluate_for_session`
  is the `session_opened` hook target.
- **Formula**: `score = clamp(baseline + Σ positive − Σ negative, 0, 100)`,
  `baseline = 70` (Zero-Trust neutral-positive, not 100).
- **Factors** (`evaluator.py`; weights in `app/core/config.py`, all
  `TRUST_*` env-overridable):
  - always checked: approved-VPN CIDR `+10`, known-public-VPN CIDR `−15`
    (approved wins if an IP is in both), `≥3` failed logins in 15 min `−15`.
  - hour: `≥5` prior sessions → typical-hour range `+5`; otherwise off-hours
    (00:00–05:00 local) fallback `−5`.
  - history-dependent (only when the user has ≥1 prior session): known device
    `+15` / unknown device `−10`; known IP or same /24 (/64) `+10`; IP changed
    from last session `−10`. First-ever login skips all of these — it is
    **not** penalised for having no history, so a new user's first score is
    ≈70 = MEDIUM (a deliberate, approved "challenge every first login" result).
- **Risk bands** (feed Module 6): `≥80` LOW, `≥50` MEDIUM, else HIGH.
- **Storage**: `sessions.trust_score` (int) + `sessions.risk_level` (str)
  columns (migration `0004`); one `trust_score_factors` row per *applied*
  factor + a baseline row, so the dashboard breakdown sums exactly to the
  score. Failed-login bursts: Redis `ztsaacm:failed_logins:{user_id}`,
  `INCR` + 15-min TTL, incremented from `POST /auth/login` failures for a
  *known* username (via `trust_score.record_failed_login_attempt`, called
  from the auth endpoint — the one auth→trust_score touchpoint).
- **Known limitation** (state in the writeup): `TRUST_KNOWN_VPN_CIDRS_RAW` is
  a small static sample, not a live threat feed.
- **Read surface**: `GET /api/v1/trust-score/{session_id}` (score + factor
  breakdown, admin or owner), `/trust-score/user/{id}/history` (admin or
  self), `/trust-score/config` (the live weight table, admin).

## Module 6 — Adaptive MFA (as implemented, revised 2026-09-10)

Spec: Master Context Section 6 bands. **Method is email one-time codes, not
TOTP** — this deliberately departs from the Master Context Section 7/8 draft
(TOTP-primary + email-bootstrap-only), at the user's explicit instruction.
See Project status.md section 11 for the full history: TOTP (`pyotp`,
authenticator-app codes, QR enrolment) was implemented first, matched neither
the user's expectation nor the Section 7 draft precisely, and was removed
outright rather than patched — every MFA challenge, the first one and every
one after, is now a numeric code emailed to the address the user registered
with. Module 7's continuous re-verification will reuse this same email path
when it is built, not TOTP.

- **Where**: at `POST /auth/login`, *after* the credential check and *before*
  any session. `trust_score.evaluate_login()` gives a risk band;
  `mfa.decide(risk_level)` maps it:
  - **LOW** (`score >= 80`) → issue a normal access token.
  - **MEDIUM** (`50-79`) → create an `mfa_challenges` row, email its code to
    the user's registered address, and return `mfa_required: true` + a
    short-lived `mfa_pending` token. The client completes it at
    `POST /mfa/verify` with that code, which returns a real `Token`.
    `mfa_enabled=false` downgrades MEDIUM to allow.
  - **HIGH** (`< 50`) → HTTP 403, no token.
  There is **no "already verified before" exemption** — every login that
  lands in MEDIUM is challenged again with a brand-new code, including for a
  long-established user on a device they've used for months. A first-ever
  login has no history and always lands in MEDIUM.
- **Registration is not gated** — `POST /auth/register` returns a token
  directly. Deliberate: you created and proved the credentials in the same
  request; the risk gate is on *returning*.
- **Delivery** (`app/services/mfa/email_otp.py`, the only place `smtplib` is
  touched): Gmail SMTP (`SMTP_HOST=smtp.gmail.com`), sender credentials from
  `SMTP_USERNAME`/`SMTP_PASSWORD` (a Gmail **App Password**, not the account
  password). If SMTP isn't configured (both blank — the default, and always
  true in tests), the code is logged server-side instead
  (`delivered_via=dev_logged`) and, only in that case, optionally echoed back
  as `dev_code` (see Dev below) — a real send (`delivered_via=sent`) never
  echoes the code. A configured-but-failing send raises and the login gets
  HTTP 503 rather than handing out a challenge nobody can complete.
- **Storage** (Alembic `0007`, replacing `0005`'s TOTP tables): the
  `mfa_credentials` table (one TOTP secret per user) is dropped — an emailed
  code needs nothing durable per user, so there's nothing left to enrol or
  store between challenges. `mfa_challenges` (one row per prompt): `status`
  pending→verified/failed/expired, `attempts`/`max_attempts`, `expires_at`,
  the `trust_score`/`risk_level` that triggered it, a `reason` — `login_risk`
  / `step_up` / `risk_retrigger` for Module 7 — and now `code_hash`/
  `code_salt` (salted HMAC-SHA256 of the code, keyed on `JWT_SECRET_KEY`;
  the plaintext code is never persisted, only ever held in memory for the one
  request that generated it) plus `delivered_via`.
- **Token**: `mfa_pending` JWT type (`create_mfa_token`, carries `sub` + `cid`,
  expires with the challenge). `decode_access_token` rejects it, so it cannot
  open a session, hit `/auth/me`, or start a step-up — only `/mfa/verify`.
- **Retry / expiry**: `MFA_MAX_ATTEMPTS` wrong codes → challenge `failed`
  (403); past `MFA_CHALLENGE_TTL_MINUTES` → `expired` (403); a closed
  challenge → 409. All server-enforced on the `mfa_challenges` row. Checked
  *after* the account-level lockout below, which can short-circuit a verify
  attempt before it ever reaches this per-challenge logic (see "MFA account
  lockout hardening" section, 2026-09-13).
- **Dev**: only when SMTP isn't configured AND (`MFA_DEV_EXPOSE_CODE` or
  `ENVIRONMENT=development`), the challenge response also carries `dev_code`
  (the plaintext code) so the demo/tests need no real mailbox. Off the moment
  SMTP is configured, and off in a real deployment either way.
- **Read surface**: `POST /mfa/challenge` (step-up for an authed user; also
  Module 7's re-challenge entry point), `GET /mfa/challenge/{id}` (owner or
  admin), `GET /mfa/challenges` (admin — dashboard MFA events, now shows
  `delivery` per challenge), `GET /mfa/config` (admin — the live policy).
- **No session hook** — unlike M4/M5, the MFA gate is upstream of the session,
  so `app/services/mfa/` registers nothing on `session/hooks.py`.

## MFA account lockout hardening (Module 6, 2026-09-13)

Closes the gap noted in Project status.md and this file's own "known,
deliberately out-of-scope" observation from the Module 7 review: Master
Context Section 7 describes a Redis-backed account-level MFA lockout (3
wrong codes -> 15-minute lockout) that Module 6 never actually built — it
only ever enforced `MFA_MAX_ATTEMPTS` on the one challenge row being
verified. Now built, additively, alongside that existing mechanism rather
than replacing it.

- **Two independent limits, by design**: `MFA_MAX_ATTEMPTS` (default 5)
  closes ONE challenge after that many wrong codes on it. The new
  `MFA_LOCKOUT_THRESHOLD` (default 3) locks the WHOLE ACCOUNT out of MFA —
  `login_risk`, `step_up`, and Module 7's `risk_retrigger` alike — once that
  many wrong codes land across ANY of the user's challenges within
  `MFA_LOCKOUT_WINDOW_MINUTES` (default 15). The lockout, once tripped, lasts
  `MFA_LOCKOUT_DURATION_MINUTES` (default 15). With the stock defaults the
  account-level lockout trips first (3 wrong codes) — before a single
  challenge could ever exhaust its own 5 attempts.
- **Where the logic lives**: `backend/app/services/mfa/service.py` — two new
  Redis keys per user, best-effort like every other Redis-backed mechanism in
  this project (`ztsaacm:mfa_failed:{user_id}`, a counter with
  `MFA_LOCKOUT_WINDOW_MINUTES` TTL; `ztsaacm:mfa_lockout:{user_id}`, set only
  once the threshold trips, TTL = the remaining lockout time). `verify_challenge`
  checks the lockout key first — raising the new `MFALockedOut` exception
  before even looking at the challenge's own status — clears the failed-count
  key on a correct code, and increments it on a wrong one.
- **API**: `POST /mfa/verify` returns HTTP 429 with a `Retry-After` header and
  `{"code": "locked", "retry_after_seconds": N}` when locked out — same shape
  as the existing `expired`/`exhausted`/`closed` error codes, so the frontend
  branches on `code` the same way it already did. `GET /mfa/config` gained a
  `lockout` block (threshold/window/duration) alongside the existing
  `max_attempts`.
- **Module 7 interaction**: exactly like an exhausted or expired
  `risk_retrigger` re-verification, an account-level lockout during one also
  revokes the session it was guarding (`_revoke_retrigger_session`,
  `TerminationReason.RISK_REVOKED`) — the user still can't re-prove identity
  right now, so zero trust says the session doesn't get to keep running just
  because the *reason* they can't prove it was an account lock rather than a
  used-up challenge.
- **Tests**: `backend/tests/test_mfa.py` — the lockout trips before a single
  challenge's own `max_attempts` with stock defaults; it counts wrong codes
  across *different* challenges for the same user; a correct code resets the
  streak; it's scoped per-user (one user's wrong codes don't lock another
  user out). `backend/tests/test_continuous_trust.py` — a `risk_retrigger`
  challenge that trips the account lockout also revokes its session.

## Token revocation hardening (Module 2/3, 2026-09-10)

Closes the gap in Project status.md section 6b: ending a session used to only
end the *session row* + its ACL rule, never the JWT itself (stateless,
signature/expiry-only). A copy of the token made before termination kept
authenticating a brand-new session for the rest of its original lifetime.

- Every access token now carries a `jti` (`app.core.security.create_access_token`).
- `sessions.token_jti` / `sessions.token_exp` (Alembic `0006_add_token_revocation`,
  additive) record the `jti`/expiry of the token that opened that session —
  stamped in `create_session` from the WebSocket handshake's decoded claims
  (`app.ws.auth.resolve_ws_user`).
- `app.services.auth.revocation` is a Redis denylist keyed by `jti` (entries
  expire at the token's own `exp`, so it never grows unbounded).
  `app.services.auth.wiring` registers an `on_session_closed` hook — same
  pattern as Module 4's ACL / Module 5's trust score — that revokes the
  closing session's token, but **only** for a "terminated for cause" reason:
  `logout`, `admin_terminated`, `idle_timeout`, `max_lifetime`, or (reserved)
  `risk_revoked`. An ordinary `websocket_disconnect` (closed tab / page
  refresh) is deliberately excluded — that reopening a fresh session with the
  same still-valid token is documented, intended behaviour (see the Module 3
  section above), not the gap this fix closes.
- `get_current_user` (REST) and `resolve_ws_user` (WebSocket handshake) both
  check the denylist after decoding a token, so a revoked token can no longer
  authenticate a REST call or open a new session.
- Scoped to the *specific session's* token, not every token the user holds —
  ending one session must not sign the user out on another device.
- Frontend: `tokenStore.ts` switched from `localStorage` to `sessionStorage`
  (Project status.md section 7) — scoped per browser tab, closing the
  same-browser/multiple-tabs/multiple-accounts collision where one tab's login
  could overwrite another tab's token under the same key. Trade-off taken on
  purpose: a token no longer survives closing and reopening a tab.

## Module 7 — Continuous Trust Evaluation (as implemented)

Spec: Section 8 of `MASTER_PROJECT_CONTEXT.docx` ("converts the initial/static
Trust Score into a DYNAMIC Trust Score, recalculated during an active session
in response to security-relevant events... potentially re-triggering MFA or
revoking the session/ACL"), the Section 4/14 end-to-end demo scenario, and
Section 7's REVISED-2026-09-10 constraint that re-verification reuses the
Module 6 email mechanism, never TOTP.

- **Where the logic lives**: `backend/app/services/trust_score/continuous.py`
  — a plain submodule of the existing `trust_score` package, composing it with
  `mfa` and `session` (no new service package, per this file's own mapping
  table above). It is sync like every other service in this codebase; the
  async WebSocket push/close its result calls for is the caller's job (the
  `/security/events` endpoint, and `/mfa/verify` for the failure/success side
  of an outstanding re-verification).
- **Event catalogue** (`app.models.security_event.SecurityEventType`, six
  fixed types so Module 9's future simulation buttons have a stable target):
  `ip_change`, `vpn_detected` (classified against the same
  `trust_approved_vpn_cidrs` / `trust_known_vpn_cidrs` config lists Module 5
  checks at login, via a new public `evaluator.in_any_cidr` — no duplicated
  logic), `unknown_device`, `abnormal_request_rate`, `large_download`
  (both new, config-driven weights — `trust_weight_abnormal_request_rate`,
  `trust_weight_large_download`, default 20 each), and
  `multiple_failed_logins` (reuses Module 5's `trust_weight_failed_logins`).
  `ip_change` / `unknown_device` / `multiple_failed_logins` reuse the exact
  Module 5 `Factor` names and weights — the same signal, observed mid-session
  instead of at login.
- **Recomputation is against the session's CURRENT score, not the static
  baseline** — this is the "dynamic" part Section 8 asks for.
  `record_event()` clamps `current_score + signed_weight` to `[0, 100]`,
  reclassifies the risk band with the same `classify_risk` Module 5 uses, and
  writes both the new `sessions.trust_score`/`risk_level` *and* a
  `trust_score_factors` row (so a session's full factor history — login-time
  and every mid-session adjustment — stays in one place with the breakdown
  still summing to the current score) *and* a new, Module-7-owned
  `security_events` audit row (the event itself, the score/risk before and
  after, and the action taken — `trust_score_factors` has no column for
  that).
- **Risk-based action**, decided purely by the *new* risk band:
  - **LOW** → `none` — nothing beyond recording the event.
  - **MEDIUM** → `reverify` — `mfa_service.create_challenge(reason=risk_retrigger,
    session_id=..., ttl_minutes=settings.mfa_retrigger_ttl_minutes)` (Module
    6's exact email one-time-code path; TOTP is never reintroduced). The
    re-verification window (`MFA_RETRIGGER_TTL_MINUTES`, default 3 minutes)
    is deliberately shorter than the login-time window
    (`MFA_CHALLENGE_TTL_MINUTES`, still 5) — a session that's already active
    and just had its live trust score knocked down by a security event gets a
    tighter clock to re-prove identity than a fresh login does. Pushed down
    that session's own live WebSocket as
    `trust.reverify_required` (a full `MFAChallengeOut`, including a freshly
    minted `mfa_pending` token, so the client can complete it at the existing
    `POST /mfa/verify` unchanged). A re-verification already pending for that
    session is reused, not duplicated — one outstanding challenge per session,
    mirroring Module 6's own "no exemption, but no spam either" spirit.
  - **HIGH** → `revoke` — `session_service.terminate_session(reason=
    RISK_REVOKED)`. `RISK_REVOKED` was already a reserved constant *and*
    already included in `app.services.auth.wiring`'s revoke-on-reasons set
    since the Module 6 hardening pass, so ACL removal (Module 4's
    `session_closed` hook) and access-token revocation (Module 2/3's hook)
    both happen automatically — Module 7 only had to add the trust-score
    recompute itself, not re-wire either of those. Since 2026-09-14, a
    *direct* HIGH crossing here (only this branch, not the DeliveryFailed
    reassignment below) also trips the account-level risk lockout — see
    "Account-level risk lockout hardening (Module 7, 2026-09-14)" below.
  - A re-verification email that fails to send (`DeliveryFailed`) is *also*
    treated as `revoke`, not silently left `reverify` — fail safe, not fail
    open: if the user can't be reached to re-prove their identity, a
    MEDIUM-risk session must not keep running unchallenged.
- **Re-verification failure/expiry also revokes the session it was scoped
  to**, not just the challenge: `mfa_challenges` gained a nullable
  `session_id` (Alembic `0008`, SQLite-portable via `batch_alter_table` since
  SQLite can't ALTER-add a foreign key directly). `POST /mfa/verify` checks
  `challenge.reason == risk_retrigger` and, on `ChallengeExhausted` or
  `ChallengeExpired`, terminates `challenge.session_id` with `RISK_REVOKED`
  and closes its socket — before re-raising the same 401/403 the login flow
  already returns, so the client-facing error contract is unchanged. On
  success, it pushes `trust.reverified` down the socket (clearing the
  client's prompt) but does **not** restore the trust score — the underlying
  signal (e.g. still being on an unrecognised VPN) is still true; passing MFA
  re-proves identity, it doesn't undo the event.
- **Every action pushes something to the session's own socket, `none`
  included (2026-09-14 fix; see `Project status.md` section 20)**: an event
  that recomputes the score but stays inside the same risk band now pushes
  `trust.updated` (`session_id`, `risk_level`, the new `trust_score`).
  Before this, `record_event()` always persisted the new score to the DB —
  which is why the admin's polling Live Sessions table always showed it
  correctly — but the endpoint only pushed a WS message for
  `reverify`/`revoke`, so a session's own tab (User Portal) never learned
  about an event that stayed in-band (e.g. several small drops that never
  cross out of LOW). This message never ends the session or opens the
  reverify modal; it only keeps a client's own live number in sync with the
  admin view.
- **An unanswered re-verification is a failed one**: the existing session
  sweeper (`app.main._session_sweeper`) now also calls a new
  `mfa_service.expire_overdue_challenges()` every tick, and for any expired
  `risk_retrigger` challenge whose session is still active, revokes it the
  same way — reusing the existing background-task pattern rather than adding
  a second one.
- **Storage**: `security_events` (Alembic `0008`) — `session_id`, `user_id`,
  `event_type`, `weight_applied`, `reason`, `previous_score`/`new_score`,
  `previous_risk`/`new_risk`, `action`. Additive only; no Module 1-6 table
  altered besides the one new nullable `mfa_challenges.session_id` column.
- **Read/write surface**: `POST /security/events` (admin today; the exact
  entry point Module 9's simulation buttons will call), `GET
  /security/events` (admin, optional `session_id` filter — dashboard feed),
  `GET /security/config` (admin — live event/weight/action reference table,
  mirrors `/trust-score/config` and `/mfa/config`). `SessionRead` gained a
  computed (non-persisted) `current_action` field — `"reverify_required"`
  while a session has an open `risk_retrigger` challenge, populated the same
  way `acl_status` was in Module 4 (a batched lookup at the endpoint layer,
  `continuous.pending_reverify_map`), on all three session read endpoints and
  the Live Sessions feed.
- **WebSocket additions**: `ConnectionManager.send(session_id, message)` — the
  additive counterpart to `close()`'s pre-close send, for pushing a live
  message (`trust.reverify_required`, `trust.reverified`) to an ACTIVE
  session without ending it. `close()` itself is unchanged.
- **Frontend**: `SessionProvider` listens for `trust.reverify_required` /
  `trust.reverified` on its own signalling socket (the existing `onMessage`
  hook, previously unused) and renders a `ReverifyModal` (mirrors `Login.tsx`'s
  MFA step: code entry, retry/expiry handling, a dev-code hint) as an overlay
  over whichever page the user is on — completing it calls the unchanged
  `POST /mfa/verify`. Live Sessions gained a "Current Action" column and a
  per-row "Simulate (Module 7)" control (event-type picker + Trigger button)
  as this project's demo/testing hook for `POST /security/events` until
  Module 9 gives it dedicated buttons; Security Alerts gained a second feed
  table for `GET /security/events` alongside the existing MFA-challenges one.
  **Bug fixed 2026-09-14** (see `Project status.md` section 19): `SessionProvider`
  originally only fetched `trust_score`/`risk_level` once, at
  `onEstablished` — it received the live values on `trust.reverify_required`
  but discarded everything except the `challenge` field, so User Portal's
  own Trust/Risk display went stale the instant a Module 7 event actually
  fired, while the admin's Live Sessions table (which polls fresh) showed
  the correct current value. Fixed by applying `trust_score`/`risk_level`/
  `current_action` from that push directly, and re-fetching the session on
  `trust.reverified` (which carries no score of its own, since reverifying
  doesn't restore it) so it and the admin view agree from then on.
- **Follow-up note**: this Module 7 review originally flagged Master Context
  Section 7's Redis-backed MFA lockout (3 wrong attempts -> 15-minute
  lockout) as a pre-existing Module 6 gap, deliberately left untouched here
  to keep this module's diff scoped to continuous evaluation. It has since
  been built — see "MFA account lockout hardening (Module 6, 2026-09-13)"
  above, including how it interacts with a `risk_retrigger` re-verification.
- **Tests**: `backend/tests/test_continuous_trust.py` — event ingestion
  recomputes the score against its current value correctly; a small-impact
  event that stays LOW takes no action; a MEDIUM crossing creates exactly one
  re-verification challenge and pushes it live; a second MEDIUM event while
  one is already pending reuses it instead of spamming a new email; a
  successful re-verification keeps the session alive without restoring the
  score; an exhausted, an expired (via the sweeper), and an
  undeliverable-email re-verification all revoke the session (ACL removed,
  token revoked); a direct HIGH crossing revokes immediately; validation (
  unknown event type, unknown/terminated session) and RBAC on the new
  endpoints; `classify_event` unit tests (VPN classification, unknown type).
  Also fixed, while verifying this module: `backend/tests/conftest.py` now
  force-blanks `smtp_username`/`smtp_password` for every test (a new autouse
  fixture) — a real Gmail App Password configured in a developer's own
  `backend/.env` (Project status.md section 14) was otherwise leaking into
  the "hermetic, SMTP-never-configured" test environment every MFA/auth test
  is written against, which several tests (pre-existing, not Module 7's own)
  were silently relying on before this fix.

## Account-level risk lockout hardening (Module 7, 2026-09-14)

Closes a gap found live: testing the "Simulate (Module 7)" control against
the admin's own active session (repeated `ip_change` events, driving the
score below 50/HIGH and revoking that session — exactly the mechanism
described above) surfaced that the account could immediately log back in
with no consequence at all — `POST /auth/login`'s risk decision is computed
fresh from that attempt's own signals every time and has no memory of a
prior session having been forcibly revoked for risk.

- **Trigger, deliberately narrow**: ONLY a session revoked because
  continuous evaluation pushed its *live* score straight into HIGH (the
  direct-HIGH branch above). Explicitly does **not** count: a HIGH-risk
  *login* attempt's ordinary 403 (already blocked per-attempt, nothing to
  add), or a MEDIUM-risk reverify challenge that was failed, exhausted, got
  MFA-account-locked, expired unanswered, or failed to even send — all of
  those also end in the same `TerminationReason.RISK_REVOKED`, but the risk
  itself was only MEDIUM; the session only ended because a recoverable
  follow-up check wasn't (or couldn't be) cleared, which is not the same
  signal as an outright HIGH crossing. Enforced structurally, not by
  filtering after the fact: the call into the lockout module sits only
  inside `continuous.record_event`'s direct-HIGH branch, never inside the
  reverify-then-reassigned-to-revoke branch a few lines later.
- **Where the logic lives**: `backend/app/services/trust_score/risk_lockout.py`
  (new) — two Redis keys per user, best-effort/fail-open like every other
  auxiliary Redis mechanism in this codebase: `ztsaacm:risk_offense:{id}` (a
  counter, TTL = `RISK_LOCKOUT_WINDOW_HOURS`, set only once at the first
  offense and never renewed by later increments, so the window stays
  anchored to that first offense, not the most recent one) and
  `ztsaacm:risk_lockout:{id}` (the active lockout, TTL = the current tier's
  duration).
- **Escalating, capped, account-wide**: 1st qualifying offense →
  `RISK_LOCKOUT_TIER1_HOURS` (default 1), 2nd → `TIER2_HOURS` (default 4),
  3rd and every one after that within the same window → `TIER3_HOURS`
  (default 7 — the cap; it repeats, it never stops enforcing). Account-wide
  (keyed on `user_id`, not device/IP/User-Agent) — a risky session on one
  device locks the account out everywhere.
- **API**: checked in `POST /auth/login`, deliberately AFTER the password
  has already been verified — never before, so a wrong-password probe
  against a locked account still gets the ordinary generic 401 and can't be
  used to learn the account exists and is locked (enumeration-safety, same
  principle the Module 6 MFA lockout already follows). Returns HTTP 423
  with a `Retry-After` header and `{"code": "risk_locked",
  "retry_after_seconds": N}` when locked — same shape convention as the MFA
  lockout's 429, distinct status code so the two are never confused.
- **Frontend**: `Login.tsx`'s credentials-step catch branches on
  `code === "risk_locked"` and shows a dedicated message with the remaining
  hours, alongside its existing generic-failure handling.
- **Admin recovery — deliberately deferred**: no "locked accounts" UI in
  this pass. The documented fallback if an account (including the only
  admin account) gets stuck is clearing the Redis keys by hand:
  `redis-cli DEL ztsaacm:risk_lockout:<user_id> ztsaacm:risk_offense:<user_id>`.
  A proper unlock view is a natural fit for Module 8 (Security Dashboard)
  once it exists.
- **No migration**: purely Redis-backed, like the MFA lockout — no new
  column or table, no Alembic revision.
- **Tests**: `backend/tests/test_risk_lockout.py` (unit, against the fake
  Redis client directly) — tier escalation 1st→2nd→3rd, the cap-and-repeat
  behaviour on a 4th+ offense, the window resetting once it elapses
  (simulated by expiring the underlying counter key rather than waiting a
  real 24 hours), per-user scoping, and fail-open on a simulated Redis
  outage. `backend/tests/test_continuous_trust.py` (integration) — a direct
  HIGH crossing both revokes the session *and* returns 423 on the very next
  login attempt with the correct `Retry-After`/`retry_after_seconds` shape;
  a MEDIUM-risk reverify that was exhausted, or that failed to even send,
  does **not** trip it (the account can log back in normally right after);
  a wrong password against a locked account still gets a plain 401, never
  a hint that the account is locked; the lockout blocks a login attempt
  carrying a completely different `User-Agent`; and a second, unrelated
  account is unaffected. Full suite: **112 passing** (103 prior, per
  section 17, + 9 new). `frontend` type-checks and builds clean.

## Real Passive Network Detection (Module 7 hardening, Section 18, 2026-09-15)

Closes the one gap the rest of Module 7 above leaves open: through section
20, the *only* thing that ever created a mid-session security event was an
admin manually calling `POST /security/events` (the Live Sessions "Trigger"
control). Nothing passively watched a real user's own session and noticed,
on its own, a genuine IP/device change, a VPN, or an abnormal request rate.
See `Project status.md` section 21 for the full implementation write-up;
this is the architectural summary. **`abnormal_request_rate`'s counting
mechanism was redesigned the same day — see the dedicated bullet below and
`Project status.md` section 22 for the full write-up.**

- **Second, independent HTTP channel, not the WebSocket**: the session *is*
  the WS connection (Module 3) — its real IP/User-Agent are read exactly
  once, at handshake, and cannot change again on that connection without
  dropping it. So the frontend (`SessionProvider.tsx`) runs a small periodic
  authenticated call, `POST /security/heartbeat` (any authenticated user, no
  body — resolves the caller's own current session server-side), separate
  from the WS's own ping (`session_ws_heartbeat_seconds`). Every such HTTP
  request naturally carries the browser's real, current IP/UA.
- **Where the logic lives**: `backend/app/services/trust_score/heartbeat.py`
  (new) — compares each heartbeat's real IP/UA against a per-session
  **"last observed"** value in Redis (`heartbeat:last:{id}`, same
  fail-open convention as `store.py`/`risk_lockout.py`), **never** the
  immutable login-time baseline. The session's first heartbeat silently
  seeds this state and fires nothing; every later one fires the matching
  event on a genuine difference — `vpn_detected` (reusing Module 5's
  `evaluator.in_any_cidr` unchanged) instead of a plain `ip_change` when
  the new IP lands in either VPN CIDR list, `unknown_device` on a UA
  change, both if both changed (stopping early if one of them revokes the
  session first).
- **`abnormal_request_rate` counting (redesigned 2026-09-15, same day as
  the rest of this section)**: lives in its own module,
  `backend/app/services/trust_score/request_rate.py`, not in
  `heartbeat.py`. Section 18 left the counting *strategy* an explicit open
  choice between two options — **Option A**, a dependency incrementing a
  Redis counter on every authenticated call anywhere in the app, versus
  **Option B**, counting only heartbeat calls specifically (what this
  section originally shipped with). The design was switched to **Option A
  plus a read-exclusion refinement**: every `POST`/`PUT`/`PATCH`/`DELETE`
  authenticated call, from *any* endpoint, counts — via a single call to
  `request_rate.record_authenticated_call()` added to
  `app.api.deps.get_current_user`, the one dependency nearly every
  protected endpoint already uses — while `GET`/`HEAD`/`OPTIONS` calls
  never count at all, so an admin's own dashboard polling can never ding
  their own session. Each call is attributed to the caller's own current
  session by reusing `app.services.session.store`'s existing per-user
  Redis index (`ztsaacm:user:{user_id}:sessions`, already populated by
  `register_active`/`deregister_active`) via two new read accessors —
  **no new Redis state, no session-layer change**. The counter itself
  (`ztsaacm:reqrate:{id}`) is the same fixed-window `INCR`+`EXPIRE`-if-new
  pattern as before; a second flag key (`ztsaacm:reqrate:fired:{id}`)
  makes "fire exactly once per window" work now that counting happens from
  many call sites instead of one atomic check. `heartbeat.py`'s own role
  shrank to asking `request_rate.check_and_mark_fired(session_id)` at the
  end of each heartbeat and firing the event through the unchanged
  `continuous.record_event()` pipeline on `True` — numerically identical
  behavior to before for a pure heartbeat-only workload, since a heartbeat
  call is itself a qualifying `POST`. See `Project status.md` section 22
  for the full before/after reasoning.
- **Calls the identical, unmodified `continuous.record_event()`** every
  manual Trigger already used — Section 18's central constraint. The only
  addition either caller now passes is `source` (`SecurityEventSource.AUTO`
  from the heartbeat, `.ADMIN` from `POST /security/events`) — a new
  `security_events.source` column (Alembic `0009`, `server_default='admin'`,
  historically correct backfill), surfaced via a new `GET
  /security/events?source=auto|admin` filter and a `heartbeat` block on
  `GET /security/config`, so the audit trail can show which alerts were
  real detections versus manual demo clicks.
- **Push behavior is shared, not duplicated**: the WebSocket push/close
  logic that used to live inline in `ingest_security_event` was extracted
  into `_push_result()` and is now called by both the manual and the
  automatic path, so a real detection looks, live, identical to a manual
  admin Trigger from the affected session's own tab.
- **Redis state lifetime mirrors the ACL ref-count pattern**: `trust_score/
  wiring.py` (already registering Module 5's `session_opened` hook) now also
  registers an `on_session_closed` hook — imported lazily inside the hook
  closure to avoid pulling `continuous.py`'s `mfa`/`session` imports into
  `trust_score`'s own package `__init__` execution — that clears the
  heartbeat "last observed" key AND (via `heartbeat.clear_session_state`
  delegating to `request_rate.clear_session_state`) the request-rate
  counter and its fired-flag, the instant a session actually ends, for
  every termination path. A generous TTL remains only as a safety net.
- **Config**: `heartbeat_interval_seconds` (default 20, mirrors
  `session_ws_heartbeat_seconds`), `heartbeat_state_ttl_seconds`,
  `request_rate_window_seconds`, `request_rate_threshold` (renamed from
  `heartbeat_rate_window_seconds`/`heartbeat_rate_threshold` in the
  2026-09-15 redesign, since this is no longer heartbeat-specific) — all
  env-configurable, plus the frontend's own `VITE_HEARTBEAT_INTERVAL_SECONDS`.
- **Frontend**: `api/security.ts` gained `sendHeartbeat()`; `SessionProvider`
  gained a second effect that starts/stops a `setInterval` on
  `sessionId`, swallowing failures (a missed heartbeat is not itself
  suspicious — the existing WS ping / idle sweep already cover a genuinely
  dead connection). Any resulting push arrives on the session's existing
  socket via the handlers already built for the manual path.
- **Known, accepted limitations** (stated plainly, not hidden): a
  client-supplied IP is only trustworthy behind a trusted reverse proxy
  (pre-existing, shared with the section-16 login-time check); real IP
  changes aren't always malicious (mobile handoffs, NAT); a backgrounded tab
  throttles JS timers, so detection latency can exceed ~20s; VPN detection
  is bounded by the same static CIDR sample Section 6 already documents; a
  single-machine dev setup has no real second network to observe end to
  end (needs a live deployment or forged `X-Forwarded-For`, per Section 18).
- **Tests**: `backend/tests/test_heartbeat_detection.py` (20 tests as of
  the 2026-09-15 request-rate redesign, 17 from the original
  implementation) — silent first-heartbeat seeding; a repeated unchanged
  heartbeat firing nothing; `ip_change` with `source=auto`; VPN-CIDR
  priority over a plain `ip_change` (both known-bad and approved);
  `unknown_device`; an IP+UA change together firing both events in order;
  a revoke stopping further events in the same heartbeat; the request-rate
  counter tripping via a tight loop at exactly the threshold and not
  re-firing past it; **a non-heartbeat endpoint (repeated `DELETE`s
  against a nonexistent session) also counting toward the caller's own
  session, proving cross-endpoint attribution**; **`GET` calls never
  counting at all, even in a burst that would otherwise cross the
  threshold**; **the per-user active-session Redis index actually
  containing the session id, independent of request-rate behavior**; a
  no-active-session heartbeat as a harmless no-op; RBAC/auth; a heartbeat
  only ever touching the caller's own session; the Redis state's
  session-scoped lifetime (now `ztsaacm:reqrate:{id}` /
  `ztsaacm:reqrate:fired:{id}` in place of the old
  `ztsaacm:heartbeat:rate:{id}`); the `GET /security/events` source
  filter; the `GET /security/config` heartbeat/request_rate reference
  blocks. Full suite: **133 passing** (130 prior, per this section's
  original 17-test delivery, + 3 new for the redesign). Migration `0009`
  dry-run (upgrade/downgrade/round-trip against throwaway SQLite) clean in
  both directions — the redesign itself needs no migration (Redis/config
  only, no schema change). `frontend` type-checks (`tsc -b --noEmit`) and
  lints clean.

## Cascading account-lockout termination (Module 7 hardening, 2026-09-16)

Closes a gap in the account-level risk lockout above: that lockout (section
"Account-level risk lockout hardening" above) is a **login gate only** — it
records an offense inside `continuous.record_event`'s direct-HIGH branch and
checks it in exactly one other place, `POST /auth/login`. Nothing between
those two points ever looked at the account's *other already-open*
sessions, so a direct HIGH crossing on one device correctly blocked that
account from logging back in, while a second, already-open session on the
same account (a different browser or device, still holding a valid token)
kept running untouched for the full lockout window. Found live by testing
with the same admin account open in two browsers at once; see
`Project status.md` section 23 for the full gap writeup and the
recommendation discussion that preceded building this.

- **Trigger — identical scoping to the lockout offense itself, by
  construction**: a `direct_high_crossing` flag is set in
  `continuous.record_event()` at the same place, under the same condition
  (`new_risk == RiskLevel.HIGH`, before the later `DeliveryFailed`-reassigns-
  a-MEDIUM-reverify-to-revoke branch runs), as the pre-existing
  `risk_lockout.record_risk_offense()` call. One condition now drives two
  consequences (record the offense, and cascade-terminate), so the
  already-established "a failed/expired/undeliverable MEDIUM reverify must
  not count" distinction governs both automatically.
- **Mechanism — reuses existing code, no new query**: immediately after the
  triggering session's own `terminate_session(..., reason=RISK_REVOKED)`,
  the revoke branch also calls the pre-existing
  `session_service.terminate_user_sessions(db, user_id,
  reason=TerminationReason.ACCOUNT_LOCKED)` (previously used only by
  `/auth/logout`) to end every *other* active session on that same account.
  Call ordering matters: `terminate_session` flips the triggering session to
  `TERMINATED` synchronously before `terminate_user_sessions` runs its own
  "still ACTIVE" query, so the triggering session is naturally excluded from
  its own cascade and keeps its original `RISK_REVOKED` reason —
  `terminate_session` is idempotent, so even a hypothetical re-entry would
  be a no-op rather than overwriting it.
- **New `TerminationReason.ACCOUNT_LOCKED = "account_locked"`** —
  `termination_reason` is a free-form `String(32)` column with no DB-level
  enum, so this needed no migration.
- **Token revocation had to be extended, not just the session close** —
  found and fixed while writing the integration test:
  `app/services/auth/wiring.py`'s existing token-revocation hook only
  revokes the access token for an explicit allow-list of termination
  reasons (`_REVOKE_ON_REASONS`); `ACCOUNT_LOCKED` had to be added to it
  alongside `RISK_REVOKED`. Without this, the cascade would have closed the
  other session's row and removed its ACL while leaving its JWT valid,
  letting that browser silently reopen a new session on the same token —
  defeating the point. This is why the test asserts `GET /auth/me` on the
  cascaded session's *original* token returns 401, not only that its
  session row shows terminated.
- **Free by construction, no new push/WS code**: both the triggering and
  every cascaded session close through the identical, unmodified
  `terminate_session()` → `emit_session_closed()` path, so ACL removal
  (Module 4), the `session.closed` → `session.terminated` WebSocket push on
  each affected session's own socket, and the heartbeat/request-rate Redis
  cleanup (Module 7's own wiring) all already fire correctly with zero new
  code anywhere in that chain.
- **Frontend — zero functional change**: `LiveSessions.tsx`'s `StateBadge`
  already renders `termination_reason` as a raw string with no lookup table,
  so `account_locked` displays correctly automatically.
  `SessionProvider.tsx`'s `forceLogout()` already fires unconditionally on
  any `session.terminated` push regardless of `reason`, so the cascaded
  browser tab is correctly forced out with no code change. Both files got a
  docstring-only update.
- **Trade-off, stated plainly**: this makes the system more aggressive than
  before — a direct HIGH crossing on one device now instantly ends every
  *other* open window/device on that account too, not just the one that
  crossed. Deliberate, matching this project's account-wide (not
  device-scoped) framing of the lockout everywhere else, but worth calling
  out explicitly in a demo since it can look surprising (a second, innocent
  tab going dark) if not explained.
- **Tests**: three new integration tests in
  `backend/tests/test_continuous_trust.py` — a direct HIGH crossing on one
  of two sessions on the same account cascades the other to
  `account_locked` (session row, ACL, and original-token revocation all
  checked); a second, unrelated account's session is unaffected; a
  MEDIUM-reverify revoked only because it couldn't even be emailed
  (`DeliveryFailed`) does **not** cascade, proving the scoping matches the
  lockout offense exactly. A second per-account token is minted directly
  via `create_access_token()` rather than a real second login, to avoid
  Adaptive MFA's own risk evaluation on that call — precedented in
  `test_token_revocation.py`. Full suite: **136 passing** (133 prior, per
  the request-rate redesign above, + 3 new). No migration. `frontend`
  type-checks (`tsc -b --noEmit`) clean.

## Page-refresh reconnect reattach (Module 3/7 hardening, 2026-09-16)

Closes a Module 3 gap that became a real Module 7 security bypass: Module 3
ties a "session" 1:1 to the *liveness of one WebSocket connection* — its
`onclose` unconditionally drove S2 -> S3 -> gone, and a page refresh drops
that connection exactly the way closing the tab does (indistinguishable at
the transport level). The still-valid JWT (in `sessionStorage` specifically
so it survives a same-tab refresh) then opened a **brand-new** session,
scored fresh from Module 5's login-time baseline. Harmless for Module 3
alone; once Module 7 started accumulating meaningful in-session state — a
degrading live trust score, a pending re-verify challenge — refreshing the
page became a working way to erase both and dodge an outstanding MFA
challenge. See `Project status.md` section 24 for the full gap writeup and
the recommendation discussion that preceded building this.

- **Reattachment is scoped to the exact access token, not "this user
  reconnected recently"**: every session already stores the `jti` of the
  token that opened it (`token_jti` — see "Token revocation hardening"
  above). A page refresh presents that SAME token; a genuine new login
  always mints a fresh one at `/auth/login`. `backend/app/services/session/
  service.py`'s new `get_active_session_by_token_jti(db, token_jti)` is the
  entire lookup — at most one ACTIVE session can ever match, since a `jti`
  is unique per mint.
- **A short, dedicated grace window — deliberately not
  `session_idle_timeout_minutes`**: a new setting,
  `session_reconnect_grace_seconds` (default 5s). An ordinary WS drop no
  longer finalizes the session synchronously; `sessions.py`'s WS handler
  schedules a background `_finalize_disconnect` task (same pattern as
  `app.main`'s pre-existing `_session_sweeper`: its own short-lived
  `SessionLocal()`, since the request-scoped `db` is already gone by the
  time it runs) that sleeps the grace window, then finalizes
  (`TerminationReason.WEBSOCKET_DISCONNECT`) only if nothing reattached —
  checked via `ws_connected` plus a `last_seen_at` marker captured at the
  moment of that specific drop, so a slow, stale finalize task can't cut a
  *later* drop's own separately-scheduled grace window short after a
  reattach-then-drop-again sequence. Kept short and separate from the idle
  timeout on purpose: a tab that's actually closed should still lose its
  session/ACL in seconds, matching this project's "revoke fast" framing
  everywhere else.
- **The reattach itself**: a `jti` match reuses the existing session row
  outright (`touch_session` + `set_ws_connected(True)`, same `session_id`,
  `session.established` now carries a `reconnected: bool`) instead of
  calling `create_session`. Nothing else runs — no `emit_session_opened`, so
  Module 4's ACL is never re-created (never torn down to begin with) and
  Module 5's evaluator is never re-invoked (the CURRENT, possibly-degraded
  score/risk band is returned as-is). No match (a real new login, or the
  grace window already lapsed) falls through to `create_session` exactly as
  before this hardening pass.
- **The actual fix for the reported bypass**: on a reattach, the handler
  calls the existing `continuous.has_open_retrigger_challenge` and, if one
  is still PENDING, re-pushes `trust.reverify_required` down the newly
  attached socket — identical construction to `security.py`'s
  `_push_result` (fresh `mfa_token`, same underlying `MFAChallenge` row and
  `challenge_id`) — so the client's `ReverifyModal` reappears instead of the
  refreshed tab looking clean. One accepted, narrow exception: `dev_code`
  (the SMTP-unconfigured local/demo convenience) is never re-shown on a
  resend, only on the original push, since it's a transient attribute of the
  in-memory object `create_challenge` returns at creation time and is
  deliberately never persisted (storing a real OTP in cleartext anywhere
  would be the actual regression); the code is still visible in that
  session's server log from the first push.
- **Frontend — zero code changes**: `SessionSocket` already reconnects on
  any ordinary drop and ignores unrecognized extra fields on
  `session.established`; `SessionProvider`'s `onMessage` already applies
  `trust.reverify_required`/`trust.updated` pushes the same way regardless
  of whether they're a first push or a resend. A page refresh tears down and
  rebuilds the whole React tree anyway, so there was never any client-side
  session-identity state to reconcile.
- **Testability fix found while writing the first reattach test, not a
  feature change**: `app.core.database.SessionLocal` (used directly by
  `_finalize_disconnect`, and — this uncovered — by the pre-existing
  `_session_sweeper` too) bypasses `app.dependency_overrides` entirely,
  since that override only intercepts FastAPI's own `Depends(get_db)`
  resolution; both background paths were quietly trying to reach the real
  Postgres `database_url` in every test all along, invisible for the
  sweeper only because it wakes on a 30s timer that essentially never fires
  within one fast test (the harmless "session sweeper iteration failed" log
  line visible in verbose test output since Module 3). Fixed once, at the
  root, in `backend/tests/conftest.py`'s `client` fixture:
  `SessionLocal.configure(bind=db_engine)` reconfigures the shared
  `sessionmaker` INSTANCE in place (not a reference swap), so every module
  that already imported it is reached too — and, incidentally, makes the
  idle sweeper itself properly testable against the in-memory SQLite for the
  first time.
- **Tests**: `backend/tests/test_sessions.py` — reattach on an instant
  reconnect keeps the same `session_id` and un-resets score/risk;
  reconnecting only after the grace window genuinely lapses opens a
  brand-new session (`reconnected: false`), preserving the pre-hardening
  behaviour for a tab that's actually gone; a different token for the same
  account never reattaches regardless of timing; `GET /sessions/current`
  stays populated through the grace window and clears only once it lapses.
  `backend/tests/test_continuous_trust.py` — the direct regression test:
  force MEDIUM with a real pending challenge, disconnect, reconnect with the
  same token, and confirm both the un-reset score AND a resent
  `trust.reverify_required` with the identical `challenge_id` and a fresh
  `mfa_token` (with `dev_code` correctly null on the resend); a reattach
  with no pending challenge pushes nothing extra. Several pre-existing tests
  updated for the new timing/identity semantics they'd been incidentally
  relying on (an ordinary disconnect finalizing instantly; two sockets
  sharing one token meaning two independent sessions) — see `Project
  status.md` section 24 for the full list. Full suite: **141 passing** (136
  prior, per the cascading-lockout section above, + 5 new). No migration —
  no model/schema/column changed, the reused `token_jti` column already
  existed. `frontend` type-checks (`tsc -b --noEmit`) clean; no frontend
  file changed.

## Module 8 — Security Dashboard (as implemented, 2026-09-17)

Spec: Section 5 (the Dashboard Home / Analytics field lists), Section 9's
Module 8 description, and Section 18's own "no admin unlock UI yet --
natural fit for Module 8" deferral (Project status.md sections 17b/18).

- **Pure aggregation, no new persisted state** — `backend/app/services/dashboard/service.py`
  is read-only over Modules 2-7's own tables (`sessions`, `acl_rules`,
  `mfa_challenges`, `security_events`) plus their Redis-backed lockout keys.
  No model, no migration: Module 8 introduces zero schema of its own.
- **`GET /dashboard/overview`** (admin) — Section 5's Dashboard Home cards:
  active users/sessions, average trust score (reuses Module 5's own
  `average_trust_score`), high-risk (HIGH-band, ACTIVE) sessions, pending
  MFA requests, revoked-for-risk sessions (`risk_revoked` +
  `account_locked` specifically -- not diluted by ordinary logout/idle/admin
  terminations), current ACL rules and its avg authorization/revocation
  latency (reuses Module 4's own `average_latencies` unchanged), and a
  `locked_out_accounts` count (MFA + risk lockouts combined).
- **`GET /dashboard/analytics`** (admin) — Section 5's Analytics charts, all
  real bucketed counts, never fabricated: login activity (sessions opened
  per day -- the real, measurable proxy; a multi-day failed-login trend is
  deliberately not offered, since Module 5's failed-login counter is a
  15-minute Redis burst counter with no historical record to chart), trust
  score distribution (10-point buckets, ACTIVE sessions), risk-level
  breakdown, MFA events by status, revoked sessions by termination reason,
  security alerts by event type, plus the same ACL latency averages.
- **Admin lockout UI** (`GET`/`DELETE /dashboard/lockouts/{user_id}`) — the
  panel Sections 17b/18 explicitly deferred: lists every account currently
  under Module 6's MFA lockout or Module 7's risk lockout (SCAN over their
  small, bounded Redis key namespaces, joined with a username/email from
  Postgres) and clears both with one DELETE, wrapping the documented
  `redis-cli DEL ...` fallback in a real button. `app/services/mfa/service.list_mfa_lockouts`/
  `clear_mfa_lockout` and `app/services/trust_score/risk_lockout.list_risk_lockouts`/
  `clear_risk_lockout` are the two small additions this needed to each
  existing lockout module.
- **`WS /ws/dashboard`** (admin-only) — Section 5's "real-time updates via
  WebSocket" requirement. Forwards the Redis pub/sub channels every earlier
  module already publishes to but nothing previously consumed:
  `ztsaacm:events:session` (Module 3, `app/services/session/store.py` --
  its own docstring already said "consumed by Module 8"), `ztsaacm:events:acl`
  (Module 4), `ztsaacm:events:mfa` (Module 6), and a new
  `ztsaacm:events:security` Module 7 gained alongside this module
  (`app/services/trust_score/continuous.py`, mirroring the exact same
  publish pattern the other three already used). The handshake reuses
  `app.ws.auth.resolve_ws_user` (the same JWT/revocation check every other
  socket in this app uses) plus an admin check this one alone needs. The
  loop polls `pubsub.get_message(timeout=0)` (non-blocking) every ~0.25s
  inside the async handler rather than a background thread -- consistent
  with this codebase's existing style of sync Redis/DB calls inside async
  WS handlers (e.g. `sessions.py`'s own `session_ws`), and avoids a second
  threading model. **Purely additive, never a new source of truth**: every
  admin page keeps its existing REST polling (Modules 3-7's own pattern)
  unchanged as the real data path and fallback; a page only listens for a
  push to refetch sooner than its next poll tick
  (`frontend/src/ws/useDashboardSocket.ts`'s `tick` counter).
- **Frontend**: `DashboardHome.tsx` and `Analytics.tsx` (both placeholders
  since Module 1) are now real, reading `frontend/src/api/dashboard.ts`.
  `DashboardHome` also renders the new Locked Accounts panel with a per-row
  Unlock button. `Analytics` charts every bucket list with Recharts (already
  a dependency), reusing the same bar/line styling `TrustScorePage.tsx`
  established in Module 5.
- **Tests**: `backend/tests/test_dashboard.py` -- overview/analytics/lockouts
  RBAC; overview reflects real active-session/user/ACL state and counts a
  risk-revoked session; analytics' login-activity bucket count and shape,
  and its MFA/security-alert/revoked-session breakdowns after triggering
  each; the lockouts panel lists and clears both an MFA lockout and a risk
  lockout (confirmed by the account being immediately usable again, not just
  absent from the listing); the dashboard WebSocket rejects a non-admin and
  a missing token, and forwards a real, live `security` channel event end to
  end. Full backend suite: **153 passing** (141 prior + 12 new). `frontend`
  type-checks (`tsc -b --noEmit`) and builds clean.

## Automatic `multiple_failed_logins` detection (Module 7 hardening, 2026-09-17)

Closes the last "manual-only" gap in Module 7's event catalogue.
`multiple_failed_logins` had been modeled in `classify_event`/the weights
table since Module 7's original design, but nothing ever fired it except an
admin manually calling `POST /security/events` -- unlike every other event
type, which by this point (Section 18, the request-rate redesign, and the
cascading-lockout/reattach hardening above) also had a real, automatic
detector behind it. Found while explaining to the project owner how to
verify this alert: the honest answer was "you currently can't, except by
clicking the manual Trigger yourself" -- a real attacker guessing a live
user's password produced no live signal on that user's own already-open
session anywhere. See `Project status.md` section 27 for the full
gap/design discussion that preceded building this.

- **Reuses Module 5's existing burst counter as the trigger signal, adds no
  new counting logic**: `backend/app/services/trust_score/store.py`'s
  `ztsaacm:failed_logins:{user_id}` (`INCR`+`EXPIRE`, 15-minute window,
  threshold `trust_failed_login_threshold`) already existed to compute the
  Section 6 `-15` login-time penalty. This hardening reads that exact same
  counter mid-burst instead of adding a second one.
- **A new fire-once-per-window guard**, `store.check_and_mark_burst_fired()`
  -- a second Redis key, `ztsaacm:failed_logins_fired:{user_id}`, set once
  the counter is observed at/above threshold, with the counter's own
  remaining TTL. Structurally identical to `request_rate.py`'s
  `check_and_mark_fired` for `abnormal_request_rate`, and for the same
  reason: without it, every wrong password past the threshold within the
  same 15-minute window would re-fire the mid-session event again. Cleared
  alongside the counter itself by `clear_failed_logins` (unlocks/tests).
  Fail-open on any Redis error, matching every other auxiliary Redis
  mechanism in this codebase.
- **Where it hooks in**: `trust_score/service.py`'s
  `record_failed_login_attempt` (already the sole caller from
  `POST /auth/login`'s `InvalidCredentialsError` branch) now, immediately
  after incrementing the counter, checks the fire-once guard and -- on a
  fresh crossing -- calls the identical, unmodified
  `continuous.record_event(..., event_type=MULTIPLE_FAILED_LOGINS,
  source=SecurityEventSource.AUTO)` against **every** currently ACTIVE
  session on that account (`app.services.session.store
  .active_session_ids_for_user`, the same per-user Redis index
  `request_rate.py` already reuses) -- not just one, since an attacker
  guessing a password has no way to know which of the account's open tabs,
  if any, to target. `continuous`/`session.store` are imported locally
  inside the function, not at module level, for the same circular-import
  reason `trust_score/__init__.py` already avoids importing `continuous.py`
  eagerly (documented in `service.py`'s own module docstring; precedented
  by `app.services.auth.wiring`'s `on_session_closed` hook).
- **`POST /auth/login` had to become `async`** (`auth.py`) so it can
  `await` the WebSocket push each returned `ContinuousEvalResult` calls
  for -- the same reason Section 16 made `verify_mfa` async. The push
  itself reuses the exact helper the manual admin path and the Section 18
  heartbeat path already share, renamed from the module-private
  `_push_result` to the importable `push_continuous_result`
  (`security.py`) purely so `auth.py` can call it too; its behavior is
  otherwise byte-for-byte unchanged.
- **A no-op, by construction, whenever there is no live target**: an
  unknown username, an account with nothing currently open anywhere, or a
  burst that hasn't yet crossed the threshold all return an empty result
  list and change nothing about the plain 401 the failed attempt still
  gets. A Redis/Postgres drift between the active-session index and the
  session's real row (closed in between) is skipped per-session rather
  than raised, so one stale entry can never turn a failed login into a 500.
- **The manual admin path is completely untouched**: `POST
  /security/events` with `event_type=multiple_failed_logins` still calls
  the same `continuous.record_event(..., source=SecurityEventSource.ADMIN)`
  it always did, unmodified -- this hardening only adds a second, automatic
  caller alongside it, exactly like Section 18 added an automatic caller
  alongside the manual Trigger without removing it.
- **Tests**: six new tests added to
  `backend/tests/test_continuous_trust.py` -- a burst against a single
  active session fires `multiple_failed_logins` with `source=auto` and the
  documented `-` weight/score change; a burst on an account with two active
  sessions (two browsers) fires it against both; the fire-once guard
  suppresses a second automatic fire for further failed attempts inside the
  same window (only the first crossing fires); a burst against an account
  with no active session anywhere is a harmless no-op (still a plain 401);
  a direct HIGH crossing via this path still cascades and account-locks
  exactly like the manual path does (reuses the existing cascading-lockout
  machinery unmodified). Plus one explicit regression test asserting the
  manual `POST /security/events` path for this same event type still works
  end to end with `source=admin`. Full suite: **159 passing** (153 prior,
  per Module 8 above, + 6 new). No migration -- no schema change, Redis/
  config only. `frontend` unaffected (no API contract change: the pushed
  WebSocket message shapes are identical regardless of which caller
  produced the `ContinuousEvalResult`).

## Module 9 — Attack Simulation (as implemented, 2026-09-18)

Spec: Section 5's eight named "Simulate ..." buttons, Section 6's "Attack
Simulation -- VPN buttons" note (two independent, self-contained buttons,
not a generic VPN toggle), Section 9's Module 9 description, and Section
15's "these should trigger the actual backend logic rather than simply
changing text on the UI" instruction.

- **No new scoring/revocation logic** -- `backend/app/services/simulation/`
  (a package; the directory already existed as an empty Module-1 scaffold,
  now filled in, matching the one-sub-package-per-module convention) is a
  thin dispatch layer over functions Modules 3/5/7 already built:
  `continuous.record_event()` for six of the eight scenarios,
  `trust_score_service.record_failed_login_attempt()` for
  `failed_login`, and `session_service.terminate_session()` for
  `session_termination`. No new model, no migration.
- **The two VPN buttons pick a real, classifiable IP automatically** --
  `pick_sample_ip()` returns the first usable host address in the first
  configured CIDR block: `trust_approved_vpn_cidrs` for "Simulate Approved
  VPN", `trust_known_vpn_cidrs` for "Simulate Unknown VPN" -- the admin
  picks a scenario, not an IP, per Section 6's own framing of these as two
  complete, self-contained buttons.
- **`ip_change` uses a fixed RFC 5737 TEST-NET-3 address**
  (`203.0.113.10`), deliberately outside both configured VPN CIDR lists, so
  it always classifies as a plain `ip_change` and never gets accidentally
  reclassified as `vpn_detected`.
- **Five scenarios (`ip_change`, `approved_vpn`, `unknown_vpn`,
  `unknown_device`, `large_download`, `abnormal_requests`) call
  `continuous.record_event()` directly**, exactly the same call the
  pre-existing manual admin Trigger (`POST /security/events`, Module 7)
  already makes -- deliberately NOT routed through the Section 18 heartbeat/
  request-rate detectors, since those compare against Redis-held "last
  observed" state a polished, always-reliable demo control cannot assume is
  seeded. Tagged `source=admin`.
- **`failed_login` reuses the REAL Section 27 detector end to end** -- calls
  `record_failed_login_attempt()` `trust_failed_login_threshold` times in a
  row against the target session's own username, exercising the identical
  Redis burst counter and fire-once guard a genuine password-guessing
  attacker would trip. This is safe to do for real here (unlike the IP/
  device scenarios) because it has no unpredictable prior-state dependency
  -- a tight loop deterministically crosses the threshold every time. Hits
  **every** currently active session on the account, not just the one
  selected in the UI (the endpoint pushes each affected session's own
  result over its own live socket); tagged `source=auto`, since it is
  genuinely running the automatic detector, not injecting a synthetic
  event.
- **`session_termination` calls `session_service.terminate_session(reason=
  ADMIN_TERMINATED)`** -- the identical call `DELETE /sessions/{id}` already
  makes, including the same pre-close WebSocket push ordering.
- **New endpoints**: `GET /simulate/scenarios` (admin -- the live
  scenario -> label catalogue, mirroring `/security/config`/`/mfa/config`'s
  "live reference" shape) and `POST /simulate/{scenario}` (admin -- runs one
  scenario against a `session_id` in the request body; replaces the
  Module-1 `501` stub).
- **Frontend**: `AttackSimulation.tsx` (a placeholder with disabled buttons
  since Module 1) is now real -- a session picker plus all eight scenario
  buttons rendered from the live catalogue, and a running "Recent results"
  table showing each run's actual score/risk/action or termination state.
  Deliberately a separate, dedicated surface from `LiveSessions.tsx`'s own
  per-row "Simulate (Module 7)" control, which stays exactly as it was (a
  quick single-event tester for any of Module 7's six event types) --
  Module 9's page is Section 5's actual eight named scenarios, including
  the VPN split and the two scenarios (`failed_login`, `session_termination`)
  the Live Sessions control doesn't offer at all.
- **Tests**: `backend/tests/test_simulation.py` (16 tests) -- RBAC on both
  endpoints, the scenario catalogue's shape, validation (unknown scenario,
  unknown/inactive session), each of the eight scenarios' real effect
  (exact score-delta assertions against the live config weights, not just a
  200 status), the VPN buttons' automatic IP selection and correct
  classification, `failed_login`'s fire-once-per-window guard and its
  hitting every active session on the account, `session_termination`'s
  real state/ACL/token effects, and one full integration check that a
  Module 9 scenario crossing into HIGH drives the exact same revoke +
  account-lockout pipeline every other trigger already does. Full backend
  suite: **175 passing** (159 prior + 16 new). `frontend` type-checks,
  builds, and lints clean.
- **A real packaging bug caught while building this**: an empty
  `app/services/simulation/__init__.py` had existed since Module 1's
  original scaffold, alongside which a first draft of this module was
  written as a flat `app/services/simulation.py` file -- Python resolves
  the package over the same-named module in that situation, so
  `app.services.simulation.UnknownScenario` (etc.) raised `AttributeError`
  at runtime despite the class genuinely existing in the file on disk.
  Caught immediately by the very first test run (not shipped); fixed by
  moving the implementation into `app/services/simulation/service.py` and
  populating the existing `__init__.py` to re-export it, matching every
  other module's own package layout.
