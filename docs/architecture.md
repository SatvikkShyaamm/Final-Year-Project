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
| Adaptive MFA            | `backend/app/services/mfa/` (Module 6) — `decide(risk_level)` (LOW/MEDIUM/HIGH → allow/mfa/block) + email one-time-code challenge lifecycle (`mfa_challenges` one row per prompt: create / verify / expiry / retry — code hashed, never stored plaintext). `mfa_pending` token type (`app/core/security.create_mfa_token`) is rejected by `decode_access_token`. Redis `ztsaacm:events:mfa` for the dashboard |
| Continuous evaluation   | `backend/app/services/trust_score/continuous.py` (Module 7) -- composition of trust_score + mfa + session services, no separate service package. `record_event()` recomputes the session's CURRENT score (not the static baseline) and carries out none / reverify (email, reusing Module 6) / revoke (`TerminationReason.RISK_REVOKED`, already wired into token revocation) |

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
  challenge → 409. All server-enforced on the `mfa_challenges` row.
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
    session_id=...)` (Module 6's exact email one-time-code path; TOTP is never
    reintroduced), pushed down that session's own live WebSocket as
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
    recompute itself, not re-wire either of those.
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
- **Known, deliberately out-of-scope observation for the write-up**: Master
  Context Section 7 also describes a Redis-backed MFA lockout (3 wrong
  attempts -> 15-minute lockout, `ztsaacm:mfa_lockout:{user_id}`) that was
  never actually built in Module 6 (it uses only the per-challenge
  `attempts`/`max_attempts` columns, default 5) — noted during Module 7's
  review as a pre-existing Module 6 gap, not touched here to keep this
  module's diff scoped to continuous evaluation.
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
