# PROJECT STATE

## 1. Current Status

Current Module: Module 10 – Testing & Evaluation (next)
Overall Project Status: Core base-paper flow complete (Modules 1-4) + static
Trust Score (Module 5) + risk-gated Adaptive MFA at login (Module 6) + a
post-Module-6 hardening pass closing the server-side token-revocation and
cross-tab storage gaps found during live testing, and Continuous Trust
Evaluation (Module 7): mid-session security events recompute a session's
LIVE trust score and can re-trigger the same email MFA or revoke the
session/ACL/token outright — hardened 2026-09-13/14 with a shorter
re-verification window, an account-level MFA lockout, and an account-level
RISK lockout; hardened 2026-09-15 with **Real Passive Network Detection**
(Section 18, sections 21-22): a periodic authenticated heartbeat now drives
`ip_change` / `vpn_detected` / `unknown_device` / `abnormal_request_rate`
events automatically from a real user's own traffic (the latter counting
every non-GET authenticated call, not just heartbeats), so Module 7 no
longer depends on an admin manually clicking "Trigger"; hardened
2026-09-16 with cascading account-lockout termination and a page-refresh
reconnect-reattach fix (sections 23-24); and hardened 2026-09-17 (section
27) with automatic `multiple_failed_logins` detection — reusing Module 5's
own failed-login burst counter to fire the identical mid-session event
against every one of an account's currently open sessions the moment a
real password-guessing burst crosses threshold, alongside (not replacing)
the manual admin Trigger. Module 8 – Security Dashboard is also complete
(section 25): real Dashboard Home/Analytics aggregates, an admin
lockout-management panel, and a live admin WebSocket feed. Module 9 –
Attack Simulation is now also complete (section 28): all eight Section-5
scenarios trigger real Module 3/5/7 backend logic, on a dedicated Attack
Simulation page.
Module 10 not started.

|         Module                         |              Status          |
|----------------------------------------|------------------------------|
| Module 1 – Project Foundation          | Completed                    |
| Module 2 – Authentication              | Completed                    |
| Module 3 – Session Lifecycle           | Completed                    |
| Module 4 – Dynamic ACL                 | Completed & independently verified |
| Module 5 – Trust Score Engine          | Completed                    |
| Module 6 – Adaptive MFA                | Completed & independently verified (MFA method revised 2026-09-10 — see section 11) |
| Module 7 – Continuous Trust Evaluation | Completed — see section 16; hardened with account-level lockouts (sections 17-18), live-display fixes (sections 19-20), Real Passive Network Detection (sections 21-22), cascading lockout termination + reconnect-reattach (sections 23-24), automatic multiple_failed_logins detection (section 27) |
| Module 8 – Security Dashboard          | Completed — see section 25   |
| Module 9 – Attack Simulation           | Completed — see section 28   |
| Module 10 – Testing & Evaluation       | Not started                  |

---

## 2. Technology Stack

- Frontend: React 19 + TypeScript, Vite, Tailwind CSS v4, React Router v7, Recharts, Axios
- Backend: Python, FastAPI, SQLAlchemy 2, Alembic
- Database: PostgreSQL 16
- Authentication: JWT (PyJWT, HS256) + bcrypt password hashing
- WebSocket: FastAPI/Starlette WebSocket — the session signalling channel (Module 3)
- Network access control: Redis task queue + L-PEP worker → ipset/iptables on Linux, or a simulated backend elsewhere (Module 4)
- Trust Score: config-driven weighted-factor engine (Module 5), static score at session creation, Redis failed-login burst counter
- Adaptive MFA: email one-time codes (Gmail SMTP, `smtplib`), risk-band gated at `POST /auth/login`, sent to every user on every MFA-required login (Module 6, method revised 2026-09-10 — see section 11; TOTP/`pyotp` removed)
- Continuous Trust Evaluation: mid-session security events recompute a session's live trust score (Module 7); MEDIUM re-triggers the same emailed one-time code, HIGH revokes the session/ACL/token immediately; events are raised either manually (admin "Trigger") or automatically by a periodic authenticated heartbeat (Section 18, 2026-09-15) that passively observes a real user's own IP/User-Agent/request-rate mid-session
- Other important technologies: Redis 7 (session active-set + events; ACL task queue + ref-counts + receipts + events; failed-login counter; MFA event stream; token-revocation denylist), Docker + Docker Compose

---

## 3. Implemented Features

### Module 1 — Project Foundation
- Repo, frontend, backend, Postgres, Redis, Docker Compose wired together.
- Real `GET /api/v1/health` (live `SELECT 1` + Redis `PING`), rendered by the
  frontend System Status page.
- All later dashboard sections exist as routes with honest placeholders /
  `501 Not Implemented` stubs.

### Module 2 — Authentication
- `users` table (Alembic migration `0001_create_users_table`): username, email,
  bcrypt hash, role (`user` / `admin`), `is_active`, `created_at`, `last_login_at`.
- `POST /api/v1/auth/register` — bcrypt-hashes the password, returns a signed
  JWT + user. The first account on an empty DB is auto-promoted to `admin`.
- `POST /api/v1/auth/login` — verifies credentials (constant-time; updates
  `last_login_at`), returns a JWT.
- `GET /api/v1/auth/me` — validates the `Authorization: Bearer` token.
- `POST /api/v1/auth/logout` — stateless (client drops the token); real
  server-side revocation is deferred to the Module 3 session lifecycle.
- `app/core/security.py` — bcrypt + JWT primitives with no FastAPI/DB deps, so
  Module 3's WebSocket handshake can reuse `decode_access_token`.
- `app/api/deps.py` — `get_current_user` / `get_current_admin`: the auth +
  authorization middleware every later module reuses.
- Frontend: real login/register screen, JWT-aware axios client (attaches the
  token, redirects to `/login` on 401), `AuthProvider` that rehydrates the
  session from a persisted token via `/auth/me`, and route guards
  (`/admin` = admin only, `/portal` = any authenticated user).
- Tests: `backend/tests/test_auth.py` (16 tests) covering register → JWT →
  authenticated user plus every rejection path.

### Module 3 — Session Lifecycle
- `sessions` table (Alembic `0002_create_sessions_table`): uuid `id`, `user_id`
  FK, ip / user-agent, `state` (`active`/`terminated`), `ws_connected`,
  `created_at`, `last_seen_at`, `terminated_at`, `termination_reason`.
- `WS /api/v1/ws/session?token=<jwt>` — the base paper's SS-PDP signalling
  channel: socket open ⇒ `create_session` (FSM S1→S2); socket close ⇒
  `terminate_session` (S2→S3). Ping/pong heartbeat; `?token=` handshake reuses
  the Module 2 JWT verification (`app/ws/auth.resolve_ws_user`).
- Termination paths, all through `services.session.terminate_session` (FSM
  authoritative, idempotent): WebSocket disconnect, `POST /auth/logout` (now
  ends the user's sessions server-side + closes the socket), admin
  `DELETE /api/v1/sessions/{id}`, and the idle / max-lifetime sweeper task in
  `app.main` lifespan.
- `GET /api/v1/sessions` (admin) — the dashboard Live Sessions feed;
  `GET /api/v1/sessions/current` — the caller's own session;
  `GET /api/v1/sessions/{id}` — admin or owner.
- `app/services/session/`: `fsm.py` (S1→S2→S3 guard), `store.py` (Redis active
  set + `ztsaacm:events:session` pub/sub, best-effort), `service.py`
  (orchestration; Postgres = source of truth). `app/ws/connection_manager.py`
  holds live sockets so the control plane can force-close them.
- Trust-score / risk / ACL columns exist in the API + table as reserved nulls
  so Modules 4/5 slot in without changing the contract.
- Frontend: `SessionSocket` client (`src/ws/socket.ts`) with capped-backoff
  reconnect on unexpected drops; `SessionProvider` opens it after login and
  tears it down on logout; a live auto-refreshing **Live Sessions** table with
  per-row Terminate; a session card + WebSocket status indicator in the portal
  and admin header. On a server-driven session end it now also drops the
  client's JWT and returns to `/login` — see the fix log in section 6.
- Tests: `backend/tests/test_sessions.py` (12 tests: WS open/close, ping/pong,
  handshake rejection, admin feed + RBAC, admin terminate, logout terminate,
  idle sweeper).

### Module 4 — Dynamic ACL Management
- `acl_rules` table (Alembic `0003_create_acl_rules_table`): uuid `id`,
  `session_id` FK (unique — one rule per session), `user_id`, `client_ip`,
  `resource`, `ipset_name`, `state` (`pending`→`active`→`removing`→`removed`,
  `failed`), `enforcement` (`ipset`/`simulated`), created/activated/removed
  timestamps, `authorization_latency_ms`, `revocation_latency_ms`,
  `removal_reason`, `last_error`.
- **Session ↔ ACL binding via hooks, not imports.** `app/services/session/hooks.py`
  is a callback registry; `create_session` / `terminate_session` `emit_*`;
  `app/services/acl/wiring.py` registers `request_acl_for_session` /
  `remove_acl_for_session` at import. Dependency direction: `acl → session` only.
  Every session termination path (ws drop / logout / admin / sweeper) funnels
  through `terminate_session`, so one hook covers all four.
- **Base paper's async task flow.** Control plane creates the rule row + LPUSHes
  a task to `ztsaacm:acl:tasks` and returns (no event-loop blocking). The L-PEP
  worker (`app/services/acl/worker.py`) BRPOPs tasks, INCR/DECRs an IP
  ref-count (`ztsaacm:acl:refcount:{ip}` — one kernel entry per IP however many
  sessions share it), calls the enforcer, updates the row to `active`/`removed`
  with a measured latency, and PUBLISHes a receipt.
- **Enforcer backends** (`app/services/acl/enforcer.py`): `IpsetEnforcer`
  (`ipset add/del -exist` on `ztsaacm_allowed` / `_v6`) or `SimulatedEnforcer`
  (allow-list mirrored in Redis). `ACL_ENFORCEMENT_BACKEND=auto` probes for a
  working `ipset` and falls back to simulated. The whole control-plane
  mechanism is real in both modes — only the final syscall differs, and the
  dashboard reports which is active.
- **L-PEP hosting**: in-process background task in `app.main` lifespan
  (`L_PEP_WORKER_ENABLED=true`, default — single-container dev/demo) **or**
  standalone `python -m app.lpep` (`app/lpep/`) on a Linux enforcement host,
  with `infra/l-pep/setup-ipset.sh` and a `docker compose --profile lpep`
  service. Same worker code either way.
- `GET /api/v1/acl/rules` + `GET /api/v1/acl/rules/{id}` + `GET /api/v1/acl/status`
  (all admin) feed the dashboard. No POST/DELETE — rules are strictly session-
  bound; terminating a session removes its rule. `SessionRead.acl_status` (the
  Module 3 reserved field) is now populated on the session endpoints.
- Frontend: `src/api/acl.ts`, `AclBadge` shared pill, a **live ACL Monitor**
  page (rules table + enforcement-plane stat strip: backend, worker, queue
  depth, active rules, avg auth/revoke latency), the Live Sessions ACL column,
  and the portal session card's ACL row — all real backend state.
- Tests: `backend/tests/test_acl.py` (13 tests: rule created on session open,
  worker activates + fills the allow-list, session close removes it,
  ref-counting across two sessions/one IP, logout + admin-terminate paths,
  admin RBAC + listing shape + status, enforcer roundtrip + auto fallback).
  Also verified the in-process `run_worker` loop end-to-end against SQLite +
  fakeredis.

### Module 5 — Trust Score Engine

Implemented against the **finalized Section 6** of `MASTER_PROJECT_CONTEXT.docx`
("Trust Score Concept — FINALIZED", approved) — verbatim, not re-derived.

- **Formula**: `score = clamp(70 + Σ positive − Σ negative, 0, 100)`, computed
  **once at session creation** (static score; Module 7 does in-session
  re-scoring). Baseline 70, not 100 (Zero-Trust neutral-positive).
- **Factor table** (`app/services/trust_score/evaluator.py`; weights in
  `app/core/config.py`, all `TRUST_*` env-overridable):
  | Factor | Weight | Applies when |
  |---|---|---|
  | baseline | +70 | always |
  | known_device | +15 | user has prior session history |
  | known_ip (exact or same /24 · /64) | +10 | user has prior session history |
  | typical_hour (login within learned range) | +5 | user has ≥5 prior sessions |
  | unknown_device | −10 | user has prior session history |
  | ip_changed (from last session) | −10 | user has prior session history |
  | approved_vpn (org CIDR allowlist) | +10 | always checked |
  | unknown_vpn (known public VPN/proxy CIDR) | −15 | always checked (approved wins if both) |
  | failed_login_burst (≥3 in 15 min) | −15 | always checked (Redis counter) |
  | off_hours (00:00–05:00 local) | −5 | fallback when typical_hour can't run (<5 prior sessions) |
- **First-ever login**: no history → history-dependent factors skipped (not
  penalised) → score ≈ 70 = MEDIUM. Deliberate, approved consequence: every
  user is challenged with MFA on first login once Module 6 exists.
- **Risk bands** (feed Module 6): ≥80 LOW, ≥50 MEDIUM, else HIGH.
- **Does NOT gate S1→S2.** Module 5 only computes + stores + reports the score;
  turning MEDIUM/HIGH into allow / require-MFA / block is Module 6's job. The
  session still opens unconditionally. This keeps Module 5 from changing any
  Module 1–4 behaviour.
- **Session ↔ trust binding via the existing `session_opened` hook** (same
  registry Module 4's ACL uses — `app/services/session/hooks.py`).
  `app/services/trust_score/wiring.py` registers `evaluate_for_session`.
  Dependency direction `trust_score → session` only; the ACL and trust hooks
  are independent, order-insensitive.
- **Storage** (Alembic `0004_add_trust_score`, additive — Modules 1–4 tables
  otherwise untouched): `sessions.trust_score` (int) + `sessions.risk_level`
  (str) columns; `trust_score_factors` audit table (one row per *applied*
  factor + a baseline row, so the breakdown sums exactly to the score).
- **Failed-login counter**: Redis `ztsaacm:failed_logins:{user_id}`, `INCR` +
  15-min TTL, incremented from `POST /auth/login` failures for a *known*
  username via `record_failed_login_attempt` (called from the auth endpoint —
  the single auth→trust_score touchpoint; auth business logic is untouched).
- **Known limitation** (for the writeup): `TRUST_KNOWN_VPN_CIDRS_RAW` is a
  small static demo sample, not a live threat feed. Named as such in config,
  `.env.example`, `docs/architecture.md`, and the `/trust-score/config`
  response (`known_vpn_list_is_static_sample: true`).
- **Read surface**: `GET /api/v1/trust-score/{session_id}` (score + factor
  breakdown; admin or session owner), `/trust-score/user/{id}/history` (admin
  or self), `/trust-score/config` (live weight table + bands; admin). The
  score is also on the `session.established` WS message and the
  `SessionRead` (Live Sessions Trust/Risk columns are now real).
- **Frontend**: `src/api/trustScore.ts`; a real **Trust Score Monitoring**
  page (`/admin/trust-score`) — session picker, score meter + `RiskBadge`,
  exact per-factor breakdown table (summing to the score), per-user history
  line chart (Recharts) with the 80/50 band lines, and a collapsible live
  weight-table reference. Live Sessions Trust/Risk columns and the portal
  session card's Trust/Risk rows are wired to the real values.
- **Tests**: `backend/tests/test_trust_score.py` (12): first session = MEDIUM
  baseline, factor breakdown sums to score, 2nd session recognised as
  known-device/known-IP → LOW, failed-login burst applies −15, evaluator unit
  tests (first-time-user = exact baseline, off-hours fallback, approved vs
  known VPN CIDR, risk-band classification), config endpoint + RBAC, session
  trust-score RBAC + 404, per-user history + RBAC. Migration `0004` verified to
  produce the same schema as the ORM.

### Module 6 — Adaptive MFA

> **Superseded 2026-09-10 — see section 11.** Everything below this note
> describes the TOTP-based implementation as it was originally built and
> independently verified (section 9). At the developer's explicit request,
> TOTP was removed outright afterward and replaced with email-delivered
> one-time codes for every MFA challenge, first login and every one after —
> not a patch on top of TOTP, a full method swap. The requirements checklist,
> decision logic (Section 6 risk bands), retry/expiry rules, and endpoint
> shapes below are still accurate in spirit; every mention of TOTP,
> `pyotp`, `mfa_credentials`, enrolment/QR codes, and "confirmed credential"
> below is historical and no longer matches the code. Section 11 is the
> current, accurate description of Module 6.

Implemented against Master Context Section 6 (risk bands) + Section 7/8
(Module 6). TOTP (RFC 6238) via `pyotp`.

- **The gate is at `POST /auth/login`**, after the credential check and before
  any session — matching Section 4/13 (JWT → trust score → risk decision →
  *then* WebSocket). `trust_score.evaluate_login()` (new, non-persisting entry
  point) produces a risk band; `mfa.decide()` maps it:
  - **LOW** → normal access token (`LoginResponse.mfa_required=false`).
  - **MEDIUM** → an `mfa_challenges` row + a short-lived `mfa_pending` token;
    the client completes it at `POST /mfa/verify` (TOTP code, ±1 step skew),
    which returns a real `Token`. `MFA_ENABLED=false` downgrades MEDIUM to
    allow (HIGH still blocks) for Module 10 perf runs.
  - **HIGH** → HTTP 403, no token.
- **Every first-ever login is MEDIUM** (no history → baseline 70) → every user
  enrols an authenticator on first sign-in. Section 6 confirmed + accepted
  this.
- **Registration is NOT gated** — `POST /auth/register` still returns a token
  directly (you created + proved the credentials in the same request; the
  gate is on *returning*). Deliberate scope line — keeps Module 2's contract
  and ~50 existing tests intact.
- **`mfa_pending` token** (`app/core/security.create_mfa_token`, type
  `mfa_pending`, carries `sub`+`cid`, expires with the challenge):
  `decode_access_token` rejects it, so it can't open a session, hit
  `/auth/me`, or start a step-up — only `/mfa/verify`.
- **Storage** (Alembic `0005_add_mfa`, additive — Modules 1-5 tables
  untouched): `mfa_credentials` (one TOTP secret per user; `confirmed` flips
  true on first successful verify, and the enrolment payload — secret +
  `otpauth://` URI — is only returned until then); `mfa_challenges` (status
  pending→verified/failed/expired, `attempts`/`max_attempts`, `expires_at`,
  the triggering `trust_score`/`risk_level`, and a `reason`: `login_risk` /
  `step_up` / `risk_retrigger` reserved for Module 7).
- **Retry / expiry / success-failure**, all server-enforced on the row:
  `MFA_MAX_ATTEMPTS` (5) wrong codes → `failed` → 403; past
  `MFA_CHALLENGE_TTL_MINUTES` (5) → `expired` → 403; a closed challenge → 409;
  a good code → `verified`, credential confirmed, real token issued.
- **Dev convenience**: when `ENVIRONMENT=development` (or
  `MFA_DEV_EXPOSE_CODE=true`) the challenge response carries `dev_code` — the
  currently-valid TOTP code — so demos/tests work without a phone. Off in
  production; documented in config / `.env.example` / architecture.md.
- **No session hook** (unlike M4/M5): the gate is upstream of the session, so
  `app/services/mfa/` registers nothing on `session/hooks.py`.
- **Endpoints**: `POST /mfa/verify`, `POST /mfa/challenge` (step-up for an
  authed user — Module 7's re-challenge entry point), `GET /mfa/challenge/{id}`
  (owner or admin), `GET /mfa/challenges` (admin — dashboard feed),
  `GET /mfa/config` (admin — live policy).
- **Frontend**: `Login.tsx` is now a two-step form (credentials → MFA step:
  authenticator key + `otpauth://` URI + 6-digit code, retry/expiry handling,
  dev-code hint); `AuthContext.login()` returns a `LoginOutcome` discriminated
  union and gains `verifyMfa()`; `api/mfa.ts`; **Security Alerts** page
  (`/admin/alerts`) is now a real MFA events feed (triggered / verified /
  failed / expired + counts).
- **Integration check**: opening a session / ACL rule / trust score is
  unchanged — all Module 1-5 tests still pass. Only `test_auth.py`'s two
  login-success tests needed a helper to complete the MFA step; every other
  test uses a *registration* token (ungated).
- **Tests**: `backend/tests/test_mfa.py` (16): first login → MFA, verify with
  dev code → access token, LOW-risk login skips MFA, HIGH-risk login 403,
  `MFA_ENABLED=false` lets MEDIUM through, wrong-code decrement → exhaustion →
  409, expired challenge → 403, confirmed credential stops re-enrolling,
  `mfa_pending` token rejected as access + for step-up, registration not
  gated, step-up create+verify, admin-only feed, `/mfa/config`, `decide()`
  band mapping, TOTP roundtrip. Migration `0005` verified against the ORM
  schema. Full backend suite: **72 passing**. `frontend` type-checks and
  builds clean.

### Module 7 — Continuous Trust Evaluation (2026-09-13 — see section 16 for the full implementation/verification writeup)

Implemented against Section 8 of `MASTER_PROJECT_CONTEXT.docx` ("converts the
initial/static Trust Score into a DYNAMIC Trust Score, recalculated during an
active session in response to security-relevant events... potentially
re-triggering MFA or revoking the session/ACL") and Section 7's
REVISED-2026-09-10 constraint (re-verification reuses Module 6's email
one-time code, never TOTP).

- **Composition, not a new service package** — `app/services/trust_score/continuous.py`
  composes the existing trust_score + mfa + session services, per this
  project's own architectural note (`docs/architecture.md`).
- **Six event types** (`app.models.security_event.SecurityEventType`):
  `ip_change`, `vpn_detected` (classified against Module 5's own approved/
  known-bad VPN CIDR config), `unknown_device`, `abnormal_request_rate`,
  `large_download` (two new config weights), `multiple_failed_logins`.
- **Recomputes the session's CURRENT score** (not the static baseline) and
  writes a `trust_score_factors` row (audit trail) plus a new,
  Module-7-owned `security_events` row (the event + before/after score-risk +
  action taken).
- **Risk-based action**: LOW → none; MEDIUM → an emailed `risk_retrigger`
  re-verification challenge (Module 6's mechanism, reused unchanged, scoped
  to the session via a new `mfa_challenges.session_id` column), pushed live
  down that session's own WebSocket; HIGH → immediate revocation
  (`TerminationReason.RISK_REVOKED`, which was already wired into ACL removal
  and token revocation since the Module 6 hardening pass). A failed
  re-verification email send, an exhausted or expired re-verification, all
  also revoke the session — fail safe, not fail open.
- **New endpoints**: `POST /security/events` (admin; Module 9's future
  simulation buttons will call this same endpoint), `GET /security/events`,
  `GET /security/config` — all admin, all in `app/api/v1/endpoints/security.py`.
- **New `ConnectionManager.send()`**: pushes a live WebSocket message
  (`trust.reverify_required` / `trust.reverified`) without closing the
  socket — additive alongside the existing `close()`.
- **Frontend**: `SessionProvider` now handles those two message types and
  renders a `ReverifyModal` (mirrors the Login MFA step) over whichever page
  the user is on; Live Sessions gained a "Current Action" column and a
  per-row event-simulation control; Security Alerts gained a second feed
  table for the new `security_events`.
- **Tests**: `backend/tests/test_continuous_trust.py` (15 tests) — full
  none/reverify/revoke matrix, no-spam reuse of a pending challenge,
  success/exhaustion/expiry/delivery-failure re-verification outcomes, direct
  HIGH-crossing revocation, validation, RBAC, unit tests. Full backend suite:
  **98 passing** (83 prior, per section 11, + 15 new). `frontend` type-checks
  and builds clean.

Module 7 was subsequently hardened through five further passes, all recorded
in their own sections: a shorter re-verification window + account-level MFA
lockout (section 17), an account-level risk lockout (section 18), two
frontend live-score-display fixes (sections 19-20), Real Passive Network
Detection — genuine automatic event detection off real heartbeat traffic
(sections 21-22), and cascading account-lockout termination + a page-refresh
reconnect-reattach fix (sections 23-24). By the end of section 24 the full
backend suite stood at **141 passing**.

### Module 8 — Security Dashboard (2026-09-17 — see section 25 for the full implementation/verification writeup)

Implemented against Section 5 of `MASTER_PROJECT_CONTEXT.docx` (the
Dashboard Home / Analytics field lists) and Section 18's own "no admin
unlock UI yet — natural fit for Module 8" deferral (sections 17b/18 above).

- **Pure aggregation, zero new persisted state** — `app/services/dashboard/`
  reads Modules 2-7's own tables/Redis state only; no model, no migration.
- **`GET /dashboard/overview`** (admin) — active users/sessions, average
  trust score, HIGH-band active sessions, pending MFA requests, sessions
  revoked specifically for risk, current ACL rules + its avg authorization/
  revocation latency, and a combined locked-accounts count.
- **`GET /dashboard/analytics`** (admin) — login activity (sessions/day,
  real counts only — no fabricated multi-day failed-login trend, since
  Module 5's own counter has no historical record to chart), trust-score
  distribution, risk-level breakdown, MFA events by status, revoked sessions
  by reason, security alerts by event type.
- **Admin lockout panel** (`GET`/`DELETE /dashboard/lockouts/{id}`) — lists
  and clears both the Module 6 MFA lockout and the Module 7 risk lockout,
  turning their documented manual `redis-cli DEL` fallback into a real
  button.
- **`WS /ws/dashboard`** (admin-only) — forwards the session/ACL/MFA event
  channels every earlier module already publishes to, plus a new
  `ztsaacm:events:security` channel Module 7 gained alongside this module —
  Section 5's "real-time updates via WebSocket" requirement. Purely
  additive: every admin page keeps its existing REST polling as the real
  data path; a live push only makes it refetch sooner.
- **Frontend**: `DashboardHome.tsx` and `Analytics.tsx` (placeholders since
  Module 1) are now real; `DashboardHome` also renders the new Locked
  Accounts panel.
- **Tests**: `backend/tests/test_dashboard.py` (12 tests) — overview/
  analytics/lockouts RBAC, real state reflection, both lockout types listed
  and cleared, the dashboard WebSocket's admin gating and live forwarding.
  Full backend suite: **153 passing** (141 prior + 12 new). `frontend`
  type-checks and builds clean.

Module 8 was subsequently independently re-verified (section 26) and Module
7 gained one further hardening pass, automatic `multiple_failed_logins`
detection (section 27), bringing the full backend suite to **159 passing**
before Module 9 began.

### Module 9 — Attack Simulation (2026-09-18 — see section 28 for the full implementation/verification writeup)

Implemented against Section 5's eight named "Simulate ..." buttons, Section
6's "Attack Simulation — VPN buttons" note, and Section 15's "trigger the
actual backend logic" instruction.

- **No new scoring/revocation logic** — `app/services/simulation/` is a
  thin, admin-only dispatch layer over functions Modules 3/5/7 already
  built: `continuous.record_event()` (six scenarios),
  `trust_score_service.record_failed_login_attempt()` (`failed_login`), and
  `session_service.terminate_session()` (`session_termination`). No new
  model, no migration.
- **Eight scenarios**: `ip_change` (a fixed RFC 5737 documentation IP,
  outside both VPN CIDR lists), `approved_vpn` / `unknown_vpn` (each
  auto-picks a real, classifiable IP from the matching configured CIDR
  block — the admin picks a scenario, not an IP), `unknown_device`,
  `large_download`, `abnormal_requests` (all five call
  `continuous.record_event()` directly, tagged `source=admin` — the same
  call the manual Trigger already makes), `failed_login` (reuses the REAL
  Section 27 detector end to end, hitting every active session on the
  account, tagged `source=auto`), and `session_termination` (the identical
  call `DELETE /sessions/{id}` already makes).
- **New endpoints**: `GET /simulate/scenarios` (the live catalogue),
  `POST /simulate/{scenario}` (admin; replaces the Module 1 `501` stub).
- **Frontend**: `AttackSimulation.tsx` (disabled placeholder since Module 1)
  is now real — a session picker, all eight scenario buttons, and a
  "Recent results" table of actual score/risk/action or termination
  outcomes. A separate, dedicated surface from `LiveSessions.tsx`'s own
  per-row Module 7 "Simulate" control, which is unchanged.
- **A real packaging bug caught before shipping**: an empty
  `app/services/simulation/__init__.py` had existed since Module 1's
  scaffold; a first draft written as a flat `simulation.py` file collided
  with it (Python resolves the package over the same-named module),
  raising `AttributeError` on every call despite the code being correct.
  Fixed by moving the implementation into the package properly.
- **Tests**: `backend/tests/test_simulation.py` (16 tests) — RBAC,
  validation, each scenario's exact real effect, the VPN IP auto-selection,
  `failed_login`'s fire-once guard and multi-session reach, and a full
  HIGH-crossing integration check. Full backend suite: **175 passing** (159
  prior + 16 new). `frontend` type-checks, builds, and lints clean.

---

## 4. Module 3 — Live Verification & Fix Log (2026-09-07)

Module 3 was independently re-verified end-to-end (code review, full backend
test run, and a live browser walkthrough) after being marked Completed:

- Confirmed against MASTER PROJECT CONTEXT.docx's Module 3 checklist, the
  Base Paper's FSM/revocation description, and `docs/architecture.md`'s
  module boundaries — all satisfied.
- Live browser check: registered the first (admin) user, watched the
  WebSocket handshake succeed (`ws attached session=... user_id=...` in the
  backend log), and saw the row appear on the Live Sessions dashboard with a
  live-ticking duration and connected WebSocket badge.
- **Bug found and fixed**: `ConnectionManager.close()` closed a session's
  socket before the owning `session_ws()` coroutine could send the
  `session.terminated` message. Closing flips the socket's state to
  disconnected immediately, so that later send silently failed. The
  frontend's `SessionSocket` then saw an ordinary drop (indistinguishable
  from a network blip) and its reconnect-with-backoff logic opened a
  brand-new session right behind the one that was just terminated — so
  admin-terminate, the idle/lifetime sweeper, and (more rarely) logout did
  not reliably end a session from the client's perspective.
  - Fix: `ConnectionManager.close()` now accepts an optional `message` and
    sends it *before* the close frame. Updated the three callers (admin
    `DELETE /sessions/{id}`, `/auth/logout`, and the sweeper in
    `app/main.py`) to pass the correct `session.terminated` reason.
  - Verified post-fix: Terminate now correctly ends the session (no
    reconnect loop); a JWT-valid page refresh afterward correctly opens a
    *new* session, since Module 3 does not (and per `docs/architecture.md`,
    should not) gate re-entry on its own — that is Module 5/6's job once
    they exist.
  - Also bumped `pydantic` `2.11.10` → `2.12.3` in `backend/requirements.txt`
    for a Python 3.14 prebuilt wheel (the pinned 2.11.10 had none, forcing a
    failing source build on a fresh Windows/Python 3.14 dev setup).
  - Backend suite still 31/31 passing after the fix. Committed as
    `f71ad0c` ("Fix Module 3 session termination handshake") and pushed to
    `origin/main`.

Module 3 is now confirmed genuinely complete and integrated with Modules 1-2,
including the termination path. Ready to start Module 4 — Dynamic ACL
Management.

---

## 5. Module 4 — Independent Verification (2026-09-08)

Module 4 was independently re-verified against MASTER PROJECT CONTEXT.docx's
Module 4 checklist, the Base Paper's L-PEP / data-plane description, and the
actual code in the repo (commit `e8f9df4`) — not just the status doc's claims.
Method: read every backend file in the ACL path plus the session hooks it
attaches to, diffed the Module 4 commit against the prior (post-fix) Module 3
commit file-by-file, ran the full backend test suite from a clean virtualenv,
and ran the frontend TypeScript compiler.

**Requirements checklist (MASTER PROJECT CONTEXT.docx, Module 4):**

| Requirement | Verified |
|---|---|
| ACL creation | Yes — `request_acl_for_session` creates a `PENDING` `acl_rules` row + enqueues an `add` task on `session.opened` |
| ACL removal | Yes — `remove_acl_for_session` flips the row to `REMOVING` + enqueues a `remove` task on `session.closed` |
| User-to-resource access mapping | Yes — each rule carries `user_id`, `client_ip`, and `resource` (`ACL_PROTECTED_RESOURCE`) |
| Session-to-ACL binding | Yes — `session_id` is a unique FK on `acl_rules` (one rule per session), enforced at the DB level |
| Automatic ACL removal when session ends | Yes — verified for all four termination paths: WebSocket drop, logout, admin `DELETE /sessions/{id}`, and the idle/max-lifetime sweeper (all funnel through `terminate_session`, which fires the one `session_closed` hook) |
| Linux firewall integration | Yes, genuinely real — `IpsetEnforcer` shells out to `ipset add/del -exist`; `infra/l-pep/setup-ipset.sh` creates the `ztsaacm_allowed`/`_v6` sets and the iptables ACCEPT/DROP rules. `ACL_ENFORCEMENT_BACKEND=auto` probes for `ipset` and falls back to a Redis-backed `SimulatedEnforcer` when it's unavailable (e.g. this Windows dev box) — the fallback is honest (dashboard reports which backend is active), not a UI fake |
| eBPF | Correctly deferred, not attempted — matches the instruction not to block on it |
| Deliverable flow (Login → Session Created → ACL Created → Access → Session Ends → ACL Removed) | Yes — reproduced by `test_acl.py`'s `test_session_open_creates_pending_acl_rule` → `test_drain_activates_rule_and_fills_allow_list` → `test_session_close_removes_acl_rule`, all passing |

**Regression check against Modules 1-3 (nothing disturbed):**

- Diffed the Module 4 commit against the post-fix Module 3 commit
  (`f71ad0c`) file-by-file. `backend/app/services/session/service.py` has
  exactly two added lines (`emit_session_opened` / `emit_session_closed`
  calls at the end of `create_session` / `terminate_session`) — no other
  line changed. `backend/app/api/v1/endpoints/auth.py`,
  `app/api/deps.py`, `app/core/security.py`, `app/ws/connection_manager.py`,
  and `app/ws/auth.py` (the Module 2/3 auth + WS core) have **zero** diff.
- The session↔ACL coupling is one-directional and hook-based
  (`app/services/session/hooks.py` registry; `app/services/acl/wiring.py`
  registers callbacks at import time), matching the project's own
  architectural rule ("Session Management" and "ACL Enforcement" must stay
  separate concepts) and keeping `acl -> session` as the only import
  direction.
- `app/api/v1/endpoints/sessions.py` and `app/schemas/session.py` changes
  are additive only: an `acl_status` lookup added to the three session read
  endpoints, populating the field Module 3 had deliberately reserved as
  `null`. The WebSocket handshake loop, heartbeat, and termination-reason
  logic (the code fixed in the Module 3 log above) are byte-for-byte
  unchanged.
- Modules 5/6/7/9 (`trust.py`, `mfa.py`, `simulation.py`, `dashboard.py` and
  their service packages) have **zero** diff — still honest `501` stubs, no
  scope creep.
- Full backend test suite re-run from a clean virtualenv (not trusting the
  prior claim): **44/44 passing**, including all 16 `test_auth.py` and all
  12 `test_sessions.py` tests — Module 2/3 behavior is unaffected.
- Frontend: `tsc -b --noEmit` compiles with zero errors. (`vite build` itself
  failed on this machine with a rolldown native-binding error —
  `Cannot find module '@rolldown/binding-linux-x64-gnu'` — which is a
  platform/`node_modules` install mismatch in the verification environment,
  not a Module 4 code defect; a `npm install` on the actual target machine
  should resolve it. Flagging so it doesn't get missed, not because it's a
  Module 4 regression.)
- `LiveSessions.tsx` and `UserPortal.tsx` diffs are minimal and precise: the
  literal placeholder string `"— (Module 4)"` / `"—"` in the ACL column is
  replaced with `<AclBadge state={... .acl_status ?? 'none'} />`; nothing
  else in either file changed. `frontend/src/types/index.ts` only has Module
  4 types appended.
- `docs/architecture.md` was updated consistently with the actual code (SS-PDP/
  L-PEP/intermediate-layer table, FSM transition table, directory map) —
  matches what's really in the repo, not just aspirational.

**Conclusion:** Module 4 — Dynamic ACL Management is genuinely, fully
implemented per the defined requirements, with no gaps found. No regressions
were introduced to Modules 1-3; every prior test still passes and the diffs
touching shared files are minimal and additive. The core base-paper flow
(login → session → ACL created → session ends → ACL removed) is real,
backend-driven, and independently reproduced end-to-end via the test suite.

Ready to proceed to **Module 5 — Trust Score Engine** without further Module
4 work needed. One non-blocking environment note carried forward: the
`vite build` native-binding issue on this dev machine should be resolved
(`npm install` after clearing `node_modules`/`package-lock.json` if needed)
before relying on production builds locally — it did not affect `tsc`
type-checking or any backend behavior.

---

## 6. Post-Module-4 Live Testing — Deployment Issue + Auth/Session Fix (2026-09-08)

After the independent Module 4 verification above (run against a clean
SQLite + fakeredis test environment), the developer ran the real stack
against the actual Postgres/Redis dev environment for the first time and
found two more issues. Neither was visible from the test suite, which is
exactly why this live pass mattered.

### 6a. Deployment gap: migration 0003 was never applied

Symptom: `psycopg2.errors.UndefinedTable: relation "acl_rules" does not
exist` on every `/api/v1/sessions` call and on every new WebSocket session,
plus the WS session opening and then closing again within about a second,
repeatedly.

Root cause: Alembic migration `0003_create_acl_rules_table` had been
committed to the repo but never run against the developer's actual Postgres
database (`alembic upgrade head` is a manual step after pulling a module
that adds a migration — not something `uvicorn --reload` does for you).
With the table missing, `request_acl_for_session` (fired from the
`session_opened` hook) threw, which is caught and logged by
`emit_session_opened` — but it left the SQLAlchemy/Postgres transaction
aborted. The very next call on that same DB session,
`session_service.set_ws_connected(...)`, tried to commit on the poisoned
transaction and raised `InFailedSqlTransaction` — uncaught, since it sits
*outside* the `try/finally` in `session_ws` that normally calls
`terminate_session`. That uncaught exception is what actually killed the
socket each time, and because it bypassed the `finally` block, the session
row was left stuck at `state=active` with a dead socket instead of being
cleaned up — hence the pile of ~53 zombie "active" rows the developer saw
on Live Sessions afterward (each with `WEBSOCKET: closed`, `ACL: no ACL`).

Not a code defect in Module 4 — the table, model, and migration are all
correct; it simply hadn't been applied yet in this environment.

Fix: developer ran `alembic upgrade head`
(`0002_create_sessions_table -> 0003_create_acl_rules_table`) against the
real dev database and restarted the backend. Confirmed working afterward:
Live Sessions showed exactly one new session with `WEBSOCKET: connected`
and a real `active` ACL badge; ACL Monitor showed the matching rule. The
~53 pre-fix zombie rows are harmless leftover test data (no ACL rule was
ever created for them) and self-clean via the existing idle sweeper
(`session_idle_timeout_minutes = 30`).

**Process note for later modules**: remember to run `alembic upgrade head`
after pulling in any module that adds a migration, before starting the
backend — worth adding to the README/runbook as an explicit step so this
isn't rediscovered the same way next time. (Update, Module 6 verification:
`backend/Dockerfile`'s CMD now runs `alembic upgrade head` automatically
before `uvicorn` on every container start, so this specific gap can no
longer recur for docker-based runs. A bare `uvicorn` dev run outside Docker
still needs it done by hand.)

### 6b. Real gap found: session termination didn't end the client's authenticated state

While testing 6a's fix, the developer noticed that terminating a session
(or letting it idle out) and then refreshing the page silently opened a
**new** session with the same still-valid JWT, instead of returning to the
login page. Tracing this against the project's own stated principle
("Authentication" and "Session Management" must stay separate concerns)
surfaced a real, pre-existing gap that predates Module 4 — it was present
in Module 3 but only became visible now that Module 4 gives session
termination an ACL consequence worth noticing:

- `decode_access_token` (Module 2) is pure signature + expiry verification
  with no revocation check of any kind. Neither `POST /auth/logout` nor any
  session-termination path have ever invalidated the JWT itself — only the
  session row and (from Module 4) its ACL rule.
- On the frontend, `SessionSocket` already correctly distinguished a
  server-driven end (`session.terminated` — the Module 3 fix in section 4
  above made this reliable) from an ordinary drop, and stopped itself
  without reconnecting. But `SessionProvider`'s `onTerminated` handler only
  cleared local session state (`endedReason`, `session`, `sessionId`) — it
  never touched the auth layer. So the tab was left sitting on the same
  page, still "authenticated" per `AuthProvider`, with a dead socket and a
  JWT that a refresh would happily hand back to the server to open a brand
  new session behind the one that was just terminated. This defeats the
  point of terminating it.
- Notably, `tokenStore.ts` had a comment from when Module 2 was originally
  built stating the intended design: "Module 3 will additionally tie
  liveness to the WebSocket session, at which point a closed socket also
  means 'logged out.'" That wiring was never actually completed — this was
  confirmed to be an implementation gap against the original plan, not a
  new requirement.

**Fix applied** (frontend-only, four files, additive):

- `frontend/src/auth/context.ts` / `AuthProvider.tsx`: added
  `forceLogout()` to `AuthContext` — a local-only counterpart to `logout()`
  that drops the token and flips auth status to `unauthenticated` **without**
  calling `/auth/logout` (the server already knows the session ended; this
  just brings the client's state in line with it). `logout()` itself is
  unchanged and still notifies the server for the user's own "Log out"
  click.
- `frontend/src/session/SessionProvider.tsx`: its `onTerminated` handler now
  also calls `forceLogout()`. `ProtectedRoute`'s existing status check then
  redirects to `/login` on its own — no new navigation logic was needed.
- `frontend/src/auth/tokenStore.ts`: updated the stale comment to describe
  the now-actual behavior.

**Resulting behavior** (matches the developer's stated intent exactly):
- Session terminated for any server-driven reason (admin terminate,
  idle/max-lifetime sweep, and — once built — a Module 7 risk-based
  revocation) → the tab is logged out and returned to `/login`
  automatically; the same JWT can no longer silently reopen a session on
  that tab.
- A refresh **while the session is still active** is unaffected and stays
  correct: the browser tears the tab down before any message can arrive, so
  the still-valid JWT correctly reopens a fresh session on reload, exactly
  as documented in `docs/architecture.md` and the Module 3 fix log above.
  Nothing needed to change here.
- The user's own "Log out" action is unchanged (still calls `/auth/logout`
  server-side, then clears the token).

**Explicitly out of scope for this fix, flagged as separate open items:**
- This is a client-enforced UX guarantee, not a server-side one. A JWT
  copied out of the browser before termination would still authenticate a
  brand-new session for up to its remaining lifetime
  (`access_token_expire_minutes = 30`) — true today for both `logout` and
  every termination path alike. Closing that gap needs a server-side
  revocation mechanism (e.g. a Redis denylist of revoked token ids, checked
  in `decode_access_token`, entries expiring at the token's own `exp`).
  Deliberately not built now — natural to schedule alongside Module 6,
  since MFA and credential re-verification are the same neighborhood of
  concern. Not required for Module 4, and not implied by Modules 5-7's
  listed deliverables either. **FIXED 2026-09-10 — see section 10.** Module 6
  itself shipped without this (confirmed still open during the Module 6
  independent verification in section 9), and it was closed immediately
  afterward as a dedicated hardening pass: session termination now revokes
  the specific access token that opened it, server-side, for every
  "terminated for cause" reason.
- `tokenStore.ts` persists the JWT in `localStorage`, shared across all tabs
  of the same browser. With this fix, terminating one tab's session logs
  the whole browser out on its next auth check, not just that tab. Flagged
  here as a risk in the abstract; the concrete bug this produces, and its
  root cause, were pinned down the same day — see section 7 below.

**Verification:**
- Diff reviewed: 4 files touched (`context.ts`, `AuthProvider.tsx`,
  `SessionProvider.tsx`, `tokenStore.ts`), all additive — one new context
  method, one new call site, two doc-comment updates. No backend file
  touched.
- `frontend`: `tsc -b --noEmit` → 0 errors.
- `backend`: full suite re-run from the same clean virtualenv used for the
  Module 4 verification → **44/44 passing**, unchanged (expected — this fix
  doesn't touch the backend at all).
- Manual live confirmation of the actual browser flow (terminate → redirect
  to `/login`; refresh-while-active → stays on the same page) is the
  developer's next step to confirm in their running dev environment.

Modules 1-4 remain intact and independently verified; this was a targeted
fix to an auth/session integration gap the live pass uncovered, not a
Module 4 regression.

---

## 7. Cross-Tab / Cross-Account Auth Bug — Diagnosed, FIXED 2026-09-10 (see section 10)

Following the section 6b fix, the developer found the concrete case the
"out of scope" caveat in 6b had only flagged in the abstract: with an admin
logged in on one tab and a regular user logged in on another tab **of the
same browser**, terminating the user from the admin's Live Sessions view
also logged the admin out — kicked back to `/login` with the admin's own
session showing `termination_reason: websocket_disconnect`, even though
only the user's session was meant to end.

**Root cause (traced by reading `frontend/src/api/client.ts` and
`backend/app/ws/connection_manager.py`; no backend cause found — the bug is
entirely a frontend storage-scoping issue):**

- `tokenStore.ts` stores the JWT in `localStorage`. `localStorage` is scoped
  per browser **application**, per origin — not per tab, and not per
  logged-in account. Every tab of the same browser pointed at the same
  origin shares one `localStorage`, so a second login in a second tab
  silently overwrites the first tab's token under the same key.
- `api/client.ts`'s axios request interceptor calls `getToken()` fresh on
  *every* outgoing request (not cached at mount), and its response
  interceptor hard-navigates the tab to `/login` via
  `window.location.assign('/login')` on any `401`, after also calling
  `clearToken()`.
- Sequence that reproduced the bug: admin terminates the user's session
  (correct, intended action) → section 6b's fix correctly force-logs-out
  *that user's own tab*. But because both tabs shared one `localStorage`
  key, whichever tab's token happened to be the one left standing (or the
  next request racing a clear) could find `getToken()` returning a stale/
  cleared value on the *admin's* tab's next poll — triggering a `401` on an
  unrelated admin request, which the interceptor treated as "this tab's
  session is invalid," clearing the token and hard-navigating the admin's
  tab to `/login` too. That hard navigation tears down the admin's own
  WebSocket, which is what produced the misleading
  `termination_reason: websocket_disconnect` on the admin's session — the
  backend behaved correctly throughout; it simply reported, accurately,
  that the socket it saw close was a `websocket_disconnect`, because from
  the server's side that's exactly what happened, for a reason entirely
  invisible to it (a client-side token collision).

**Confirmation test — separate browser applications:** the developer then
repeated the same scenario using two independent browser applications
(admin logged in on Firefox, a different regular user logged in on Chrome)
instead of two tabs of one browser, and terminating the user from the admin
side correctly logged out only that user — the admin's Firefox session was
unaffected. This is expected and confirms the diagnosis: Firefox and Chrome
have entirely separate `localStorage` engines even for the same origin, so
there is no shared key for one account's token churn to collide with. This
is not evidence the underlying bug is fixed — it's evidence the bug is
specifically a **same-browser, multiple-tabs, multiple-accounts** scenario,
and does not occur across separate browser applications, or (by the same
reasoning) within a single tab, or across multiple tabs logged into the
*same* account.

**Status: FIXED 2026-09-10 — see section 10.** For a long time the proposed
fix (switch `tokenStore.ts` from `localStorage` to `sessionStorage`, scoped
per tab even for the same origin) sat here awaiting an explicit go-ahead,
since it also means a token no longer survives a tab being closed and
reopened — a trade-off worth consciously choosing rather than having it made
silently. It remained unapplied through the entire Module 6 build (confirmed
still open during the Module 6 independent verification in section 9). The
go-ahead was given immediately afterward and the fix was applied as part of
the same post-Module-6 hardening pass as section 6b's fix — see section 10
for the change and its verification.

**Historical workaround (no longer needed after the section 10 fix, kept
here for the record):** test multiple accounts in separate browser
applications (e.g. admin in Firefox, other accounts in Chrome) rather than
in multiple tabs of the same browser. This avoided the bug entirely while it
was still open.

**Not a Module 4 or Module 3 regression** — both root causes here
(`localStorage` scoping and the 401 hard-navigate interceptor) predate
Module 4 and were introduced in Module 2; they were simply never exercised
by a multi-account-same-browser test until now.

---

## 8. Session Hook — Poisoned-Transaction Fix (2026-09-10)

Standalone hardening fix applied before starting Module 6.

**File:** `backend/app/services/session/hooks.py` — `emit_session_opened()`
and `emit_session_closed()`.

**Change:** added `db.rollback()` as the first line inside each
`except Exception:` block, before the existing `logger.exception(...)`. No
other code or logic changed.

**Why:** when a registered `session_opened` / `session_closed` hook (Module
4's ACL wiring, Module 5's trust-score wiring) raises, the exception is
caught here so the session itself still opens/closes — but the *shared*
SQLAlchemy `Session` passed into the hook was left with an aborted
transaction. The next statement on that same `db` (e.g.
`session_service.set_ws_connected(...)` right after `create_session`
returns) then raised `InFailedSqlTransaction`, uncaught, killing the
WebSocket and bypassing the `finally` cleanup — the exact failure mode
diagnosed in section 6a (which was worked around at the time by applying
migration `0003`, not by hardening the hook). Rolling back inside the
`except` clears the poisoned transaction so a single failing hook can no
longer cascade into an unrelated failure downstream.

**Verification:** full backend suite re-run — **56/56 passing**, unchanged
(the fix only affects the error path, which no test currently exercises).
Frontend untouched.

---

## 9. Module 6 — Independent Verification (2026-09-10)

Module 6 was independently re-verified against MASTER PROJECT CONTEXT.docx's
Module 6 requirements, the Base Paper's risk-gate description, and the
actual code in the repo (commit `02b57b9`, on top of the `0005_add_mfa`
migration) — not just the status doc's own claims above. Method: connected
directly to the developer's machine, read every backend file in the
login → risk-decision → MFA path plus the trust-score entry point it calls,
diffed the Module 6 commit against the prior (post-hardening) Module 5
commit file-by-file, reinstalled backend dependencies into a clean
virtualenv and re-ran the full test suite, and ran the frontend TypeScript
compiler.

**Requirements checklist (MASTER PROJECT CONTEXT.docx, Module 6 / Section 6):**

| Requirement | Verified |
|---|---|
| Risk-gated decision at login (LOW allow / MEDIUM MFA / HIGH block) | Yes — `POST /auth/login` calls `trust_score.evaluate_login()` then `mfa.decide(risk_level)`; confirmed in `app/api/v1/endpoints/auth.py` and `app/services/mfa/service.py` |
| TOTP (RFC 6238) generation + verification | Yes — `app/services/mfa/totp.py`, a thin `pyotp` wrapper (secret generation, `otpauth://` provisioning URI, ±1-step skew verification) |
| Challenge lifecycle: create / verify / expire / retry-exhaust | Yes — `mfa_challenges` row per challenge, server-enforced `max_attempts` (403 on exhaustion), `expires_at` (403 on expiry), re-verifying a closed challenge (409) — all in `app/services/mfa/service.py` |
| `mfa_pending` token cannot be used as a real access token | Yes — `create_mfa_token` stamps `type=mfa_pending`; `decode_access_token` only accepts `type=access`, so the pending token is rejected by `get_current_user`, `/auth/me`, and `POST /mfa/challenge` (step-up) alike |
| Registration not gated (scope boundary) | Yes — `POST /auth/register` is untouched, still returns a token directly |
| Admin visibility (dashboard feed + live policy) | Yes — `GET /mfa/challenges` (admin, counts by status) and `GET /mfa/config` (admin, live decision thresholds + TOTP params) |
| Storage additive only | Yes — Alembic `0005_add_mfa` only creates `mfa_credentials` / `mfa_challenges`; no existing table altered |

**Regression check against Modules 1-5 (nothing disturbed):**

- Diffed the Module 6 commit (`02b57b9`) against the prior commit
  (`cf10e8b`, the hooks.py hardening fix) file-by-file: 17 files changed,
  1283 insertions / 60 deletions. Every backend file touched is either new
  (`app/models/mfa.py`, `app/schemas/mfa.py`, `app/services/mfa/*`,
  `backend/tests/test_mfa.py`) or a small, additive change to an existing
  one:
  - `app/api/v1/endpoints/auth.py` — the login handler now computes the
    risk decision and branches; no change to `/auth/register`, `/auth/me`,
    or `/auth/logout`.
  - `app/core/security.py` — adds `create_mfa_token` / `decode_mfa_token` /
    the `mfa_pending` type constant; `create_access_token` and
    `decode_access_token`'s existing behavior is unchanged (verified by
    reading the diff, not just the file).
  - `app/services/trust_score/service.py` / `__init__.py` — adds one new
    function, `evaluate_login` (read-only, nothing persisted); does not
    touch `evaluate_for_session`, so the Module 5 session-open scoring path
    is byte-for-byte unchanged.
  - `app/core/config.py`, `app/schemas/auth.py`, `app/models/__init__.py`
    — additive fields/registrations only.
  - `backend/tests/test_health.py` — the `/mfa/challenge` line is removed
    from the "still a 501 stub" list (correct, since it's implemented now)
    and the comment is updated; the two still-genuinely-unbuilt endpoints
    (`/dashboard/overview`, `/simulate/ip_change`) are still checked.
  - `backend/tests/test_auth.py` — a new `_login_token()` test helper
    completes the MFA step with the dev code; only the two tests that
    previously asserted on a bare `access_token` from `/auth/login` were
    updated to use it. Every rejection-path test (`test_login_unknown_user_is_401`,
    etc.) is untouched, and no assertion was weakened.
  - `app/services/session/hooks.py`'s 2-line diff between these two commits
    is the section-8 rollback fix, not Module 6 work — confirmed already
    applied and unrelated to MFA.
  - `backend/tests/test_sessions.py`, `test_acl.py`, `test_trust_score.py`
    have **zero** diff.
- `app/services/mfa/` registers no `session_opened` / `session_closed` hook
  (confirmed by reading `app/services/mfa/__init__.py` and grepping for
  hook registration) — matches the documented design that the MFA gate sits
  upstream of the session, so Module 4's ACL wiring and Module 5's
  trust-score wiring are structurally unreachable from Module 6's code.
- `app/api/v1/router.py` includes `mfa.router` alongside the existing
  Module 1-5 + 8/9 routers — additive registration, nothing reordered or
  removed.
- Full backend test suite reinstalled from scratch into a clean virtualenv
  (FastAPI/SQLAlchemy/pydantic/pyotp/fakeredis per `requirements.txt`, not
  trusting any previously-installed environment) and re-run: **72/72
  passing**, matching the status doc's claim independently. This includes
  all pre-existing Module 1-5 tests (auth, sessions, ACL, trust score)
  alongside the 16 new `test_mfa.py` tests — no prior test was deleted,
  skipped, or weakened to make the suite pass.
- Frontend: `npx tsc -b --noEmit` → 0 errors (Login.tsx's two-step flow,
  the `AuthContext`/`AuthProvider` `LoginOutcome`/`verifyMfa` additions,
  `api/mfa.ts`, and the real `SecurityAlerts.tsx` MFA feed all type-check
  cleanly). `npm run build` still fails on this dev machine with the same
  pre-existing `Cannot find module '@rolldown/binding-linux-x64-gnu'`
  native-binding error already flagged in the Module 4 verification
  (section 5) — a `node_modules` platform mismatch in the verification
  environment, not a Module 6 code defect, and not new.
- Frontend diff (`git diff` between the two commits) touches exactly 8
  files, all Module-6-shaped (`api/auth.ts`, `api/mfa.ts`, `auth/context.ts`,
  `auth/AuthProvider.tsx`, `pages/Login.tsx`, `pages/admin/SecurityAlerts.tsx`,
  `types/index.ts`, and a 1-line `Sidebar.tsx` label change) — no dashboard
  page outside the MFA/login surface was touched.

**Housekeeping note (not a Module 6 defect):** `git status` currently shows
~90 files as modified in the working tree, across files well outside
Module 6 (session, ACL, trust-score, infra scripts). Confirmed with
`git diff --ignore-all-space` (empty) and a stat of exactly
`9687 insertions(+), 9687 deletions(-)` that this is 100% line-ending churn
(LF ↔ CRLF, and in fact mixed per-file — some files' committed blobs are LF,
a few such as `sessions.py` and `tokenStore.ts` are CRLF) on this Windows
checkout — not a real content change to any file. No functional risk, but
worth normalizing (e.g. a `.gitattributes` with `* text=auto` and one clean
re-checkout, or setting `git config core.autocrlf` consistently) before
Module 7, so its diff is readable and this verification pass doesn't need to
re-prove the same thing. (Still present as of section 10's fix — the fix
commit was staged file-by-file, matching each touched file's own existing
line-ending convention exactly, precisely to avoid adding to this noise.)

**Design notes worth carrying into the write-up (not defects):**
- `evaluate_login` (used for the login-time MFA decision) and
  `evaluate_for_session` (persisted onto the session row moments later, once
  the WebSocket connects) run the identical Section-6 algorithm but as two
  independent calls at two slightly different instants. By design — the
  session doesn't exist yet at login time — but means the `trust_score`
  snapshotted onto an MFA challenge and the `trust_score` eventually stored
  on that login's session row could, in a rare edge case (e.g. an hour
  boundary crossed between the two calls), differ by a point or two. Not a
  bug; worth a one-line mention in the report if asked why the two numbers
  aren't guaranteed identical.
- `dev_code` / the TOTP secret are only exposed when `ENVIRONMENT=development`
  or `MFA_DEV_EXPOSE_CODE=true`; `.env.example` ships with
  `ENVIRONMENT=development` as the default, which is appropriate for a
  demo/student deployment but is a reminder to explicitly set
  `ENVIRONMENT=production` (or `MFA_DEV_EXPOSE_CODE=false`, already its
  default) wherever this is ever deployed for real.
- The Security Alerts "Triggered" stat counts the currently-fetched page of
  challenges (server caps `GET /mfa/challenges` at the 100 most recent),
  not a true lifetime total. Fine at current scale; would need a dedicated
  count endpoint if the challenge volume ever exceeds that.
- The section-6b JWT-revocation gap and the section-7 `localStorage` cross-tab
  issue were both still open at the time of this Module 6 verification —
  **both were closed immediately afterward, the same day, as a dedicated
  post-Module-6 hardening pass. See section 10.**

**Conclusion:** Module 6 — Adaptive MFA is genuinely, fully implemented per
the defined requirements, with no gaps found and no regressions introduced
to Modules 1-5. Every prior test still passes, the new tests exercise the
full decision/challenge/token-scope surface (not just the happy path), and
the diffs touching shared files are minimal, additive, and exactly where
the status doc above said they'd be.

Ready to proceed to **Module 7 — Continuous Trust Evaluation** without
further Module 6 work needed.

---

## 10. Post-Module-6 Hardening — Server-Side Token Revocation + Per-Tab Storage (2026-09-10)

Closes the two gaps left open at the end of section 9 (section 6b's
JWT-revocation gap and section 7's `localStorage` cross-tab collision),
applied as one combined hardening pass right after Module 6's independent
verification, before starting Module 7.

### 10a. Server-side access-token revocation (closes section 6b)

**Problem:** ending a session (logout, admin terminate, idle/max-lifetime
sweep) only ever ended the *session row* and its ACL rule. The JWT itself is
stateless (signature + expiry only) and was never invalidated, so a copy of
the token made before termination kept authenticating a brand-new session
for the rest of its original lifetime.

**Files added:**
- `backend/app/services/auth/revocation.py` — a Redis denylist keyed by the
  token's `jti`. `revoke_access_token(jti, exp)` sets `ztsaacm:revoked_tokens:{jti}`
  with a TTL equal to the token's remaining lifetime (so entries self-expire
  and the denylist never grows unbounded); `is_token_revoked(jti)` checks it.
  Best-effort like every other Redis use in this codebase (session store, ACL
  ref-counts, trust-score failed-login counter): fails open (treats a check
  as "not revoked") if Redis is unreachable, rather than locking everyone out.
- `backend/app/services/auth/wiring.py` — registers an `on_session_closed`
  hook, same pattern as Module 4's ACL wiring / Module 5's trust-score
  wiring (`acl -> session` / `trust_score -> session` one-directional import;
  this is `auth -> session`). Looks up the closing session's `token_jti` /
  `token_exp` and revokes that token — **but only** for a "terminated for
  cause" reason: `logout`, `admin_terminated`, `idle_timeout`,
  `max_lifetime`, or the reserved `risk_revoked`. An ordinary
  `websocket_disconnect` (closed tab / page refresh) is deliberately
  excluded from this list.
- `backend/alembic/versions/0006_add_token_revocation.py` — additive:
  `sessions.token_jti` (String(32), nullable) and `sessions.token_exp`
  (DateTime, nullable). No other table touched.

**Files changed (all additive):**
- `backend/app/core/security.py` — every access token now carries a `jti`
  (`uuid.uuid4().hex`), and a new `token_expiry_datetime()` helper converts a
  decoded token's numeric `exp` claim to the naive-UTC datetime convention
  the rest of the codebase uses. `decode_access_token`/`create_access_token`'s
  existing behavior is otherwise unchanged.
- `backend/app/ws/auth.py` — `resolve_ws_user` now also checks
  `is_token_revoked` (rejecting a revoked token's attempt to open a *new*
  session) and returns a small `ResolvedWsAuth(user, token_jti, token_exp)`
  instead of a bare `User`, so the caller can stamp the token's identity onto
  the session it's about to open.
- `backend/app/services/session/service.py` — `create_session` gained two
  optional keyword params, `token_jti` / `token_exp`, stored on the new
  session row. Module 3 itself has no opinion on revocation; it just carries
  the data for whoever does, matching how it already carries Module 5's
  reserved trust-score columns.
- `backend/app/api/v1/endpoints/sessions.py` — the WebSocket handshake passes
  `resolved.token_jti` / `resolved.token_exp` into `create_session`.
- `backend/app/api/deps.py` — `get_current_user` (the REST auth dependency)
  now also checks `is_token_revoked` after decoding, 401'ing a revoked token
  exactly like an expired one.
- `backend/app/services/auth/__init__.py` — imports `wiring` for its side
  effect (registers the hook), same pattern as `acl`/`trust_score`'s
  `__init__.py`, and re-exports `is_token_revoked` / `revoke_access_token`.

**A real bug caught during this fix, not shipped:** the first implementation
revoked the token on *every* session close, with no reason filter. That
immediately broke `test_get_current_session_for_caller`,
`test_second_session_is_recognised_as_known_device_and_ip`, and
`test_user_trust_history` — all of which rely on the documented, intended
behavior that a page refresh (an ordinary `websocket_disconnect`) reopens a
fresh session with the *same still-valid token*. Revoking unconditionally
would have silently broken that refresh behavior and any legitimate
multi-session use of one token. Root-caused from the failing tests and fixed
by restricting the hook to the "terminated for cause" reason list above
before this was committed — the broad version was never merged.

**Deliberately scoped narrow:** revocation targets the *specific session's*
token, not every token the user holds. Ending one session (e.g. from one
device) must not silently sign the user out of a different, still-legitimate
session on another device. A token that never opened a WebSocket session
(e.g. used only for REST calls) has no `jti` recorded on any session row and
so cannot be targeted by this mechanism — there is nothing to terminate for
it, matching the pre-existing behavior for such tokens.

### 10b. Per-tab token storage (closes section 7)

**File changed:** `frontend/src/auth/tokenStore.ts` — switched from
`localStorage` to `sessionStorage`. `sessionStorage` is scoped per tab even
for the same origin, so each tab's token is fully isolated from every other
tab's, eliminating the cross-tab collision at its source. `api/client.ts`
needed no change — it already only calls `getToken()`/`setToken()`/
`clearToken()` from `tokenStore.ts`, never touching browser storage directly.

**Trade-off taken on purpose** (the same one section 7 had been flagging for
a while before the go-ahead was given): a token no longer survives closing
and reopening a tab — a fresh login is required. Refreshing a tab is
unaffected either way; `sessionStorage` survives a same-tab reload, only a
full tab close clears it.

### Verification

- Reinstalled the backend into a clean virtualenv (not trusting anything
  already installed) and ran the full suite: **80/80 passing** — the prior
  72 plus 8 new tests in `backend/tests/test_token_revocation.py`:
  admin-terminate revokes the session's own token; logout revokes it; an
  *ordinary disconnect does NOT revoke it* and the same token can still open
  a brand-new session afterward (the regression guard for the bug caught
  above); a revoked token cannot open a new WebSocket session; terminating
  one session never revokes a different session's token (multi-device
  safety); a token that never opened a session is unaffected by an unrelated
  session ending; the idle sweeper's `idle_timeout` termination revokes its
  session's token too (unit-level, mirroring the existing sweeper test); and
  a unit-level roundtrip of `revoke_access_token`/`is_token_revoked` directly
  against the Redis denylist.
- Migration `0006` dry-run (both `upgrade head` and `downgrade -1`) against a
  throwaway SQLite database: the resulting `sessions` schema matches the ORM
  model exactly in both directions.
- Frontend: `npx tsc -b --noEmit` → 0 errors.
- Diff reviewed file-by-file before committing: 13 files, 591 insertions /
  16 deletions, nothing outside the two gaps touched. Each file was staged
  matching its own pre-existing line-ending convention (see the section 9
  housekeeping note) so this commit adds zero new line-ending noise.
- Committed locally as `2a12b9a` ("Server-side JWT revocation on session
  termination + per-tab token storage") on `main`, one commit ahead of
  `origin/main` at the time of this writing; the developer pushes it from
  their own machine.

**Conclusion:** both gaps flagged at the end of Module 6's independent
verification are now closed, verified by an expanded regression-tested
suite (72 → 80 passing) and a caught-before-shipping bug in the first draft
of the fix. Modules 1-6 remain otherwise untouched. Ready to proceed to
**Module 7 — Continuous Trust Evaluation**.

---

## 11. MFA Method Redesign — TOTP Removed, Email One-Time Codes for Every Login (2026-09-10)

Supersedes the Module 6 subsection in section 3 above (that description is
kept, annotated, for the historical record). This is a deliberate,
user-directed method swap decided *after* Module 6's own independent
verification (section 9) had already confirmed the TOTP implementation was
internally correct and gap-free against its own design — this change is not
a bug fix, it is the developer overriding the MFA method itself.

### How this came about

While testing Module 6 live, the developer observed the actual behavior
(screenshot: a "Verify it's you" MFA screen with `dev environment — current
code: NNNNNN` shown directly on the page) and raised two concerns: (1) why
does an already-used, long-established admin account get MFA-challenged
again just from switching browsers, and (2) the code being visible on the
dashboard itself looks security-weak — shouldn't a first-time login send a
code by email, with an authenticator app used only for logins after that?

Investigating this against the project's own source of truth surfaced a
real discrepancy worth recording precisely: `MASTER_PROJECT_CONTEXT.docx`
Section 7 ("ADAPTIVE MFA CONCEPT — FINALIZED," status "Finalized and
approved for implementation") specifies a **two-method hybrid** — TOTP as
the steady-state method, but a mandatory one-time email-OTP *bootstrap* the
first time a user is MFA-challenged (before they have a TOTP secret),
immediately followed by mandatory TOTP enrollment, after which TOTP is used
for every subsequent challenge. It also specifies a 3-attempt/15-minute
Redis-backed lockout (separate from Module 5's password-failure counter)
and TOTP secrets **encrypted at rest**. The developer's expectation matched
this approved spec almost exactly. The actual Module 6 implementation (as
verified in section 9) never built the email-bootstrap step, the lockout, or
secret encryption — it used TOTP from the very first challenge, with
`dev_code` (a development-only convenience, gated behind
`ENVIRONMENT=development` / `MFA_DEV_EXPOSE_CODE`) standing in for "how does
the user get their first code" instead. Section 9's own requirements
checklist did not catch this because it was checked against Section 6 (risk
bands) and the general Module 6 deliverable list, not against Section 7's
more detailed, separately-approved method spec — a real blind spot in that
verification pass, flagged here for the record.

Separately, confirmed directly from the code that TOTP was applied to
**every** MEDIUM-risk login, not just first-time ones — `mfa.decide()` looks
only at the login's own risk band, with no "already enrolled" or "already
verified before" exemption. This matches Section 7's steady-state behavior
in isolation, but not the developer's expectation once combined with the
missing email-bootstrap distinction: a switched browser (different
User-Agent → unknown-device factor → MEDIUM) on an old, trusted account
still triggers a full challenge, TOTP included, exactly as implemented.

### The developer's decision

Rather than build out the missing Section 7 pieces (email bootstrap +
mandatory TOTP enrollment + lockout + secret encryption) to bring Module 6
into line with the approved spec, the developer chose a simpler, different
design and asked for it explicitly:

1. Remove the TOTP concept entirely — from login MFA now, and explicitly
   **not** to be reintroduced for Module 7's continuous session
   re-verification either (deferred to Module 7, not built now; when Module
   7 is built, its re-challenges will reuse the same email path below, not
   TOTP).
2. Every user, every login that requires MFA, gets a one-time code emailed
   to their registered address — no authenticator app, no QR enrollment
   step, no "first login only" special case.
3. The same email-code mechanism is the intended design for Module 7's
   future continuous-session re-verification challenges too (not built yet
   — Module 7 remains "Not started" per section 1's table; this is a design
   decision recorded now so Module 7 doesn't reintroduce TOTP later).

This is itself a further, explicit deviation from the Master Context Section
7 draft (which keeps TOTP as the steady-state method) — a conscious,
developer-directed simplification, not an oversight, and recorded here as
such.

### What changed

- **Backend, `app/services/mfa/`**: `totp.py` (the `pyotp` wrapper) deleted
  outright, replaced by `email_otp.py` — the only place `smtplib` is used.
  Generates a cryptographically random numeric code (`secrets.choice`, not
  `pyotp`), hashes it for storage (salted HMAC-SHA256, keyed on
  `JWT_SECRET_KEY`, a fresh random salt per challenge — the plaintext code
  is never persisted, only ever held in memory for the one request that
  generated it), and sends it via Gmail SMTP
  (`smtp.gmail.com`, `SMTP_USERNAME`/`SMTP_PASSWORD` — a Gmail **App
  Password**, not the account password — as the sender; the recipient is
  always the address the user registered with). If SMTP isn't configured
  (both settings blank, the default — and always true in the test suite),
  the code is logged server-side instead of emailed and, only in that case,
  optionally echoed back as `dev_code` for local testing. A real send never
  echoes the code back, and a configured-but-failing send now returns
  HTTP 503 rather than silently issuing a challenge nobody can complete.
- **`app/models/mfa.py`**: `MFACredential` (the one-secret-per-user TOTP
  table) removed — an emailed code needs nothing durable per user, so there
  is nothing left to enroll or store between challenges. `MFAMethod` is now
  `EMAIL` only. `MFAChallenge` gained `code_hash`/`code_salt` (the salted
  hash described above) and `delivered_via` (`sent` / `dev_logged` /
  `failed` — visible on the admin MFA feed).
- **`app/services/mfa/service.py`**: `create_challenge` now generates and
  emails a code instead of deriving a TOTP value from a stored secret;
  `verify_challenge` checks the salted hash instead of calling
  `pyotp`. `build_challenge_out` no longer returns an `enrollment` payload
  (no more QR code / provisioning URI — there's nothing to enroll).
- **`app/schemas/mfa.py`**: `MFAEnrollmentOut` removed; `MFAChallengeOut` /
  `MFAChallengeStatusOut` gained a `delivery` field, dropped `enrollment`.
- **`app/api/v1/endpoints/mfa.py`**: `/mfa/config`'s response now describes
  the email/OTP policy (`otp_length`, whether SMTP is configured) instead of
  TOTP parameters; `/mfa/challenge` (step-up) and `/auth/login` both surface
  a delivery failure as HTTP 503.
- **`app/core/config.py`**: `mfa_totp_*` settings replaced with
  `mfa_otp_length` and Gmail SMTP settings (`smtp_host`, `smtp_port`,
  `smtp_use_tls`, `smtp_username`, `smtp_password`,
  `mfa_email_from_name`, `mfa_email_subject`); `.env.example` (both root and
  `backend/`) updated to match. `mfa_dev_expose_code` is now meaningful only
  when SMTP is *not* configured — the moment real credentials are set, real
  email is always sent and the code is never echoed back, regardless of
  that flag.
- **Database**: Alembic `0007_mfa_email_otp` — drops `mfa_credentials`
  entirely; adds `code_hash`/`code_salt`/`delivered_via` (all nullable, since
  pre-existing challenge rows predate this column and have no meaningful
  code to backfill) to `mfa_challenges`. Verified with a dry-run `upgrade`
  and `downgrade` against a throwaway SQLite database — both directions
  produce the expected schema.
- **Dependencies**: `pyotp` removed from `backend/requirements.txt`. No new
  dependency added — email is sent with the Python standard library's
  `smtplib`/`email.message`.
- **Frontend**: `Login.tsx`'s MFA step no longer shows an authenticator-key
  / QR-code enrollment block (removed along with the backend's `enrollment`
  field); copy changed to "we emailed a verification code to your
  registered address," and the dev-code hint now reads "dev environment (no
  SMTP configured)" instead of implying a real deployment would ever show
  it. `types/index.ts` drops `MFAEnrollment` and the `enrollment` field, and
  adds `delivery`/`MFADelivery`. `SecurityAlerts.tsx` (the admin MFA feed)
  needed no changes — it already renders challenges generically.
- **`docs/architecture.md`**: Module 6 section rewritten to describe the
  email-OTP design as-implemented, with an explicit note that this departs
  from the Section 7/8 draft at the developer's instruction.
- **`backend/tests/test_mfa.py`**: rewritten for the new flow — every
  assertion on `enrollment`/`provisioning_uri`/`confirmed credential` is
  gone; added coverage for `delivery` status on both the dev-logged and
  real-SMTP-configured paths (a real send never exposes `dev_code`, a
  configured-but-failing send returns 503), and an explicit regression test
  that a second, later MEDIUM-risk login for the same already-challenged
  user is challenged again with a brand-new code (documenting the
  no-exemption behavior called out above, so it can't silently regress into
  an "already verified" shortcut later).

### Verification

- Full backend suite reinstalled into a clean virtualenv and re-run:
  **83/83 passing** (80 prior + 3 net new — two TOTP-specific tests removed,
  five new ones added covering the email flow, delivery-failure 503, and the
  consecutive-challenge behavior).
- Migration `0007` dry-run (`upgrade head` then `downgrade -1`) against a
  throwaway SQLite database in both directions: `mfa_credentials` is
  dropped/recreated correctly, `mfa_challenges` gains/loses exactly
  `code_hash`/`code_salt`/`delivered_via`, nothing else moves.
- Grepped the entire backend and frontend source trees after the change:
  the only remaining mentions of `TOTP`/`totp`/`pyotp`/`enrollment` are
  explanatory doc-comments describing the removal, not live code.
- `app.main:app` imports cleanly (route table unaffected — MFA endpoint
  paths and method are unchanged, only their internals and schemas).
- Frontend: `npx tsc -b --noEmit` → 0 errors.
- Every file was written matching its own file's pre-existing line-ending
  convention (CRLF for `backend/app/**/*.py` and the frontend files touched;
  LF for `docs/architecture.md` and the new `0007` migration, matching
  `0006`'s precedent) — no line-ending churn introduced.

### What the developer still needs to do to see real emails

This ships with SMTP unconfigured (`SMTP_USERNAME`/`SMTP_PASSWORD` blank in
`.env.example`), so out of the box every MFA challenge is dev-logged with
`dev_code` shown in the UI — functionally similar to the old TOTP dev
shortcut, but now honestly labeled and structurally temporary rather than a
permanent stand-in. To see a real email land in an inbox: generate a Gmail
**App Password** for a Gmail account (myaccount.google.com/apppasswords —
requires 2-Step Verification enabled on that Google account), then set
`SMTP_USERNAME=<that gmail address>` and `SMTP_PASSWORD=<the 16-character
app password>` in the actual `backend/.env` (not just `.env.example`) and
restart the backend. The recipient of each code is always the address the
signing-in user registered with — no separate configuration needed for that
side.

### Master Context reconciliation — resolved 2026-09-10

The "open question" originally left here (whether to update
`MASTER_PROJECT_CONTEXT.docx` to match, or leave it as an untouched
historical record) has been resolved: `MASTER_PROJECT_CONTEXT.docx` has now
been revised. Its Section 7 is marked "REVISED 2026-09-10 (Module 6 design,
as implemented)," describes the email-only-for-every-login design in full,
explicitly states TOTP is not to be reintroduced for Module 7's future
continuous-verification challenges either, and preserves the original
TOTP-hybrid draft underneath as a clearly labeled "Superseded original
spec" subsection for historical traceability rather than deleting it.
Sections 8 (Module 6 description), 9 (project modules list), 10 (technology
stack's MFA line), 14 (example final scenario), and 17/the final instruction
footer were updated to match. `MASTER_PROJECT_CONTEXT.docx` has no physical
file counterpart in the git repository — it exists only as a document in
the Claude Projects tool — so this reconciliation reached that document
directly there; there was no on-disk repo file to additionally update for
it. This status doc (`Project status.md`) remains the authoritative,
continuously-updated "as implemented" account for day-to-day development;
`MASTER_PROJECT_CONTEXT.docx` is the longer-lived planning/context document,
now brought back into agreement with it on the MFA method.

**Conclusion:** Module 6's MFA *method* is now pure email one-time codes for
every login, per the developer's explicit instruction, with TOTP fully
removed rather than patched. This is a deliberate design choice that departs
from the originally-approved Master Context Section 7 draft; it does not
change Section 6's risk-gating logic (LOW/MEDIUM/HIGH still decide
allow/challenge/block exactly as before), nor any other module. Modules
1-5, 6's decision logic, and the section-10 hardening remain intact and
unaffected — verified by the full regression-tested suite above. Module 7
is unaffected and still not started; this section records a constraint
Module 7 should follow (email, not TOTP) rather than any Module 7 work.

---

## 12. First-Login MFA Bypass via Registration-Triggered Session — Diagnosed and Fixed (2026-09-10)

Found while the developer was live-testing the email-OTP MFA flow from
section 11: registering a brand-new account, then logging out and logging
back in as that same account, skipped the MFA challenge entirely — even
though Module 5/6 are supposed to guarantee that a genuinely first-ever
login always lands in MEDIUM risk and gets challenged.

### Root cause

Not a defect in the trust-score or MFA decision code itself — both were
verified to do exactly what they're told with the history they were given.
The gap is one step upstream, in how the frontend treats registration:

1. `AuthProvider.register()` set auth status to `'authenticated'` the
   instant `POST /auth/register` returned. This was intentional — Module 6
   was never meant to gate registration, since the user already proved
   their credentials in that same request (see the Module 6 subsection in
   section 3 and Section 7 of `MASTER_PROJECT_CONTEXT.docx`).
2. `SessionProvider` opens the app's WebSocket as soon as auth status
   becomes `'authenticated'`, with no distinction between "just registered"
   and "just logged in."
3. That WebSocket connect calls Module 3's `create_session`, which persists
   a real `sessions` row recording the browser's User-Agent and IP — and
   Module 5's `session_opened` hook silently computes and stores a trust
   score for it, with no gate of any kind (Module 5 was never designed to
   gate anything; it just scores and stores).
4. So by the time the developer logged out and back in, the account already
   had **one prior session on file**. Module 5's `evaluate_login` therefore
   saw `has_history = True`, and since the login came from the same
   browser/machine that had just registered: `known_device` (+15,
   `trust_weight_known_device` in `app/core/config.py`) and `known_ip`
   (+10, `trust_weight_known_ip`) both applied. `70 (baseline) + 15 + 10 =
   95` — comfortably inside the LOW band (≥80) — so `mfa.decide()` correctly
   returned `ALLOW`, not `MFA`.

In short: registering quietly seeded exactly the "known device, known IP"
history that Module 5 is supposed to reward on a *second* login — before
the account's first real login ever ran the risk check at all. The
"first-ever login is always MEDIUM and gets MFA" guarantee (Section 6 of
the master context, and the Module 5 test suite's own
`test_second_session_is_recognised_as_known_device_and_ip` case) technically
still holds for a session with zero prior history; the frontend flow just
made sure no real login ever saw zero prior history.

### Fix (frontend only, no backend/API contract change)

- `frontend/src/auth/context.ts` — `register()`'s return type changed from
  `Promise<User>` to `Promise<void>`: creating an account no longer implies
  an authenticated outcome.
- `frontend/src/auth/AuthProvider.tsx` — `register()` still calls
  `POST /auth/register` (the account is created exactly as before), but now
  discards the returned token/user instead of storing it and flipping auth
  status to `'authenticated'`. With auth status never becoming
  `'authenticated'` off the back of a register call, `SessionProvider` never
  opens a WebSocket for it, so no session — and no trust history — is
  seeded.
- `frontend/src/pages/Login.tsx` — after a successful registration, the form
  now switches back to sign-in mode (with an "Account created. Sign in to
  continue." notice, and the email/password fields cleared) instead of
  routing straight into the dashboard. The user's very next action is a
  real `POST /auth/login`, which runs Module 5/6's risk check against a
  genuinely empty history — so a first-ever login is now actually
  challenged with MFA, matching the documented design.

`POST /auth/register`'s own contract (still returns a `Token`) is
unchanged — this is purely about what the frontend chooses to do with that
response. No backend file was touched; Modules 1-6 and the section-10/11
hardening are unaffected.

### Verification

- Diff reviewed: exactly 3 frontend files touched
  (`auth/context.ts`, `auth/AuthProvider.tsx`, `pages/Login.tsx`),
  39 insertions / 8 deletions — all additive except the register-branch
  rewrite in `Login.tsx`'s `handleCredentials`. No backend file in the diff.
- Grepped the whole frontend source tree for other `register(` call sites —
  the only one was the `Login.tsx` call already updated to the new
  `Promise<void>` signature.
- `npx tsc -b --noEmit` → 0 errors.
- Each file was patched in place preserving its own pre-existing
  line-ending convention (`context.ts` / `AuthProvider.tsx` are CRLF,
  `Login.tsx` is LF, per the section-9 housekeeping note) — `git diff` and
  `git diff -w` stats match exactly, so no line-ending noise was
  introduced.
- Not yet re-run live end-to-end by the developer (register → sign in →
  confirm the MFA step now appears) — that confirmation is the developer's
  next step; the reasoning above is the actual mechanism traced through the
  code, not an assumption.

**Conclusion:** the MFA/trust-score decision logic in Modules 5 and 6 was
correct all along; the bug was that the app's own registration flow
inadvertently gave every account a "known device" head start before its
first real login could ever be risk-evaluated from a clean slate. Fixed by
no longer treating a successful registration as an authenticated session.
Modules 1-5, Module 6's decision logic, and the section-10/11 hardening are
all unaffected. Module 7 is unaffected and still not started.

## 13. Post-Section-12 Regression — First-Time-Login 500 (Reported as a CORS Error) from an Unapplied Alembic Migration — Diagnosed and Fixed (2026-09-10)

Right after verifying the section-12 fix, the developer registered two new
accounts and tried logging in to both, to confirm MFA now actually
triggers. Both failed. The browser (Firefox) reported:

> Cross-Origin Request Blocked: The Same Origin Policy disallows reading
> the remote resource at http://localhost:8000/api/v1/auth/login. (Reason:
> CORS header 'Access-Control-Allow-Origin' missing). Status code: 500.

The developer also reported this was **not** limited to the two new
accounts — pre-existing accounts that had been created earlier but never
successfully logged in failed the exact same way.

### Diagnosis

The CORS wording is a red herring. The line the browser itself prints —
`Status code: 500` — is the real signal: the backend threw an unhandled
exception while handling the request, and FastAPI/Starlette's CORS
middleware only attaches `Access-Control-Allow-Origin` to responses that
pass back through its own `send` wrapper normally. An unhandled 500 can
skip that, so the browser sees a response with no CORS header and reports
"CORS blocked" instead of surfacing the real 500. This is a backend crash,
not a credentials problem and not a cross-origin misconfiguration.

Traced the request path end to end through the actual code (not assumed):
`authenticate_user` (username/password check), `trust_score_service.
evaluate_login`, `mfa_service.decide`, and — for a MEDIUM-risk decision —
`mfa_service.create_challenge`. Nothing in the decision logic itself was
broken. The distinguishing fact that cracked it: every affected account had
**zero prior session history** — either brand new, or old and never
logged in. Section 6/7's Module 5 guarantee is that a first-ever login
with no history always lands in MEDIUM risk, which means `/auth/login`
always calls `mfa_service.create_challenge` for these accounts. That
function does:

```python
challenge = MFAChallenge(
    ...
    code_hash=email_otp.hash_code(code, salt),
    code_salt=salt,
    delivered_via=delivered_via,
    ...
)
db.add(challenge)
db.commit()
```

`code_hash`, `code_salt`, and `delivered_via` are exactly the three columns
added by Alembic migration `0007_mfa_email_otp.py` (`alembic/versions/
0007_mfa_email_otp.py`), authored earlier the same day (2026-09-10) as part
of the section-11 TOTP-to-email-OTP redesign. `alembic upgrade head` had
not been re-run against the developer's actual running Postgres database
after that migration was written, so the live `mfa_challenges` table was
still missing those three columns. Every attempt to insert a challenge row
for a MEDIUM-risk login therefore failed at the database level with a SQL
error, which FastAPI turned into an unhandled 500 — and, per the CORS
mechanism above, a browser-side "CORS blocked" message instead of a
readable error.

This also explains why the symptom looked account-independent: any account
with an *existing* session history (known device/IP) lands in LOW risk,
never calls `create_challenge` at all, and would have logged in fine — the
developer did not report any account working, consistent with every
account tested at that point being either brand-new or never-logged-in.

### Fix

No source code was changed — Modules 2, 5, and 6's logic was correct and
untouched. This was a deployment/ops gap: the migration existed in the
repo but had not been applied to the live database. Resolved by running,
in the backend's virtualenv:

```
alembic current
alembic upgrade head
```

followed by a backend restart.

### Verification

Developer confirmed, after applying the migration and restarting the
backend, that login now completes normally for both newly-registered
accounts and pre-existing accounts that had never logged in before.

**Conclusion:** not a regression from the section-12 fix, and not a bug in
the trust-score/MFA decision code — a migration that had been written but
not yet applied to the real database. Worth remembering for future
migrations: a schema change to `mfa_challenges` (or any table) only takes
effect once `alembic upgrade head` is actually re-run against the running
database — writing the migration file is not enough by itself.

## 14. Module 6 — SMTP Configured for Real Email Delivery of MFA Codes (2026-09-10)


Sections 7 and 9 both flagged that Module 6's email-OTP delivery had only
ever run in its `dev_logged` fallback mode — `SMTP_USERNAME`/`SMTP_PASSWORD`
were blank in `backend/.env`, so every verification code was logged
server-side and surfaced to the UI as `dev_code` instead of actually being
emailed. This section configures the real send path.

### What was done

`backend/app/services/mfa/email_otp.py` already implemented both paths
(`is_smtp_configured()` gates between a real `smtplib.SMTP` send and the
dev-log fallback) — no source file was touched. The developer filled in
the previously-blank SMTP settings in `backend/.env`:

```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USERNAME=<a Gmail address with 2-Step Verification on>
SMTP_PASSWORD=<a 16-character Gmail App Password for that address>
```

`MFA_DEV_EXPOSE_CODE` was left unset, which defaults to `false` in
`app/core/config.py` — and per the code comment in `email_otp.py`, once
`SMTP_USERNAME`/`SMTP_PASSWORD` are set, real email is always sent and
`dev_code` is never returned regardless of that flag anyway.

`backend/.env` is listed in `.gitignore` (confirmed via `git check-ignore
-v backend/.env`) and was not, and will never be, committed — the Gmail
App Password never enters git history. This is purely a local
configuration change; there is no corresponding code diff to commit for
this step.

### Verification tool added

`backend/app/services/mfa/smtp_check.py` was added as a standalone
connectivity check — `python -m app.services.mfa.smtp_check
<recipient-email>` sends one real code through the exact same
`send_verification_email()` function the live login flow uses, entirely
outside the login/trust-score/MFA-challenge database flow, so SMTP itself
can be verified with one command instead of registering an account and
waiting for a MEDIUM-risk decision to fire.

### `SMTP_USERNAME` typo found and fixed

First run of `smtp_check.py` failed with Gmail's `535 5.7.8 Username and
Password not accepted`. The script's own printed configuration line made
the cause visible immediately: `backend/.env` had
`SMTP_USERNAME=ztcaasm.noreply@gmail.com` — the letters transposed from
the intended `ztsaacm.noreply@gmail.com`. Gmail was correctly rejecting
authentication for a mismatched/non-existent account; the App Password
itself was never the problem. Corrected the spelling in `backend/.env`
(not committed — see above) and re-ran the check.

### Status — confirmed working

Second run of `smtp_check.py` succeeded (`delivered_via=sent`) and the
developer confirmed the code was actually received in the target inbox.
Module 6's email-OTP delivery is now live end-to-end: `SENT` is the real
`delivered_via` value on every MEDIUM-risk login going forward, in place
of `DEV_LOGGED`. See section 15 for the `dev_code` UI removal this
unblocked.

## 15. Module 6 — `dev_code` Removed from the MFA Screen (2026-09-10)

With section 14's live SMTP delivery confirmed, the developer's original
condition for this change ("remove `dev_code` once SMTP is set up and
working, not before") was met.

### Change

`frontend/src/pages/Login.tsx` — removed the conditional block in the MFA
verification step that displayed `challenge.dev_code`:

```tsx
{challenge.dev_code && (
  <p className="text-xs text-[color:var(--color-text-muted)]">
    dev environment (no SMTP configured) — current code:{' '}
    <span className="font-mono">{challenge.dev_code}</span>
  </p>
)}
```

The MFA screen's doc comment was extended to note why: SMTP is configured
as of 2026-09-10, so every code is genuinely emailed and the dev-mode
readout no longer applies.

This is a UI-only change. Nothing on the backend was touched:
`MFAChallengeOut.dev_code` (the field) and the `email_otp.py`/
`mfa/service.py` dev-logging fallback both still exist exactly as before —
if SMTP is ever unconfigured again (blank `SMTP_USERNAME`/`SMTP_PASSWORD`),
the backend will still dev-log the code server-side and still populate
`dev_code` in the API response, per `_dev_exposed()` in `mfa/service.py`;
the frontend now simply never displays it. `frontend/src/types/index.ts`'s
`dev_code: string | null` field was left in place for the same reason —
it is still part of the real API contract, only its UI rendering was
removed.

### Verification

- `git diff -w` on `Login.tsx` shows exactly the 6-line JSX block removed
  and a doc-comment addition — no other line touched, no line-ending
  noise (file remains LF, per the section-9 housekeeping note).
- `npx tsc -b --noEmit` → 0 errors.
- Grepped the frontend source tree for `dev_code` — the only remaining
  reference is the still-valid type declaration in `types/index.ts`; no
  other component reads it.

**Conclusion:** Module 6 is now feature-complete as originally designed —
every MFA-required login gets a genuinely emailed one-time code, with no
visible dev/test fallback in the UI, while the backend keeps its
dev-logging safety net for any future environment where SMTP isn't
configured (local dev machines, CI, etc.).

---

## 16. Module 7 — Continuous Trust Evaluation: Implementation + Verification (2026-09-13)

Before starting, re-read `MASTER_PROJECT_CONTEXT.docx` in full (Section 6
Trust Score — unchanged; Section 7 "ADAPTIVE MFA CONCEPT — REVISED
2026-09-10" — email-only, TOTP never reintroduced, explicitly including
Module 7's re-verification; Section 8 — Module 7's definition; Sections 4/14
— the end-to-end demo scenario: session established → VPN/download events
lower the score → re-evaluation triggers an emailed code → a failed
re-verification revokes the session, removes the ACL, and generates a
security alert), this `Project status.md` in full, `docs/architecture.md` in
full, and every backend file in the Module 1-6 path this module needed to
integrate with (session hooks, the trust-score evaluator/service, the MFA
service/model/schema/endpoint, token revocation wiring, the WebSocket
connection manager, the session sweeper) — confirmed against the actual code,
not just this document's prior claims.

### What was built

- **`app/models/security_event.py`** (new) — `SecurityEvent` (Module 7's own
  audit table) + `SecurityEventType` (the six-event catalogue: `ip_change`,
  `vpn_detected`, `unknown_device`, `abnormal_request_rate`,
  `large_download`, `multiple_failed_logins`) + `SecurityEventAction`
  (`none` / `reverify` / `revoke`).
- **Alembic `0008_continuous_trust_evaluation`** (additive; `down_revision =
  0007_mfa_email_otp`, the actual migration head) — creates `security_events`;
  adds a nullable `mfa_challenges.session_id` (FK to `sessions.id`), added via
  `op.batch_alter_table(...)` rather than a bare `create_foreign_key`, because
  SQLite (used for this project's dry-run migration verification and its
  whole test suite) cannot ALTER a table to add a foreign key constraint
  in place — Postgres runs the same batch as one native ALTER, so this is
  portable both ways without weakening the constraint on the real target
  database.
- **`app/services/trust_score/continuous.py`** (new) — the core of the
  module. `classify_event()` maps an event type to a signed weight (config
  values in `app/core/config.py`: two brand-new weights,
  `trust_weight_abnormal_request_rate` / `trust_weight_large_download`,
  default 20 each; the other four reuse Module 5's existing weights).
  `record_event()` loads the session, recomputes its score against its
  **current** value (not the static baseline — the actual "dynamic" part of
  Section 8), persists a `trust_score_factors` row (so a session's full
  factor history — login time + every mid-session adjustment — stays
  queryable in one place) and a `security_events` row, decides the
  none/reverify/revoke action from the *new* risk band, and (for reverify)
  calls `mfa_service.create_challenge(reason=risk_retrigger, session_id=...)`
  or (for revoke) `session_service.terminate_session(reason=RISK_REVOKED)`.
  Deliberately a **submodule of the existing `trust_score` package**, not a
  new service package — per this project's own architectural note in
  `docs/architecture.md` — composing `trust_score` + `mfa` + `session`
  instead. Stays fully sync, like every other service in this codebase; the
  async WebSocket push/close its result calls for is left to the caller.
- **Reused, not rebuilt, for revocation**: `TerminationReason.RISK_REVOKED`
  and `MFAChallengeReason.RISK_RETRIGGER` were both already reserved
  constants (`app/models/session.py`, `app/models/mfa.py`), and
  `RISK_REVOKED` was already included in `app.services.auth.wiring`'s
  revoke-on-reasons set since the Module 6 hardening pass (section 10) — so
  calling `terminate_session(reason=RISK_REVOKED)` gets ACL removal (Module
  4's `session_closed` hook) and access-token revocation (Module 2/3's hook)
  "for free." Module 7 only added the trust-score recompute itself.
  `app/services/mfa/service.create_challenge` gained one new optional
  `session_id` parameter (nothing else in it changed) to scope a
  `risk_retrigger` challenge to the session that triggered it.
- **Re-verification failure/expiry revokes the specific session it guarded**,
  not just the challenge: `POST /mfa/verify` now checks
  `challenge.reason == risk_retrigger` and, on `ChallengeExhausted` or
  `ChallengeExpired`, terminates `challenge.session_id` with `RISK_REVOKED`
  and closes its socket, before re-raising the exact same 401/403 the login
  MFA flow already returns (the client-facing error contract for
  `/mfa/verify` is unchanged). On success it pushes a `trust.reverified`
  message down that session's socket but does **not** restore the trust
  score — re-proving identity doesn't undo the security signal that
  triggered the challenge. This required converting `verify_mfa` from a sync
  to an async endpoint function (it now `await`s `ConnectionManager`
  send/close); no other behavior of that endpoint changed.
- **An unanswered re-verification is a failed one**: `app/services/mfa/service.py`
  gained `expire_overdue_challenges()` (flips any PENDING challenge past its
  `expires_at` to `EXPIRED`), called every tick from the *existing* session
  sweeper in `app/main.py` (extended, not duplicated) — for any expired
  `risk_retrigger` challenge whose session is still active, that session is
  revoked the same way a live failure/exhaustion would be.
- **`ConnectionManager.send(session_id, message)`** (new, additive) — pushes
  a live JSON message to an ACTIVE session's socket *without* closing it, the
  counterpart to the existing `close(..., message=...)`. Used for
  `trust.reverify_required` / `trust.reverified`.
- **New endpoints** (`app/api/v1/endpoints/security.py`, registered in
  `router.py` as Module 7): `POST /security/events` (admin — ingest one
  event for a session; this is also the exact entry point Module 9's future
  simulation buttons will call), `GET /security/events` (admin, optional
  `session_id` filter — dashboard feed), `GET /security/config` (admin — the
  live event/weight/action reference table, mirroring `/trust-score/config`
  and `/mfa/config`).
- **`SessionRead` gained a computed `current_action` field**
  (`"reverify_required"` while a session has an open `risk_retrigger`
  challenge, else `null`) — populated at the endpoint layer via a new batched
  `continuous.pending_reverify_map()`, the same pattern `acl_status` used in
  Module 4, on all three session read endpoints and the Live Sessions list.
- **Frontend**: `frontend/src/session/ReverifyModal.tsx` (new) — mirrors
  `Login.tsx`'s MFA step (code entry, retry/expiry handling, a dev-code
  hint), shown as an overlay whenever `SessionProvider` receives a
  `trust.reverify_required` push on this tab's own signalling socket
  (previously-unused `onMessage` handler now wired up); completing it calls
  the unchanged `POST /mfa/verify`. A `trust.reverified` push, or the session
  ending for any reason, clears it. `frontend/src/api/security.ts` (new)
  wraps the three endpoints above. `LiveSessions.tsx` gained a "Current
  Action" column and a per-row event-type picker + "Trigger" button (this
  project's demo/testing hook for `POST /security/events`, clearly labelled
  as such, until Module 9 gives attackers dedicated buttons of their own
  calling the same endpoint). `SecurityAlerts.tsx` gained a second feed table
  for `GET /security/events` alongside the existing MFA-challenges one.
  `types/index.ts` mirrors every new backend schema.

### Standalone fix applied while verifying (not a Module 7 code defect)

**File:** `backend/tests/conftest.py` — added an autouse `_no_real_smtp`
fixture that force-blanks `settings.smtp_username` / `smtp_password` for
every test.

**Why:** `backend/.env` on this developer's machine has carried a real Gmail
App Password since section 14, so real email delivery is genuinely live for
local dev runs — correct and intended for that purpose. But `Settings`
reads `.env` unconditionally (`app/core/config.py`), and every MFA/auth test
in this suite (`test_mfa.py`, `test_auth.py`, and this module's new
`test_continuous_trust.py`) is written against the documented, load-bearing
assumption that SMTP is *unconfigured* in the test environment — dev-logged
delivery, `dev_code` echoed back, no real network call. Running the suite
with those real credentials loaded silently violated that assumption: 18
tests failed on the first full run, either because a real send attempt hit a
now-broken/expired Gmail App Password (534 `Please log in with your web
browser`, surfaced as an unexpected HTTP 503) or, for this module's own new
tests, because a *successful* real send meant `create_challenge` never threw
`DeliveryFailed`, so the MEDIUM-risk assertions in `test_continuous_trust.py`
correctly observed `action=reverify` turning into the email-failure
`action=revoke` path once the credentials happened to be stale that day — a
misleading, environment-dependent failure, not a Module 7 logic bug. Fixed
by blanking those two settings for every test, restoring the suite's own
documented hermeticity regardless of what a given developer's `.env` has
configured for real use. No test assertion was weakened; no non-test file
was touched; `backend/.env` itself was not touched.

### Known, deliberately unfixed observation carried forward from the Module
6 review (not a Module 7 gap)

`MASTER_PROJECT_CONTEXT.docx` Section 7 also describes a Redis-backed MFA
lockout — 3 wrong attempts within 15 minutes locks the account for 15
minutes (`ztsaacm:mfa_lockout:{user_id}` / `ztsaacm:mfa_failed:{user_id}`),
separate from Module 5's password-failure counter. Grepping the codebase
(`grep -rn "mfa_lockout\|mfa_failed\b\|ztsaacm:mfa" backend/app/`) confirms
this was never built in Module 6 — the real implementation only tracks
`attempts`/`max_attempts` (default 5, not 3) directly on the `MFAChallenge`
row, no separate Redis lockout layer. Flagged here for the record, per
"report outcomes faithfully" — deliberately **not** fixed as part of Module
7, since it is a pre-existing Module 6 gap outside this module's explicit
scope, and touching Module 6 further would only add regression risk to a
module that is otherwise independently verified and stable.

### Verification

- **Requirements checklist against Section 8 + the Section 4/14 demo
  scenario**: continuous re-evaluation during an active session (yes —
  `record_event` against the current score, not the baseline); the named
  example events VPN change / IP change / abnormal download / abnormal
  request rate (yes — all six catalogue types); re-triggering MFA (yes —
  `reverify`, reusing Module 6's email mechanism per Section 7's REVISED
  constraint, no TOTP anywhere in the diff); revoking the session/ACL (yes —
  `revoke` → `RISK_REVOKED` → the existing ACL-removal and token-revocation
  hooks); a security alert being generated (yes — the new `security_events`
  row + its `GET /security/events` feed on the Security Alerts page);
  dashboard updating live (yes — `current_action` on the polled session
  list, plus the live WebSocket push for the affected user's own tab).
- **Regression check against Modules 1-6**: every file this module touched
  was an *addition* to an existing file (new column, new optional parameter,
  new method, new route registration, new field with a default) except
  `verify_mfa`'s sync→async conversion (behavior-preserving — confirmed by
  the full pre-existing `test_mfa.py` suite still passing unmodified) and the
  session sweeper gaining one more per-tick step (the pre-existing idle/
  lifetime sweep logic and its own tests are untouched). No Module 1-6 model,
  schema, or endpoint had a field removed or renamed. `git diff --stat`
  reviewed file-by-file before considering this complete.
- **Full backend suite**, reinstalled from the project's throwaway
  Python-3.14-compatible virtualenv (see the `dev-env-backend-build` note),
  re-run from scratch: **98/98 passing** — the prior 83 (section 11) plus 15
  new in `backend/tests/test_continuous_trust.py`, with zero prior tests
  deleted, skipped, or weakened.
- **Migration `0008` dry-run** (`upgrade head` from a fresh DB, `downgrade
  -1`, `upgrade head` again) against a throwaway SQLite database (Settings'
  `database_url` property patched for the duration of the check only — no
  file this project ships was changed to do this): both directions succeed;
  `mfa_challenges` gains/loses exactly `session_id` (+ its index + FK);
  `security_events` is created/dropped cleanly with all three of its
  indexes.
- **Frontend**: `npx tsc -b --noEmit` → 0 errors. `npm run build` → succeeds
  (the `@rolldown/binding-linux-x64-gnu` issue flagged in the Module 4/6
  verifications no longer reproduces on this machine — not a Module 7
  change, noted for the record since this is the first time a from-scratch
  build was re-attempted since then).

**Conclusion:** Module 7 — Continuous Trust Evaluation is implemented per
Section 8 and the Section 4/14 demo scenario, integrates with Modules 1-6
through composition and existing hooks rather than new coupling, introduces
no TOTP anywhere (per Section 7's REVISED constraint), and does not regress
any prior module — verified by a from-scratch reinstall and full test run
(98/98), a bidirectional migration dry-run, and a clean frontend
type-check + production build. One pre-existing test-hermeticity gap (real
SMTP settings leaking into the test environment from a developer's own
`.env`) was found and fixed while verifying this module, and one pre-existing
Module 6 spec/implementation gap (the Redis MFA lockout) was confirmed still
open and deliberately left for a future, explicitly-scoped fix. Ready to
proceed to **Module 8 — Security Dashboard**.


---

## 17. Post-Module-7 Hardening — Shorter Re-Verification Window + Account-Level MFA Lockout (2026-09-13)

Two changes made right after Module 7's implementation/verification (section
16), at the developer's explicit request, both scoped to Module 6/7's MFA
mechanism rather than touching Module 7's event/scoring logic itself.

### 17a. Mid-session re-verification window shortened, 5 → 3 minutes

**Change:** a Module 7 `risk_retrigger` re-verification challenge (triggered
by `record_event()` dropping a session's live score into MEDIUM) now expires
after `MFA_RETRIGGER_TTL_MINUTES` (new setting, default 3) instead of
reusing `MFA_CHALLENGE_TTL_MINUTES` (still 5, unchanged, and still what a
fresh *login's* MFA challenge uses). The developer's stated reasoning: an
already-active session that just tripped a security event should get a
*tighter* window to re-prove identity than a brand-new login does — a
stricter, more zero-trust posture for the in-session case specifically.

- `app/core/config.py` — new `mfa_retrigger_ttl_minutes: int = 3`.
- `app/services/trust_score/continuous.py` — its `mfa_service.create_challenge(...)`
  call for a `risk_retrigger` challenge now passes
  `ttl_minutes=settings.mfa_retrigger_ttl_minutes`; `event_catalogue()`'s
  admin-facing config dict gained a `reverify_ttl_minutes` field.
- `app/services/mfa/service.py` — `create_challenge()` gained an optional
  `ttl_minutes: int | None = None` parameter (falls back to
  `mfa_challenge_ttl_minutes` when omitted, so every other caller — login,
  step-up — is byte-for-byte unaffected); used for both the emailed
  "expires in N minutes" copy and the challenge row's `expires_at`.
- `.env.example` (root and `backend/`) — new
  `# ---- Continuous Trust Evaluation (Module 7) ----` block documenting
  `MFA_RETRIGGER_TTL_MINUTES=3` and why it's deliberately shorter than the
  login TTL above it.
- Scoped deliberately narrow: only Module 7's mid-session re-verification
  changed. Login MFA and step-up MFA still use the original 5-minute
  `MFA_CHALLENGE_TTL_MINUTES`, unchanged.

**Verification:** full backend suite re-run — **98/98 passing**, unchanged
(no existing test asserted a specific re-verification TTL value, so none
needed updating); a direct API check confirmed a fresh `risk_retrigger`
challenge's `expires_at` is exactly 3.00 minutes out, and the dev-log line
shows the code annotated `(valid 3 min)`.

### 17b. Account-level MFA lockout (Redis-backed, additive alongside `max_attempts`)

**Problem:** Master Context Section 7 (see section 11's history above)
describes a Redis-backed *account-level* lockout — 3 wrong codes within 15
minutes locks the account out of MFA entirely for 15 minutes
(`ztsaacm:mfa_lockout:{user_id}` / `ztsaacm:mfa_failed:{user_id}`) — separate
from Module 5's password-failure counter. Section 16 confirmed this was
never built: Module 6 only ever enforced `MFA_MAX_ATTEMPTS` (default 5) on
the *one challenge row* being verified, with no cross-challenge, account-wide
limit. Flagged in section 16 as a known, deliberately-unfixed pre-existing
gap; the developer asked for it to be built now, explicitly **alongside**
`max_attempts` rather than replacing it.

**Two independent limits, by design:**

| Mechanism | Scope | Threshold (default) | Window | Effect |
|---|---|---|---|---|
| `MFA_MAX_ATTEMPTS` (pre-existing) | one `mfa_challenges` row | 5 wrong codes on it | the challenge's own lifetime | that one challenge closes (`failed`, 403) |
| `MFA_LOCKOUT_THRESHOLD` (new) | the whole account | 3 wrong codes across ANY of the user's challenges | `MFA_LOCKOUT_WINDOW_MINUTES` (15) | the account is locked out of MFA entirely for `MFA_LOCKOUT_DURATION_MINUTES` (15) |

With the stock defaults, the account-level lockout trips first (3 wrong
codes) — before a single challenge could ever exhaust its own 5 attempts.
This is intentional: it's the stricter, account-wide guard the Master
Context specifies, sitting in front of the pre-existing per-challenge one,
not instead of it.

**What was built:**

- `app/core/config.py` — `mfa_lockout_threshold: int = 3`,
  `mfa_lockout_window_minutes: int = 15`, `mfa_lockout_duration_minutes: int
  = 15`.
- `app/services/mfa/service.py` — new `MFALockedOut` exception (carries
  `retry_after_seconds`); two new Redis keys per user, best-effort like
  every other Redis mechanism in this codebase (fails open on a Redis
  error): `ztsaacm:mfa_failed:{user_id}` (a counter, TTL =
  `MFA_LOCKOUT_WINDOW_MINUTES`) and `ztsaacm:mfa_lockout:{user_id}` (set only
  once the threshold trips, TTL = the remaining lockout time).
  `verify_challenge()` now checks the lockout key *first* — raising
  `MFALockedOut` before it even looks at the challenge's own status —
  clears the failed-count key on a correct code, and increments it on a
  wrong one.
- `app/services/mfa/__init__.py` — re-exports `MFALockedOut`.
- `app/api/v1/endpoints/mfa.py` — `POST /mfa/verify` catches `MFALockedOut`
  and returns HTTP 429 with a `Retry-After` header and
  `{"message": ..., "code": "locked", "retry_after_seconds": N}` — same
  error shape as the existing `expired`/`exhausted`/`closed` codes, so the
  frontend branches on `code` the same way it already did. Exactly like an
  exhausted or expired `risk_retrigger` challenge, a lockout that occurs
  mid-re-verification also revokes the session it was guarding
  (`_revoke_retrigger_session`, `TerminationReason.RISK_REVOKED`) — the user
  still can't re-prove identity right now, so zero trust says the session
  doesn't get to keep running regardless of *why* they can't prove it.
  `GET /mfa/config` gained a `lockout` block (threshold/window/duration)
  alongside the pre-existing `max_attempts`.
- `.env.example` (root and `backend/`) — `MFA_LOCKOUT_THRESHOLD=3`,
  `MFA_LOCKOUT_WINDOW_MINUTES=15`, `MFA_LOCKOUT_DURATION_MINUTES=15`, in the
  Module 6 section next to `MFA_MAX_ATTEMPTS`.
- `docs/architecture.md` — new "MFA account lockout hardening (Module 6,
  2026-09-13)" section; the stale "known, deliberately out-of-scope"
  observation from the Module 7 section now points to it instead of
  describing the lockout as unbuilt.
- **Frontend**: `ReverifyModal.tsx` and `Login.tsx` both gained a `locked`
  branch alongside their existing `expired`/`exhausted` handling —
  `ReverifyModal` explains the session is being ended (matching the actual
  server-side revocation above); `Login.tsx` shows a "try again in N
  minute(s)" message (from `retry_after_seconds`) and returns to the
  sign-in step, same as `expired`/`exhausted` already did. No change to
  either file's happy-path or invalid-code handling.

**Tests added:**

- `backend/tests/test_mfa.py` — the lockout trips before a single
  challenge's own `max_attempts` with stock defaults; it counts wrong codes
  across *different* challenges for the same user (not just retries on one);
  a correct code resets the streak; it's scoped per-user (one user's wrong
  codes never lock another user out). `test_mfa_config_endpoint` updated to
  assert on the new `lockout` block. One pre-existing test
  (`test_wrong_code_decrements_then_exhausts`) needed one line added
  (`monkeypatch` the lockout threshold high) to isolate it from the new
  mechanism, since both it and the new lockout defaulted to the same
  threshold (3) and would otherwise collide on the same wrong attempt —
  not a logic bug, a genuine, intended interaction between two now-coexisting
  mechanisms.
- `backend/tests/test_continuous_trust.py` — a `risk_retrigger` challenge
  that trips the account-level lockout also revokes its session, mirroring
  the existing exhaustion/expiry tests' own assertions (WebSocket
  `session.terminated`/`risk_revoked` push, subsequent 401 on `/auth/me`).

**Verification:**

- Full backend suite reinstalled into a clean virtualenv and re-run from
  scratch: **103/103 passing** — the prior 98 (section 16) plus 5 new (4 in
  `test_mfa.py`, 1 in `test_continuous_trust.py`), with zero prior tests
  deleted, skipped, or weakened.
- Frontend: `npx tsc -b --noEmit` → 0 errors; `npm run build` → succeeds.
- No Module 1-7 model, schema, or endpoint had a field removed or renamed —
  every change here is additive (a new exception type, three new config
  settings, two new Redis keys, one new response field, one new error
  branch on each of two frontend files).

**Conclusion:** the account-level MFA lockout flagged as a known gap at the
end of Module 7's review (section 16) is now built, exactly as Master
Context Section 7 specifies, additively alongside the pre-existing
per-challenge `max_attempts` mechanism rather than replacing it, and
integrates with Module 7's `risk_retrigger` re-verification the same
fail-safe way an exhausted or expired challenge already did. Combined with
17a's shorter re-verification window, Module 6/7's MFA surface is now
strictly more zero-trust than it was at the end of section 16, with no
regression to any prior module. Modules 1-7 remain otherwise intact. Ready
to proceed to **Module 8 — Security Dashboard**.


---

## 18. Post-Module-7 Hardening — Account-Level Risk Lockout (2026-09-14)

### Gap found

While independently testing Module 7 via the admin panel's "Simulate"
control (section 16/17's own verification work), the developer intentionally
changed IP several times in a row against their own active (admin) session,
driving its live trust score below 50 (HIGH) and correctly getting it
revoked (`TerminationReason.RISK_REVOKED` — Module 7 working exactly as
designed). The developer then immediately logged back in as the same
account with no restriction at all.

Root cause: `POST /auth/login`'s risk decision (`evaluate_login()`) is
computed fresh from that attempt's own signals every time — it has no
memory of a prior session having been forcibly revoked for risk. The
`security_events` table (Module 7) is a pure audit log; nothing read it back
at login time. So a `RISK_REVOKED` termination had zero effect on the
account's ability to log back in right after. This is distinct from, and
has no interaction with, the account-level MFA lockout (section 17b) — that
one counts wrong MFA codes, not risk-based session revocations.

The design was worked out over an extended discussion before any code was
written, deliberately scoping what does and doesn't count as an offense,
the escalation shape, the reset window, and the enumeration-safety ordering
— see the full back-and-forth (including rejected/refined readings of each
point) preserved in this project's `claude/module-7-account-risk-lockout-plan.md`
doc. This section is the as-implemented, verified record; that doc is now
superseded by it.

### What was built

- **Trigger, deliberately narrow**: only a session revoked because
  continuous evaluation pushed its *live* score straight into HIGH (a direct
  crossing, no reverify chance ever offered). Explicitly excludes a
  HIGH-risk *login* attempt's own 403 (already blocked per-attempt) and a
  MEDIUM-risk reverify challenge that was failed, exhausted, MFA-locked, or
  left to expire, or that failed to even send — all of those also end in
  the same `RISK_REVOKED` reason, but the underlying risk was only MEDIUM
  and the session only ended because a recoverable follow-up check wasn't
  cleared, which is not the same signal as an outright HIGH crossing.
- **`backend/app/services/trust_score/risk_lockout.py`** (new) — two Redis
  keys per user, best-effort/fail-open like every other auxiliary Redis
  mechanism in this codebase: `ztsaacm:risk_offense:{user_id}` (a counter,
  TTL = `RISK_LOCKOUT_WINDOW_HOURS`, set once at the first offense and never
  renewed by later increments — so the 24h window stays anchored to that
  first offense, not the most recent one, exactly as agreed) and
  `ztsaacm:risk_lockout:{user_id}` (the active lockout, TTL = the current
  tier's duration).
- **Escalating, capped, account-wide**: 1st qualifying offense →
  `RISK_LOCKOUT_TIER1_HOURS` (default 1h), 2nd → `TIER2_HOURS` (4h), 3rd and
  every one after that within the same window → `TIER3_HOURS` (7h — the
  cap; it repeats, it never stops enforcing past the 3rd). Account-wide,
  keyed on `user_id` only — not device/IP/User-Agent — so a risky session
  on one device locks the account out everywhere, per the developer's
  explicit decision.
- **`app/services/trust_score/continuous.py`** — `record_event()` calls
  `risk_lockout.record_risk_offense(session.user_id)` from *inside* the
  `new_risk == RiskLevel.HIGH` branch only, before the later
  `DeliveryFailed`-reassigns-a-MEDIUM-reverify-to-revoke branch even runs —
  structurally guaranteeing the two cases can never be confused, rather than
  trying to filter one out after the fact.
- **`app/api/v1/endpoints/auth.py`** — `POST /auth/login` checks
  `risk_lockout.lockout_remaining_seconds(user.id)` immediately after
  `authenticate_user` succeeds, deliberately *after* the password is
  verified and before any trust-score evaluation or MFA challenge creation.
  Ordering matters: a wrong password against a locked account still gets
  the ordinary generic 401 and never reveals the account exists and is
  locked (enumeration-safety — the same principle the Module 6 MFA lockout
  already follows). Returns HTTP 423 with a `Retry-After` header and
  `{"message": ..., "code": "risk_locked", "retry_after_seconds": N}` when
  locked — a distinct status code from the MFA lockout's 429 so the two are
  never confused in logs or on the client.
- **`app/core/config.py`** — `risk_lockout_tier1_hours` / `_tier2_hours` /
  `_tier3_hours` / `_window_hours`, all env-overridable.
- **`.env.example`** (root and `backend/`) — `RISK_LOCKOUT_TIER1_HOURS=1`,
  `RISK_LOCKOUT_TIER2_HOURS=4`, `RISK_LOCKOUT_TIER3_HOURS=7`,
  `RISK_LOCKOUT_WINDOW_HOURS=24`, in the Module 7 section.
- **`docs/architecture.md`** — new "Account-level risk lockout hardening
  (Module 7, 2026-09-14)" section; the Module 7 HIGH→revoke bullet now
  cross-references it.
- **Frontend**: `Login.tsx`'s credentials-step catch branches on
  `code === "risk_locked"` and shows a dedicated "locked... try again in N
  hour(s)" message, alongside its existing generic-failure handling. No
  other frontend file needed a change (this never reaches the MFA step —
  it's rejected at the credentials step itself).
- **No migration** — purely Redis-backed like the MFA lockout, no new
  column or table, no Alembic revision needed.
- **Admin recovery — deliberately deferred, by explicit developer decision**:
  no "locked accounts" UI in this pass. The documented fallback if an
  account (including the only admin account, which is exactly the scenario
  that surfaced this whole gap) gets stuck is clearing the Redis keys by
  hand: `redis-cli DEL ztsaacm:risk_lockout:<user_id>
  ztsaacm:risk_offense:<user_id>`. Flagged as a natural fit for Module 8
  (Security Dashboard) once it exists, not forgotten.

### Tests

- `backend/tests/test_risk_lockout.py` (new, unit-level, against the fake
  Redis client directly — no HTTP/DB needed): tier escalation
  1st→2nd→3rd; the cap-and-repeat behaviour on a 4th+ offense (never stops
  enforcing, never grows past tier 3); the window resetting once it elapses
  (simulated by directly expiring the underlying counter key, the same
  technique used elsewhere in this suite for time-based Redis behaviour,
  rather than waiting a real 24 hours); scoped per-user; fails open on a
  simulated Redis outage without raising.
- `backend/tests/test_continuous_trust.py` (integration, extended) — a
  direct HIGH crossing both revokes the session *and* returns 423 with the
  correct `Retry-After`/`retry_after_seconds`/`code` shape on the very next
  login attempt; a MEDIUM-risk reverify that was exhausted, or that failed
  to even send (`DeliveryFailed`), does **not** trip it — confirmed by a
  fresh login succeeding (or at least never coming back 423) right after
  each; a wrong password against a locked account still gets a plain 401,
  never a hint the account is locked; the lockout blocks a login attempt
  carrying a completely different `User-Agent` (account-wide, not
  device-scoped); a second, unrelated account is unaffected.

### Verification

- Full backend suite reinstalled into a clean virtualenv and re-run from
  scratch: **112/112 passing** — the prior 103 (section 17) plus 9 new (5 in
  `test_risk_lockout.py`, 4 in `test_continuous_trust.py`), with zero prior
  tests deleted, skipped, or weakened; every extended pre-existing test
  (the direct-HIGH-crossing test, the reverify-exhaustion test, the
  reverify-email-failure test) still passes its original assertions
  unchanged, with only new assertions appended.
- No Module 1-7 model, schema, or endpoint had a field removed or renamed —
  every change here is additive (a new module, three new config settings +
  one existing pattern reused for a fourth, one new call site inside an
  existing branch, one new error branch in one existing endpoint, one new
  error branch in one existing frontend catch block).
- Frontend: `npx tsc -b --noEmit` → 0 errors; `npm run build` → succeeds.

**Conclusion:** the gap surfaced by testing Module 7 live — a session
correctly revoked for a direct HIGH-risk crossing had zero effect on the
account's ability to log straight back in — is now closed, exactly to the
scope the developer specified after working through the edge cases (which
revocations count, the escalation shape, the reset window anchor, the
enumeration-safe check ordering, and the deliberate decision to defer an
admin-unlock UI): additively, with no regression to any prior module or to
Module 7's own existing behaviour. Modules 1-7 remain otherwise intact.
Ready to proceed to **Module 8 — Security Dashboard**.

---

## 19. Bug Fix — User Portal's Trust Score/Risk Went Stale After a Module 7 Event (2026-09-14)

Found by the developer via a direct side-by-side comparison: the admin's
Live Sessions table showed a user's live score correctly dropped to 70
(MEDIUM) after a mid-session event, but that same user's own User Portal
still showed 100 (LOW) even after they completed the resulting re-verify
challenge.

### Root cause

`frontend/src/session/SessionProvider.tsx` fetched `trust_score`/`risk_level`
(via `GET /sessions/current`) exactly once, in the WebSocket's `onEstablished`
handler right after login — and never again for the life of the tab.

When Module 7 fires a mid-session event, the backend correctly recomputes
the score and pushes `trust.reverify_required` down that session's own
socket, and that push already carries the new `trust_score`/`risk_level`
(`app/api/v1/endpoints/security.py`). But `SessionProvider`'s handler for
that message only read the `challenge` field out of it to open the reverify
modal — `trust_score`/`risk_level` were received and silently discarded, so
the portal's copy was already stale the moment the event fired, before the
user even reverified.

Completing the reverify then pushes `trust.reverified` — which intentionally
carries **no** score at all (`{"type": "trust.reverified", "session_id":
...}`), since reverifying proves identity again but does not restore the
score (the underlying signal, e.g. still being on an unrecognised network,
is still true — this was correct, documented behaviour from Module 7 itself,
see section 16). `SessionProvider`'s handler for that message only closed
the modal, never re-fetching the session either.

Net effect: once any Module 7 event fired, the User Portal's Trust/Risk
display was permanently frozen at its session-creation value for that tab's
entire lifetime, regardless of any later event or reverify — while the
admin's Live Sessions table, which polls `GET /sessions` fresh on an
interval, always showed the true, current value. Two independent read
paths against the same underlying data, one of them just never updated.

This was a genuine implementation gap, not a documented design decision —
the caption under the score ("the static score from session creation") was
accurate when it was written, right after Module 5 and before Module 7
existed to change anything mid-session; it was never revisited once Module
7 added live push updates the frontend should have been consuming.

### Fix (frontend-only, additive, no backend/Module 1-7 logic touched)

- `frontend/src/session/SessionProvider.tsx` — on `trust.reverify_required`,
  now also merges `trust_score`, `risk_level`, and `current_action:
  "reverify_required"` from the push into the local `session` state
  (previously only `challenge` was read). On `trust.reverified`, now calls
  the existing `refresh()` (re-fetches `GET /sessions/current`) instead of
  only clearing the modal — since that push carries no score of its own,
  re-fetching is what picks up the authoritative server row (in particular
  `current_action` clearing back to `null`).
- `frontend/src/pages/UserPortal.tsx` — updated the now-inaccurate caption
  ("the static score from session creation") to describe the corrected,
  actually-live behaviour.
- No backend file, model, schema, or endpoint changed. No new tests needed
  at the backend level — the backend was already computing and pushing the
  correct values (confirmed by `test_continuous_trust.py`, unchanged, still
  passing); this closes a client-side gap in consuming them.

### Verification

- `npx tsc -b --noEmit` → 0 errors.
- `npm run build` → succeeds (only the pre-existing, unrelated chunk-size
  warning).
- Backend untouched by this fix — the existing 112/112 backend suite
  (section 18) is unaffected and was not re-run for this change since no
  backend file was modified.

**Conclusion:** User Portal's Trust score/Risk now update live in step with
Module 7's mid-session re-evaluation, matching what the admin dashboard has
always shown. Modules 1-7 (backend) and every other frontend page are
untouched.

---

## 20. Bug Fix — In-Band Score Changes Never Reached the User Portal Live (2026-09-14)

Found immediately after section 19's fix, by the developer testing the
corrected flow: triggering three IP-change events in a row (100 -> 90 -> 80
-> 70) made the User Portal jump straight from 100 to 70 the moment the OTP
was verified — the 90 and 80 steps were never shown, even though the admin's
Live Sessions table showed all three correctly as they happened.

### Root cause

`app/services/trust_score/continuous.py`'s `record_event()` always recomputes
*and persists* the new score/risk to the session row, on every single event,
regardless of what action results. But `app/api/v1/endpoints/security.py`
only pushed a WebSocket message down the affected session's own socket for
two of the three possible outcomes:

- crosses into **MEDIUM** -> `trust.reverify_required` (carries the new score)
- crosses into **HIGH** -> `session.terminated` (closes the socket)
- **stays in the same band** (`action == none`) -> **nothing was pushed**

So 100 -> 90 and 90 -> 80 both stayed inside the LOW band (80-100): the DB
was updated each time (which is exactly why the admin's Live Sessions table,
which polls the DB on an interval, showed 90 then 80 as they happened), but
neither event ever reached the user's own tab. The third event, 80 -> 70,
was the first to cross a boundary (into MEDIUM) and was therefore the first
(and only) WS push that tab ever received — hence the single jump straight
from 100 to 70.

This was a genuine design gap, not the same bug as section 19 (that one was
the frontend discarding data it already had over the wire; this one is the
backend simply never sending it for the `none` case).

### Fix

- **`backend/app/api/v1/endpoints/security.py`** — added an `else` branch
  (action `== none`) that now also pushes a WebSocket message,
  `trust.updated` (`session_id`, `risk_level`, `trust_score`), down the
  affected session's own socket. This never ends the session and never
  opens the reverify modal — it exists purely to keep a live numeric display
  in sync with what the DB (and therefore the admin dashboard) already has.
- **`frontend/src/types/index.ts`** — added `TrustUpdatedMessage`, mirroring
  the existing `TrustReverifyRequiredMessage`/`TrustReverifiedMessage`
  pattern.
- **`frontend/src/session/SessionProvider.tsx`** — handles `trust.updated`
  by merging `trust_score`/`risk_level` into the local `session` state, the
  same way `trust.reverify_required` already does (from section 19's fix).
- No change to `continuous.py`'s scoring logic itself, no schema/migration
  change, no change to the `reverify`/`revoke` push paths.

### Tests

- `backend/tests/test_continuous_trust.py` — extended
  `test_event_with_small_impact_keeps_low_risk_and_takes_no_action` to also
  assert the new `trust.updated` push's exact shape; added a new test,
  `test_consecutive_in_band_events_each_push_their_own_trust_updated`,
  reproducing the exact reported scenario (100 -> 90 -> 80, two consecutive
  in-band events on the same socket, each asserted to push its own
  `trust.updated` message with the correct running score).

### Verification

- Full backend suite reinstalled into a clean virtualenv and re-run from
  scratch: **113/113 passing** — the prior 112 (section 18) plus 1 new test
  (the extended test added an assertion to an existing test rather than a
  new test function), with zero prior tests deleted, skipped, or weakened.
- `npx tsc -b --noEmit` → 0 errors; `npm run build` → succeeds (only the
  pre-existing, unrelated chunk-size warning).
- No Module 1-7 model, schema, or endpoint had a field removed or renamed —
  this is additive: one new `else` branch in one existing endpoint, one new
  message type, one new branch in one existing frontend handler.

**Conclusion:** the User Portal's Trust score/Risk now update live for
*every* Module 7 event, not only the one that happens to cross a risk-band
boundary — matching the granularity the admin's Live Sessions table has
always had. Modules 1-7 (backend) and every other frontend page are
untouched.

---

## 21. Module 7 Hardening — Real Passive Network Detection (Section 18, 2026-09-15)

Implements the design finalized the previous day and recorded as Section 18
of `MASTER_PROJECT_CONTEXT.docx` ("REAL PASSIVE NETWORK DETECTION — Module 7
hardening"), per the explicit instruction to treat this as the core of the
project and build it before Module 8. Before writing any code, re-read
`MASTER_PROJECT_CONTEXT.docx` Section 18 in full, this file's sections 16-20,
`docs/architecture.md`'s Module 7 section, and every Module 1-7 file this
pass needed to integrate with or reuse (`config.py`, `security_event.py`,
`redis_client.py`, `continuous.py`, `evaluator.py`, `store.py`,
`risk_lockout.py`, the session model/hooks/wiring, the ACL wiring pattern it
mirrors, `sessions.py`'s WS handshake and `_client_ip()`, `deps.py`,
`ws/auth.py`, the existing `security.py` endpoint, `SessionProvider.tsx`,
and the existing `test_continuous_trust.py`/`conftest.py`) — confirmed
against the actual code, not this document's prior description of it.

### The problem this closes

Every part of Module 7 built through section 20 is real *once a security
event exists* — but until this pass, the only thing that ever created one
was an admin manually calling `POST /security/events` (the Live Sessions
"Trigger" control). Nothing passively watched a real user's own session and
noticed, on its own, that their real IP changed, their device looked
different, they were now on a VPN, or their request volume spiked. This
section closes that gap.

### What was built

- **`app/services/trust_score/heartbeat.py`** (new) — the detector itself.
  `record_heartbeat(db, session_id, ip_address, user_agent)` compares the
  request's real IP/User-Agent against a per-session **"last observed"**
  value (two Redis keys, `ztsaacm:heartbeat:last:{id}` /
  `ztsaacm:heartbeat:rate:{id}`, following the exact
  `store.py`/`risk_lockout.py` fail-open convention) — **never** the
  immutable login-time baseline (`sessions.ip_address`/`user_agent`, which
  this module never touches). The session's first-ever heartbeat silently
  seeds this state and fires nothing, exactly as Section 18 specifies. Every
  later heartbeat fires the matching event on a genuine difference: a
  changed IP checked against the same approved/known-bad VPN CIDR lists
  Module 5 already uses (`evaluator.in_any_cidr`, unchanged) fires
  `vpn_detected` instead of a plain `ip_change` when it lands in either list
  — one event per genuine change, not two competing penalties for the same
  address. A changed User-Agent fires `unknown_device`. Both can fire in the
  same heartbeat if both changed; if one of them revokes the session, the
  other is not attempted against an already-terminated session. Both call
  the **exact same, unmodified** `continuous.record_event()` every manual
  Trigger already used — Section 18's central design constraint — now
  passed a new `source` argument (see below); nothing about scoring, MFA
  re-triggering, or revocation logic changed.
- **`abnormal_request_rate`** — a rolling, fixed-window Redis counter
  (identical `INCR` + `EXPIRE`-if-new shape to Module 5's failed-login burst
  counter) incremented once per heartbeat call for a session, firing exactly
  once when it crosses `heartbeat_rate_threshold` within
  `heartbeat_rate_window_seconds` (defaults 20/60s — well above the ~3/min a
  single session's own heartbeat cadence alone would ever produce, so normal
  use never trips it). Section 18 explicitly left the counting strategy open
  ("a lightweight dependency incrementing a Redis counter on every
  authenticated call vs. counting heartbeats specifically") and its own
  testing plan describes tripping it with "a tight loop" of heartbeat calls
  — so **counting heartbeats specifically** was the implementation decision
  made here: simpler, self-contained to one new module, and directly
  testable exactly as the spec's own testing plan describes, rather than
  instrumenting every authenticated REST call in the app.
- **Second, independent HTTP channel — not the WebSocket**: `POST
  /security/heartbeat` (new, `app/api/v1/endpoints/security.py`) — any
  authenticated user, no request body. Resolves the caller's own current
  ACTIVE session server-side (`session_service.get_current_session_for_user`
  — a heartbeat can never be pointed at someone else's session), reads this
  *request's* real IP/User-Agent via a `_client_ip()` mirroring
  `sessions.py`'s own WebSocket version (so the existing deployment
  requirement — a trusted reverse proxy setting `X-Forwarded-For` — covers
  this endpoint too), and calls `heartbeat.record_heartbeat`. A heartbeat
  with no active session (a brief race around login/logout) is a harmless
  200 no-op, never an error the frontend has to special-case. This is
  deliberately separate from the WebSocket's own ping
  (`session_ws_heartbeat_seconds`): the session **is** the WS connection
  (Module 3) — its real IP/User-Agent are read exactly once, at handshake,
  and cannot change again on that connection without dropping it — so only
  a fresh HTTP request can ever observe a genuine mid-session change.
- **`app/api/v1/endpoints/security.py` refactor** — the WebSocket
  push/close logic that used to live inline in `ingest_security_event` was
  pulled out into a shared `_push_result()` helper, now called by both the
  manual admin path and the new heartbeat path, so a real automatic
  detection looks, live, **identical** to a manual admin Trigger from the
  affected session's own tab's point of view — Section 18's own explicit
  requirement ("no admin Trigger click involved anywhere in the path").
  `ingest_security_event` itself is otherwise behaviorally unchanged (same
  request/response shape except the new `source` field below).
- **`auto`/`admin` source tag (audit trail)** — `SecurityEventSource`
  (`app/models/security_event.py`, new) with `AUTO`/`ADMIN`; a new
  `security_events.source` column (Alembic `0009_security_event_source`,
  `down_revision = 0008`, `NOT NULL`, `server_default='admin'` — every event
  that existed before this column did, by construction, come from a manual
  admin Trigger, so the backfill default is historically correct). Every
  caller of `continuous.record_event()` now passes `source` explicitly —
  `SecurityEventSource.ADMIN` from `POST /security/events`,
  `SecurityEventSource.AUTO` from the heartbeat detector — surfaced on
  `GET /security/events` (a new optional `?source=auto|admin` filter, applied
  in SQL before the row limit, not after) and on `GET /security/config`
  (a new `heartbeat` sub-object reporting the live interval/window/threshold
  settings), so the audit log can now demonstrate, honestly, which alerts
  were real detections versus manual demo/test clicks.
- **Redis state lifetime — mirrors the ACL ref-count pattern**: the
  heartbeat's "last observed" state and rate counter are session-scoped, so
  `app/services/trust_score/wiring.py` (which already registers Module 5's
  `session_opened` hook) now also registers an `on_session_closed` hook —
  imported lazily, inside the hook closure, specifically to avoid pulling
  `continuous.py`'s own imports (which reach into the `mfa`/`session`
  packages) into `trust_score`'s own package `__init__` execution — that
  clears both Redis keys the instant a session actually ends, for every
  termination path (WS drop, logout, admin, idle/lifetime sweep, or a Module
  7 revoke). A generous TTL (`heartbeat_state_ttl_seconds`, default 3600s)
  remains as a pure safety net in case that hook somehow doesn't fire (a
  crash), never as the primary mechanism.
- **New config** (`app/core/config.py`, `.env.example` × 2) —
  `heartbeat_interval_seconds` (default 20, matching
  `session_ws_heartbeat_seconds`'s own default), `heartbeat_state_ttl_seconds`
  (3600), `heartbeat_rate_window_seconds` (60), `heartbeat_rate_threshold`
  (20) — all env-configurable, per this project's standing convention for
  every timing/threshold value.
- **Frontend**: `frontend/src/api/security.ts` gained `sendHeartbeat()`
  (`POST /security/heartbeat`, no body). `SessionProvider.tsx` gained a
  second `useEffect`, keyed on `sessionId`, that starts a
  `setInterval(sendHeartbeat, intervalMs)` the moment a session is
  established and clears it the moment the session ends;
  `VITE_HEARTBEAT_INTERVAL_SECONDS` (optional, defaults to 20) controls the
  cadence. A failed/missed heartbeat is swallowed, not retried or surfaced —
  per Section 18's own documented assumption, a missed heartbeat is not
  itself suspicious; the existing WS ping and idle-timeout sweep already
  cover a genuinely dead connection. Any resulting `trust.updated` /
  `trust.reverify_required` / `session.terminated` arrives back on the
  session's existing signalling socket via the handlers already built in
  sections 16/19/20 — the heartbeat call's own HTTP response is
  best-effort/informational and otherwise ignored by the frontend.
  `types/index.ts` gained `HeartbeatResult`, `SecurityEventSource`, and the
  `source` field on the existing event types, mirroring the backend schemas.

### Known, accepted limitations (carried over from Section 18, stated plainly)

A client-supplied IP is only trustworthy behind a properly configured
trusted reverse proxy (pre-existing, shared with the section-16 login-time
IP check — not new here). Real IP changes are not always malicious (mobile
handoffs, corporate NAT) — some false positives are an accepted tradeoff.
A backgrounded browser tab throttles JS timers, so detection latency can
exceed the nominal ~20s while a tab isn't in view. VPN detection is bounded
by the same static demo CIDR sample Section 6 already documents as a
limitation. On this single-machine dev setup there is no real second network
to observe end to end — genuine IP-change/VPN verification needs either a
live multi-network deployment or deliberately forged `X-Forwarded-For`
values for a demo, exactly as Section 18 anticipates.

### Tests

`backend/tests/test_heartbeat_detection.py` (new, 17 tests) — fakes a "real"
heartbeat via `X-Forwarded-For`/`User-Agent` headers on the test client, per
Section 18's own confirmed testing plan: the first heartbeat of a session
seeds silently and records nothing; a repeated, unchanged heartbeat fires
nothing; an IP change fires `ip_change` with `source=auto` and pushes
`trust.updated`; the same IP change landing in the known-bad VPN CIDR sample
fires `vpn_detected` instead (not both); landing in the approved-VPN sample
is scored positive; a User-Agent change fires `unknown_device`; an IP+UA
change together fire both events, in order, each with its own WS push; an
IP change that alone crosses into HIGH revokes the session and skips the
UA-change check that heartbeat would otherwise have also attempted; a tight
loop of heartbeat calls trips `abnormal_request_rate` at exactly the
configured threshold and not before, and not again on the next call past it;
a heartbeat with no active session is a harmless 200 no-op; the endpoint
requires authentication; a heartbeat only ever resolves and affects the
caller's own session, never another user's; the Redis "last observed"/rate
state is present after a heartbeat and gone once the session actually ends;
`GET /security/events` correctly filters by `?source=auto|admin` (and
rejects an unknown source) with both an admin-triggered and an
auto-detected event present on the same session; `GET /security/config`
reports the live heartbeat settings.

### Verification

- **Full backend suite**, reinstalled into a clean virtualenv from
  `requirements.txt` and run from scratch: **130/130 passing** — the prior
  113 (section 20) plus 17 new in `test_heartbeat_detection.py`, zero prior
  tests deleted, skipped, or weakened.
- **Migration `0009` dry-run** — `Settings.database_url` patched for the
  duration of the check only (no shipped file changed to do this, same
  technique as section 16's `0008` verification) against a throwaway SQLite
  database: `upgrade head` from a fresh DB (all nine migrations in
  sequence) succeeds, `security_events.source` exists with the expected
  columns; `downgrade -1` cleanly removes just that column; a second
  `upgrade head` + `downgrade base` full round trip also succeeds, tearing
  every table back down to nothing. Both directions clean.
- **Regression check against Modules 1-7**: every change is additive — one
  new service module, one new endpoint, one new nullable-by-default-value
  column with a historically-correct backfill, one new optional query
  filter, one new config block, one new frontend timer effect. No existing
  model, schema, or endpoint field was removed, renamed, or had its
  behavior changed; `ingest_security_event`'s request/response contract is
  unchanged apart from the additive `source` field; the WS push logic that
  moved into `_push_result()` is a straight extraction with no behavior
  change (covered by the pre-existing section-16/19/20 tests in
  `test_continuous_trust.py`, all still passing unmodified).
- **Frontend**: `npx tsc -b --noEmit` → 0 errors. `npm run build` →
  succeeds (only the pre-existing, unrelated chunk-size warning).
  `npx oxlint` on every changed frontend file → 0 issues.

**Conclusion:** Section 18 — Real Passive Network Detection is implemented
exactly as finalized: a genuine user's own mid-session network/device
activity now drives the Trust Score, Adaptive MFA, and session termination
directly, with no admin in the loop required to produce a security event,
matching Section 3's and Section 5's original framing of continuous
evaluation. The manual admin Trigger is unchanged and still works
side-by-side with the automatic path — both now visibly distinguished on the
audit trail by the new `source` tag. No Module 1-7 functionality was broken
or altered beyond what this section documents. Ready to proceed to
**Module 8 — Security Dashboard**.

## 22. Section 18 Hardening — `abnormal_request_rate` Counting Redesigned to Option A + Read-Exclusion (2026-09-15)

Section 18's own spec (section 21 above) explicitly left the request-rate
counting *strategy* an open choice, and shipped with the simpler of the two
options. Later the same day, a deliberate decision was made to switch to
the other option, plus an additional refinement neither option originally
specified. This section documents that redesign — a correction to one
sub-component of section 21, not a new feature. Everything else section 21
built (`ip_change` / `vpn_detected` / `unknown_device` detection, the
last-observed comparison, the `source` audit tag, the Redis state's
session-scoped lifetime) is unchanged.

### The two options, and why the choice changed

Section 18 left this open:

- **Option A** — a lightweight dependency increments a Redis counter on
  *every* authenticated call, anywhere in the app, attributed to the
  caller's own current session.
- **Option B** (what section 21 shipped) — only calls to the heartbeat
  endpoint itself are counted.

Option B was simpler to wire (the heartbeat handler already had a
`session_id` in hand and did the increment and the threshold check in one
place), and matched Section 18's own documented testing plan ("calling the
heartbeat/authenticated endpoint in a tight loop"). Its limitation: it can
only ever notice a tight loop of heartbeat calls specifically. A real
abnormal-rate scenario — credential-stuffing a protected endpoint, scripted
abuse of a data-export route, a compromised token hammering an admin
action — has no reason to also call the heartbeat endpoint, so Option B
could never detect it. Option A is the more realistic passive detector:
every non-GET authenticated call anywhere in the app counts, so any burst
of state-changing activity against the caller's own session is caught, not
only a heartbeat-specific one.

**The tradeoff Option A introduces, and how it's closed:** instrumenting
every authenticated call also means an admin's own dashboard polling would
count — a real, demoable false positive (an admin working the dashboard
racking up a high count against their own session and getting their own
score dinged for normal admin use), not just a theoretical one. Rather than
maintaining a per-route allowlist of "polling" endpoints to keep in sync as
new read endpoints are added, the fix is categorical: **GET/HEAD/OPTIONS
requests never count, full stop** — only state-changing calls
(POST/PUT/PATCH/DELETE) do. This matches the underlying intuition directly:
a burst of *state changes* is what's actually suspicious about a
compromised or scripted session, not a burst of reads, and it needs no
route-by-route bookkeeping.

### What was built

- **`backend/app/services/trust_score/request_rate.py`** (new module) — the
  request-rate counting and "fire once per window" logic, extracted out of
  `heartbeat.py` and made endpoint-agnostic:
  - `record_authenticated_call(user_id, method)` — no-ops for
    GET/HEAD/OPTIONS; otherwise resolves the caller's own current active
    session and bumps its fixed-window Redis counter
    (`ztsaacm:reqrate:{session_id}`, same `INCR` + `EXPIRE`-if-new pattern
    as every other auxiliary Redis counter in this codebase).
  - `check_and_mark_fired(session_id)` — `True` the first time the current
    window's count is observed at or above `request_rate_threshold`,
    `False` otherwise (below threshold, or this window already fired). A
    separate flag key (`ztsaacm:reqrate:fired:{session_id}`, same TTL as
    the counter) is what makes "fire once per window" work now that
    counting happens from many call sites instead of one atomic check —
    without it, every qualifying call past the threshold in the same
    window would re-fire the event.
  - `clear_session_state(session_id)` — deletes both keys; called from
    `heartbeat.clear_session_state`, itself still the target of the
    existing `session_closed` hook (`wiring.py`, unchanged).
  - Fail-open throughout, matching every other auxiliary Redis mechanism in
    this codebase: a Redis error never raises, never blocks the request
    that triggered it, and can only ever suppress a detection, never cause
    a spurious one.
  - Deliberately kept a "leaf" module within `trust_score` (imports only
    `config`, `logging`, `redis_client`, and `app.services.session.store`)
    so it can be imported from `app.api.deps` — used on nearly every
    request in the app — without the circular-import risk `heartbeat.py`'s
    own docstring already documents for `continuous.py`.
- **`backend/app/services/session/store.py`** — two new read accessors,
  `active_session_ids_for_user(user_id)` and
  `active_session_id_for_user(user_id)`. Both simply read the per-user
  Redis index (`ztsaacm:user:{user_id}:sessions`) that `register_active` /
  `deregister_active` already populate from inside `create_session` /
  `terminate_session` — **no new Redis state, no session-layer change**.
  This is what lets `request_rate.py` cheaply resolve "which session does
  this authenticated call belong to" without a database query and without
  the session layer needing to know `request_rate` exists (dependency
  direction stays `trust_score -> session`, per `wiring.py`'s own
  documented convention).
- **`backend/app/api/deps.py`** — `get_current_user` (the single dependency
  nearly every protected endpoint already uses) gained a `request: Request`
  parameter and, right before returning the resolved user, calls
  `request_rate.record_authenticated_call(user.id, request.method)`,
  wrapped in `contextlib.suppress(Exception)` as an extra safety net on top
  of that module's own fail-open guarantees — this dependency runs on
  almost every request in the app and must never be the reason one fails.
  This is the single choke point that makes Option A work with zero
  per-endpoint instrumentation.
- **`backend/app/services/trust_score/heartbeat.py`** — `_rate_key` /
  `_bump_rate_counter` removed; the rate-check block now calls
  `request_rate.check_and_mark_fired(session_id)` and fires the event
  exactly as before on `True`. `clear_session_state` now also delegates to
  `request_rate.clear_session_state`. Nothing else in this module changed
  — the `ip_change` / `vpn_detected` / `unknown_device` detection and the
  last-observed comparison are untouched.
- **Config renamed** (`backend/app/core/config.py`,
  `backend/.env.example`, root `.env.example`):
  `heartbeat_rate_window_seconds` / `heartbeat_rate_threshold` →
  `request_rate_window_seconds` / `request_rate_threshold`
  (`HEARTBEAT_RATE_WINDOW_SECONDS` / `HEARTBEAT_RATE_THRESHOLD` →
  `REQUEST_RATE_WINDOW_SECONDS` / `REQUEST_RATE_THRESHOLD` in env),
  reflecting that this is no longer heartbeat-specific. Comments rewritten
  to describe the new cross-endpoint, reads-excluded counting.
  `heartbeat_interval_seconds` / `heartbeat_state_ttl_seconds` are
  untouched — still heartbeat-specific (the frontend's polling cadence and
  the last-observed-state TTL), not part of this rename.
- **`backend/app/services/trust_score/continuous.py`** —
  `event_catalogue()`'s `"heartbeat"` reference block split in two:
  `"heartbeat": {"interval_seconds": ...}` (unchanged meaning) and a new
  `"request_rate": {"window_seconds": ..., "threshold": ...}` block,
  reflecting that request-rate config is no longer part of the heartbeat's
  own timing. `frontend/src/types/index.ts`'s
  `SecurityEventConfigResponse` mirrors the same split (this endpoint has
  no frontend consumer yet — defined but not yet rendered anywhere — so
  this is a type-only, no-op change for the running app).

**Numeric behavior for a pure heartbeat-only workload is unchanged.** A
tight loop of heartbeat calls with nothing else happening on that session
still counts, fires, and stops re-firing at exactly the same call as
before: the heartbeat call is itself a POST, so the dependency bumps the
counter once per heartbeat call, in the same order, before the handler's
own `check_and_mark_fired` check runs — Option A is a strict superset of
Option B's behavior for that workload, not a behavior change to it. What
changes is that *other* non-GET calls now also count, and GET calls now
explicitly never do (Option B never counted GETs either, since it only
ever counted heartbeat POSTs — this is only a behavior change relative to
a *hypothetical* naive "count everything" version of Option A, not
relative to what section 21 shipped).

### Tests (`backend/tests/test_heartbeat_detection.py`)

- The two existing tight-loop-of-heartbeats tests
  (`test_abnormal_request_rate_trips_on_a_tight_loop_of_heartbeats`,
  `test_abnormal_request_rate_fires_only_once_per_crossing`) needed only a
  settings-name rename (`heartbeat_rate_threshold` →
  `request_rate_threshold`) — their assertions and numeric expectations are
  unchanged, confirming the "numeric behavior unchanged for a pure
  heartbeat workload" claim above.
- `test_security_config_exposes_heartbeat_reference_settings` updated for
  the split `heartbeat` / `request_rate` config blocks.
- `test_heartbeat_state_is_cleared_when_the_session_ends` updated for the
  renamed Redis keys (`ztsaacm:reqrate:{session_id}` /
  `ztsaacm:reqrate:fired:{session_id}`, in place of the old
  `ztsaacm:heartbeat:rate:{session_id}`).
- **New:** `test_non_heartbeat_calls_also_count_toward_the_callers_own_session`
  — an admin, with their own active session open, issues three `DELETE`
  calls against a nonexistent session id (each 404s, but still
  authenticates, so still counts); the admin's own first-ever heartbeat
  afterwards observes the already-crossed threshold and fires — proving a
  non-heartbeat endpoint counts, and that attribution follows the caller's
  own session regardless of which endpoint did the counting.
- **New:** `test_get_requests_never_count_toward_request_rate` — five `GET`
  calls followed by two heartbeat calls with the threshold set to 2; the
  first heartbeat alone (count=1, its own POST) fires nothing, proving the
  five GETs contributed nothing at all (had they counted, the first
  heartbeat's own bump would already be past the threshold).
- **New:**
  `test_active_session_index_used_by_request_rate_is_populated_on_login` —
  confirms `app.services.session.store`'s existing per-user Redis index
  (`ztsaacm:user:{user_id}:sessions`) actually contains the session id once
  a session is open, independent of any request-rate behavior of its own —
  the confidence check for the "reuse the existing index, don't build a new
  cache" design decision.

### Verification

- **Full backend suite**, run from the same clean virtualenv used for
  section 21's verification: **133/133 passing** — the prior 130 (section
  21) plus 3 new tests above, zero prior tests deleted, skipped, or
  weakened.
- **Isolated regression check**: with the new
  `request_rate.record_authenticated_call` call in `deps.py` temporarily
  disabled, `tests/test_trust_score.py::test_user_trust_history` was
  confirmed to fail identically in isolation — this is a **pre-existing
  order-dependent flake unrelated to this change** (it passes when the full
  suite runs together, as the 133/133 result above shows; it fails when run
  completely alone, both with and without this section's changes). Nothing
  in this redesign touches trust-score history, session-open scoring, or
  WebSocket authentication (the WS handshake does not go through
  `get_current_user` at all), so this was not introduced or worsened here.
- **Frontend**: `npx tsc -b --noEmit` → 0 errors. `npx oxlint` on the one
  changed frontend file (`src/types/index.ts`) → 0 issues. No frontend
  runtime behavior changed — `SessionProvider.tsx`'s heartbeat timer and
  `sendHeartbeat()` call are untouched; `SecurityEventConfigResponse`'s
  `request_rate` field has no consumer yet, same as `heartbeat` already
  didn't.
- **No migration needed** — this redesign is entirely Redis-key and config
  based; no model, schema, or table changed.
- **Regression check against sections 1-21**: every change is either a
  rename (config keys, env vars, one JSON response block), an extraction
  (the rate-counting logic moved from `heartbeat.py` into its own module
  with identical externally-observable behavior for the heartbeat-only
  case), or additive (two new read-only accessors on `session/store.py`,
  one new guarded call in `deps.py`). No existing model, schema, endpoint
  field, or the `ip_change` / `vpn_detected` / `unknown_device` detection
  logic was touched.

**Conclusion:** `abnormal_request_rate` now reflects Option A (every
non-GET authenticated call, anywhere in the app, attributed to the
caller's own session) with reads categorically excluded, closing the gap
where Option B could only ever notice a heartbeat-specific tight loop and
the gap where an unscoped Option A would have falsely penalized an admin's
own dashboard polling. Every other part of Section 18, and every prior
module, is unchanged and still fully passing. Still ready to proceed to
**Module 8 — Security Dashboard**.

---

## 23. Post-Module-7 Hardening — Cascading Account-Lockout Termination (2026-09-16)

### Gap found

Found live, testing section 21's real passive detection with the same admin
account open in two browsers at once: Firefox (session A, live score 75,
the developer's primary window) and Chrome (session B). Chrome's score was
driven down by repeated heartbeats and crossed into HIGH, correctly getting
terminated (`RISK_REVOKED`) and, per section 18, tripping the account-level
risk lockout (tier 1, 1 hour). Firefox's session A kept running completely
untouched — same account, still-active WebSocket, still-valid ACL — for the
full lockout window. Only after the developer separately closed Firefox and
tried to log back in did the section-18 lockout correctly show up, as a 423
on the login attempt.

Root cause: section 18's lockout is a **login gate only** — it has exactly
two touch points in the whole codebase, `continuous.py`'s revoke branch
(which only *records* an offense) and `auth.py`'s `POST /auth/login` (the
only place that ever *checks* for one). Nothing between those two points
ever looked at an account's *other already-open* sessions. That scope was
an intentional, reasonable decision when section 18 shipped — a login gate
is what closes "revoked, then logs straight back in," which was the gap
being fixed at the time — but it left a second, narrower gap: an account
the system has just decided is too risky to let back in can still have a
live window open somewhere else for up to the full lockout duration,
which sits awkwardly against this project's own account-wide (not
device-scoped) framing of the lockout everywhere else it's documented.

The developer asked for a professional recommendation before committing to
the change. Given: (1) Zero Trust's own continuous/account-aware
philosophy — an account decided untrustworthy shouldn't get to keep a
side-door session alive just because the crossing happened on a different
device; (2) the fix is a small, low-risk extension of code that already
exists (`terminate_user_sessions`, built for `/auth/logout`) rather than new
mechanism; and (3) the trade-off that this makes the system behave more
aggressively — instantly killing every other open tab/device the instant
one of them crosses HIGH, worth calling out explicitly in a demo — the
recommendation was to build it. Approved; this section is the as-built,
verified record.

### What was built

- **Trigger, identically scoped to the existing lockout offense**: a new
  local `direct_high_crossing` flag is set in
  `continuous.py`'s `record_event()` at the exact same place, and under the
  exact same condition (`new_risk == RiskLevel.HIGH`, evaluated before any
  later `DeliveryFailed`-reassigns-a-MEDIUM-reverify-to-revoke branch runs),
  as the pre-existing `risk_lockout.record_risk_offense()` call section 18
  already added there. This is deliberate, not incidental: reusing the
  identical scoping means the already-tested "a failed/expired/undeliverable
  MEDIUM reverify must not trip the account lockout" distinction
  automatically also governs "must not cascade-terminate other sessions" —
  one condition, two consequences, impossible for them to drift apart.
- **`backend/app/services/session/service.py`** — no new function needed.
  The revoke branch, immediately after the triggering session's own
  `terminate_session(..., reason=RISK_REVOKED)`, now also calls the
  pre-existing `terminate_user_sessions(db, session.user_id,
  reason=TerminationReason.ACCOUNT_LOCKED)` (previously used only by
  `/auth/logout`) to end every *other* still-active session on that account.
  Ordering is what makes this safe: `terminate_session` flips the triggering
  session to `TERMINATED` synchronously, before `terminate_user_sessions`
  runs its own "still ACTIVE" query — so the triggering session is naturally
  excluded from its own cascade and keeps its original `RISK_REVOKED`
  reason (confirmed by `terminate_session`'s existing idempotency: calling
  it again on an already-terminated session is a no-op that returns the row
  unchanged).
- **`backend/app/models/session.py`** — new
  `TerminationReason.ACCOUNT_LOCKED = "account_locked"` constant, added to
  the `ALL` tuple. `termination_reason` is a free-form `String(32)` column
  with no DB-level enum — **no migration needed**.
- **Bug caught while writing the integration test, fixed before this
  shipped**: cascading the *session* alone was not enough.
  `backend/app/services/auth/wiring.py`'s existing token-revocation hook
  only revokes the access token for an explicit allow-list of termination
  reasons (`_REVOKE_ON_REASONS`), and the new `ACCOUNT_LOCKED` reason was
  not in it. Left unfixed, the cascade would close session A's row and
  remove its ACL, but session A's own JWT would stay valid — Firefox could
  have silently reopened a brand-new session on the same token a moment
  later, defeating the entire point of the fix. Added `ACCOUNT_LOCKED` to
  `_REVOKE_ON_REASONS` alongside `RISK_REVOKED`. Caught immediately because
  the new integration test below asserts `GET /auth/me` on session A's
  *original* token returns 401 after the cascade, not just that the session
  row shows `terminated` — this class of gap only shows up when the test
  checks the token, not just the row, which is now recorded here as the
  reason that specific assertion is in the test rather than an incidental
  extra check.
- **Everything else about the cascade is free, by construction**: because
  both the triggering session and every cascaded session go through the
  exact same, unmodified `terminate_session()` → `emit_session_closed()`
  path, every existing hook already fires correctly with zero new code:
  ACL removal (Module 4's `acl/wiring.py`), the WebSocket `session.closed` →
  `session.terminated` push on each affected session's own socket (via the
  existing `store.publish_event`/WS forwarder in `main.py`), and the
  heartbeat/request-rate Redis cleanup (`trust_score/wiring.py`). No new
  push message type, no new WS code, no new Redis key, anywhere.
- **Frontend — zero functional changes needed**:
  `LiveSessions.tsx`'s `StateBadge` already renders `termination_reason` as
  a raw string with no lookup table (`` `terminated · ${reason}` ``), so
  `account_locked` displays correctly with no code change.
  `SessionProvider.tsx`'s `forceLogout()` already fires unconditionally on
  *any* `session.terminated` push regardless of `reason`, so Firefox's tab
  correctly gets forced out the instant the cascade reaches it, with no
  code change either — both files got a docstring/comment update only, for
  documentation completeness.

### Tests (`backend/tests/test_continuous_trust.py`)

Three new integration tests, added directly after the existing
direct-HIGH-crossing test and before the section-18 lockout tests:

- `test_direct_high_crossing_cascade_terminates_the_accounts_other_active_sessions`
  — opens session A (score forced to 90/LOW, standing in for "the other
  browser") and session B (score forced to 60/MEDIUM) on the same account,
  posts `abnormal_request_rate` against B pushing it to HIGH, and asserts:
  B's own socket gets `{"reason": "risk_revoked"}` (unchanged from the
  single-session case); A's socket **also** gets a push, with
  `{"reason": "account_locked"}`; A's row afterward shows
  `state: "terminated"`, `termination_reason: "account_locked"`,
  `acl_status` removed/removing; B's row still shows `"risk_revoked"`
  (never overwritten by the cascade); and — the assertion that caught the
  token-revocation gap above — a `GET /auth/me` call on session A's
  original token now returns 401.
- `test_cascade_termination_does_not_touch_a_different_users_sessions` — a
  second, unrelated account's own active session is confirmed still
  `"active"` after the first account's direct HIGH crossing and cascade.
- `test_delivery_failure_revoke_does_not_cascade_terminate_other_sessions`
  — mirrors the existing MEDIUM-reverify-email-failure test (SMTP settings
  and `send_verification_email` monkeypatched to raise): a MEDIUM-risk
  reverify reassigned to revoke because it couldn't even be emailed still
  ends only that one session — the account's other active session is
  confirmed still `"active"` — proving the cascade is scoped to a genuine
  direct HIGH crossing exactly as the lockout offense already is, not to
  every revoke.
- **Test technique**: a second token for the same account is minted
  directly via `create_access_token(user_id)` (from `app.core.security`)
  rather than a real second `POST /auth/login` call, to simulate "a second
  browser/device already logged in" without going through Adaptive MFA's
  own risk evaluation on that call (which can require a step-up challenge
  or fail unpredictably on a second login for the same user in a short
  window) — this exact technique is already precedented in
  `test_token_revocation.py`.

### Verification

- **Full backend suite**, run from the same clean virtualenv used for every
  prior section's verification: **136/136 passing** — the prior 133
  (section 22) plus the 3 new tests above, zero prior tests deleted,
  skipped, or weakened.
- The first run of the new tests caught the `_REVOKE_ON_REASONS` gap
  described above (2 of 3 new tests failed with the cascaded session's
  token still returning 200 instead of 401) — fixed by adding
  `ACCOUNT_LOCKED` to that set; re-run afterward: all 3 pass.
- **No migration** — `termination_reason` is a free-form `String(32)`
  column with no DB enum; `ACCOUNT_LOCKED` is just a new string value.
- **Frontend**: `npx tsc -b --noEmit` → 0 errors. No frontend runtime
  behavior changed — confirmed by inspection that `StateBadge` and
  `forceLogout()` both already handle an unrecognized/new `reason` value
  correctly with no lookup table to update.
- **Regression check against sections 1-22**: every change is additive (one
  new flag local to one existing branch, one new call to an existing
  function, one new constant, one existing set gaining one member) — no
  existing model, schema, endpoint field, or prior termination path's
  behavior was altered. `risk_lockout`'s own login-gate check (section 18)
  is completely untouched; this section only adds a second, independent
  consequence to the same trigger it already fires on.

**Conclusion:** the gap surfaced by testing with the same account open in
two browsers — a direct HIGH crossing correctly locked the account out of
*future* logins but left every *other already-open* session on that
account running untouched — is now closed. The instant one session on an
account has a direct HIGH crossing, every other active session on that
same account is cascade-terminated (`account_locked`) through the same,
unmodified termination path, including token revocation and ACL removal,
with no new WebSocket/push code and no frontend code changes required. As
flagged during the recommendation: this makes the system behave more
aggressively than before — a risky event on one device now instantly ends
every other open window/device on that account, not just the one that
crossed — which is worth calling out explicitly in a demo. Every prior
module and hardening pass remains otherwise intact. Still ready to proceed
to **Module 8 — Security Dashboard**.

---

## 24. Module 3/7 Hardening — Page-Refresh Reconnect Reattaches Instead of Resetting the Session (2026-09-16)

### Gap found

Found live, testing continuous evaluation directly: with a session driven
down into MEDIUM (a pending re-verify challenge outstanding) or otherwise
mid-score, refreshing the browser tab made the score jump straight back to a
fresh baseline and the pending re-verify prompt vanished — the developer
could dodge an outstanding MFA challenge just by pressing refresh.

Root cause, and it's a Module 3 one, not a Module 7 bug: Module 3's FSM ties
a "session" 1:1 to the *liveness of one specific WebSocket connection* — its
`onopen` drives S1 -> S2, its `onclose` drives S2 -> S3 -> gone,
unconditionally, per the session-lifecycle docstring going all the way back
to Module 3's original implementation. A page refresh drops that connection
exactly the same way closing the tab does — the two are indistinguishable at
the transport level — so the WS handler's `finally` block terminated the
session immediately either way, and the still-valid JWT (moved to
`sessionStorage` a while back specifically so it survives a same-tab
refresh — see the relevant earlier section) simply opened a **brand-new**
session on reconnect, scored fresh from Module 5's login-time baseline. That
was fine, arguably correct, for Module 3 alone. It became a real security
gap the moment Module 7 started accumulating state *within* a session's
lifetime that mattered to keep: a degrading trust score, and a pending
re-verify challenge that shouldn't be dischargeable by just not answering it.

The developer asked for a recommendation before committing to a fix, same
process as section 23. Given the severity — this is a working bypass of
continuous evaluation's whole premise, not a cosmetic inconsistency — the
recommendation was to fix it properly rather than patch around symptoms,
and to do so without touching the parts of Module 3 that don't need to
change (a genuinely closed tab must still lose its session and ACL quickly).
Approved; this section is the as-built, verified record.

### What was built

- **Reattachment, scoped to the exact token**: every access token carries a
  unique `jti`, already stored on the session row it opened
  (`token_jti` — Module 2/3 hardening, see the token-revocation section
  above) for revocation purposes. A page refresh presents that *same* token;
  a genuine new login always mints a fresh one at `POST /auth/login`. That
  distinction is exactly what's needed and already existed —
  **`backend/app/services/session/service.py`** gained one new read,
  `get_active_session_by_token_jti(db, token_jti)`, doing nothing but that
  lookup (at most one ACTIVE session can ever match, since a `jti` is unique
  per mint).
- **A short, dedicated grace window, not the idle timeout**:
  `backend/app/core/config.py` gained `session_reconnect_grace_seconds`
  (default 5s, env `SESSION_RECONNECT_GRACE_SECONDS`). An ordinary WS drop no
  longer finalizes the session immediately — `backend/app/api/v1/endpoints/
  sessions.py`'s WS handler schedules a background `_finalize_disconnect`
  task (mirroring `app.main`'s existing `_session_sweeper` background-task
  pattern: its own short-lived `SessionLocal()`, since the request-scoped
  `db` is already gone by the time it runs) that sleeps the grace window,
  then finalizes the close with `TerminationReason.WEBSOCKET_DISCONNECT`
  **only if nothing reattached in the meantime** (checked via `ws_connected`
  and a `last_seen_at` marker captured at the moment of that specific drop —
  guards against a slow, stale finalize task cutting short a *second* drop's
  own, separately-scheduled grace window after a reattach-then-drop-again
  sequence). Deliberately NOT reusing `session_idle_timeout_minutes` (30
  minutes) — a tab that's actually just closed should still lose its
  session/ACL in seconds, matching this project's own "revoke fast" framing
  everywhere else; only a refresh-speed reconnect gets the benefit.
- **The reattach itself, at handshake time**: if
  `get_active_session_by_token_jti` finds a match, the handler reuses that
  session row outright — `touch_session` + `set_ws_connected(True)`, same
  `session_id` sent back in `session.established` (now carrying a
  `reconnected: bool` field) — instead of calling `create_session`. Nothing
  else runs: no `emit_session_opened`, so Module 4's ACL is never re-created
  (it was never torn down) and Module 5's login-time evaluator is never
  re-invoked (the CURRENT, possibly-degraded score and risk band are sent
  back exactly as they stood). A miss (no match — a real new login, or the
  earlier session's grace window already lapsed) falls through to
  `create_session` exactly as before this hardening pass.
- **The pending re-verify challenge is resent, not just the score**: this is
  the actual fix for the reported bypass. On a reattach, the handler calls
  the existing `continuous.has_open_retrigger_challenge` and, if one is
  still PENDING, re-pushes `trust.reverify_required` down the newly-attached
  socket — same construction `security.py`'s `_push_result` already uses
  (fresh `mfa_token`, same underlying `MFAChallenge` row and `challenge_id`),
  so the frontend's `ReverifyModal` reappears instead of the refreshed tab
  looking clean. One accepted, narrow gap: `dev_code` (the SMTP-unconfigured
  local/demo convenience that echoes the raw OTP back) is never re-shown on
  a resend, only on the original push — it's a transient, deliberately
  never-persisted attribute of the object `create_challenge` returns at
  creation (storing a real OTP in cleartext anywhere would be the actual
  regression), and a resend reads a freshly re-queried row that was never
  that object. The real code is still sitting in that session's server log
  from the first push.
- **Frontend — zero code changes needed.** `SessionProvider.tsx`'s
  `SessionSocket` already reconnects on any ordinary drop and treats
  `session.established` the same regardless of an unrecognized extra field;
  its `onMessage` handler already applies `trust.reverify_required` and
  `trust.updated` pushes exactly the way a fresh one behaves. The refresh
  itself (a full page reload) recreates the whole React tree anyway, so
  there was never any client-side session-identity state to reconcile —
  everything the reattach needs the client to see arrives correctly shaped
  over the same two message types the frontend already handles.
- **Testability fix found along the way, not a feature change**: writing
  the first reattach test surfaced that `app.core.database.SessionLocal`
  (used directly by `_finalize_disconnect`, and — it turns out — by the
  pre-existing `_session_sweeper` too) bypasses `app.dependency_overrides`
  entirely, since that override only intercepts FastAPI's own
  `Depends(get_db)` resolution. Both background paths were quietly trying to
  reach the real (Postgres) `database_url` in every test all along; the
  sweeper's failure was invisible because it only wakes on a 30-second timer
  that essentially never fires within one fast test (this is the harmless
  "session sweeper iteration failed" warning visible in verbose test output
  going back to Module 3). The new grace-window path runs on a
  sub-second timer, so it hit this immediately. Fixed once, at the root, in
  `backend/tests/conftest.py`'s `client` fixture: `SessionLocal` is a
  `sessionmaker` *instance*, not a plain reference, so `SessionLocal.
  configure(bind=db_engine)` reaches every module that already imported it
  (including ones imported long before the fixture runs) — no per-call-site
  patching needed, and it incidentally makes the idle sweeper properly
  testable against the in-memory SQLite too, for whenever a test needs that.

### Tests

- **`backend/tests/test_sessions.py`** (new section, "Reconnect-within-grace
  reattach"): `test_refresh_reconnect_reattaches_without_resetting_the_score`
  — disconnect, degrade the score directly, reconnect with the same token,
  confirm the SAME `session_id`, `reconnected: true`, and the degraded score
  untouched. `test_reconnect_after_grace_window_opens_a_genuinely_new_session`
  — disconnect, let the (test-shortened) grace window actually lapse via the
  existing `_wait_terminated` poll, reconnect with the same still-valid
  token, confirm a genuinely NEW `session_id` and `reconnected: false` — the
  pre-2026-09-16 behaviour, correctly preserved for a tab that's actually
  gone. `test_a_different_token_never_reattaches_even_if_reconnecting_
  instantly` — a second, distinct token for the same account, reconnecting
  immediately, still opens its own independent session — reattachment is
  scoped to the exact `jti`, never to "this user reconnected recently."
  `test_get_current_session_for_caller` extended: immediately after an
  ordinary disconnect the session is still the caller's current one (new,
  correct behaviour); only once the grace window actually lapses does it
  stop being so.
- **`backend/tests/test_continuous_trust.py`** (new section, "reconnect
  reattach resends a pending reverify challenge"):
  `test_refresh_reconnect_resends_the_pending_reverify_challenge` — the
  direct regression test for the reported bug: force a session into MEDIUM
  with a real pending challenge, disconnect, reconnect with the same token,
  confirm `session.established` shows the SAME session/unreset score AND a
  resent `trust.reverify_required` carrying the identical `challenge_id` and
  a fresh, usable `mfa_token` (with `dev_code` correctly null on the resend,
  per the accepted gap above) — and that the underlying `MFAChallenge` row
  itself, and `GET /sessions/{id}`'s `current_action`, are undisturbed.
  `test_reconnect_without_a_pending_challenge_gets_no_reverify_push` —
  a reattach on an ordinary LOW/no-challenge session pushes nothing extra.
- **Existing tests updated for the new timing/identity semantics** (all were
  previously exploiting an ordinary disconnect finalizing instantly, or two
  sockets sharing one token to mean "two independent sessions" — neither
  assumption holds after this hardening pass):
  `test_token_revocation.py::test_ordinary_disconnect_does_not_revoke_the_token`
  (docstring + comment updated; its actual assertion — the token itself is
  never revoked by an ordinary disconnect — needed no change).
  `test_acl.py::test_session_close_removes_acl_rule` and
  `test_refcount_keeps_entry_until_last_session_closes` (the latter also
  switched its second concurrent connection to a genuinely separate
  minted token — reusing the first would now reattach instead of opening a
  second session, collapsing its own "two sessions, one IP" premise) —
  both now wait out the grace window before draining the ACL queue.
  `test_trust_score.py::test_second_session_is_recognised_as_known_device_and_ip`
  and `test_user_trust_history` — both switched their sequential second
  connection to a second minted token for the same reason.
- **New test-infra fixture**: `backend/tests/conftest.py`'s
  `_fast_reconnect_grace` (autouse) monkeypatches
  `session_reconnect_grace_seconds` to 0.3s for the whole suite — comfortably
  under existing polling helpers' ~1s budget (so `_wait_terminated`-based
  tests needed no changes) and comfortably above realistic in-process
  reconnect latency (so a reattach test's immediate reconnect reliably lands
  inside the window).

### Verification

- **Full backend suite**: **141/141 passing** — the prior 136 (section 23)
  plus 5 new tests above, zero prior tests deleted or weakened; every
  existing test's original assertions are intact, with only the specific
  ones enumerated above adjusted for the new (correct) timing/identity
  semantics.
- **The `SessionLocal` testability gap above was caught BY these new
  tests failing first** (`OperationalError: connection to server at
  "localhost", port 5432 failed`), not discovered by inspection — fixed once
  in `conftest.py`, confirmed by re-running the full suite clean afterward.
- **No migration** — no model, schema, or column changed; the token-`jti`
  column this reuses already existed for revocation, and the grace window
  is Redis/DB-free (a single in-process `asyncio.sleep` plus the existing
  `sessions` table).
- **Frontend**: `npx tsc -b --noEmit` → 0 errors. No frontend file changed —
  confirmed by inspection that `SessionSocket`'s reconnect handling and
  `SessionProvider`'s `onMessage`/`onEstablished` handlers both already treat
  the reattach case correctly with the message shapes they already handle.
- **Regression check against sections 1-23**: the WS handler's non-refresh
  paths (logout, admin terminate, idle/lifetime sweep, every Module 7
  revoke including the section-23 cascade) all set a real termination
  reason on the session row *before* the socket closes, so they hit the
  `finally` block's unchanged "already ended for a real reason — finalize
  immediately" branch, never the new grace-window branch — none of those
  paths' timing changed at all, only the plain-drop-with-no-prior-cause path
  did.

**Conclusion:** a page refresh no longer means "session over, start fresh."
An ordinary WebSocket drop now gets a short, dedicated window to reconnect
with the same token and reattach to its existing session — keeping its
live, possibly-degraded Module 7 trust score and re-delivering any pending
re-verify challenge — while a genuinely closed tab still loses its session
and ACL within seconds, exactly as before. The specific bypass this closes
(refreshing past an outstanding MFA re-verify) is now fixed at its actual
root cause in Module 3's session-identity model, not patched around in
Module 7. Every prior module and hardening pass remains otherwise intact.
Still ready to proceed to **Module 8 — Security Dashboard**.

---

## 25. Module 8 — Security Dashboard: Implementation + Verification (2026-09-17)

Before starting, re-read `MASTER_PROJECT_CONTEXT.docx` in full (Section 5's
Dashboard Home/Live Session Monitoring/Trust Score Monitoring/Security
Alerts/ACL Monitor/Analytics field lists; Section 9's Module 8 description;
Section 18's own "no admin unlock UI yet ... natural fit for Module 8"
deferral), this `Project status.md` in full (sections 1-24 — the entire
Module 7 build-and-hardening history, since Module 8 aggregates over all of
it), `docs/architecture.md` in full, and every backend/frontend file this
module needed to read from (session/ACL/trust-score/MFA/security-event
models and services, the three existing Redis event-publish call sites, both
lockout modules, `LiveSessions.tsx`/`TrustScorePage.tsx`/`SecurityAlerts.tsx`
for the established admin-page polling pattern, and the still-placeholder
`DashboardHome.tsx`/`Analytics.tsx`/`dashboard.py`) — confirmed against the
actual current code, not any prior description of it. Also confirmed, before
writing anything, that `MASTER_PROJECT_CONTEXT.docx` had been locally edited
(uncommitted) since the last session touched this project — re-extracted and
re-read it fresh rather than trusting a stale copy.

### What was found already built

Most of Module 8's own field list was, in fact, already real by the end of
Module 7's hardening: Live Session Monitoring (`LiveSessions.tsx` — user,
session id, IP, device, login time, duration, trust score, risk level,
WebSocket status, ACL status, and current action are all live), Trust Score
Monitoring (`TrustScorePage.tsx` — score, risk, history, factor breakdown),
Security Alerts (`SecurityAlerts.tsx` — MFA events feed + the Module 7
continuous-evaluation events feed), and ACL Monitor (`ACLMonitor.tsx`) were
each built incrementally by the module that introduced the state they show,
per this project's own "each module produces a working deliverable" sequencing
rule (Section 12). What remained genuinely unbuilt were exactly the two
pieces still rendering `PlaceholderCard` since Module 1 — Dashboard Home and
Analytics — plus the admin lockout-unlock UI explicitly deferred out of
Modules 6/7, and a genuine real-time push channel (every admin page so far
only polls REST on an interval). This section's scope is precisely those
gaps, not a rebuild of pages that were already real.

### What was built

- **`backend/app/services/dashboard/`** (new package, `service.py` +
  `__init__.py`) — pure read aggregation over Modules 2-7's own tables
  (`sessions`, `acl_rules`, `mfa_challenges`, `security_events`) and their
  Redis-backed lockout keys. No FastAPI imports, no new model, no migration —
  this module computes nothing that wasn't already true elsewhere, it only
  reads and counts it.
  - `overview()` — `active_users` (distinct `user_id` with an ACTIVE
    session), `active_sessions` (reuses Module 3's `count_active`),
    `average_trust_score` (reuses Module 5's `average_trust_score(active_only=True)`
    unchanged), `high_risk_sessions` (ACTIVE + `risk_level == HIGH` —
    documented as expected to read near-zero in normal operation, since
    Module 7 revokes a session the instant it crosses into HIGH; a nonzero
    reading is a live health signal, not a steady-state population),
    `mfa_requests_pending` (reuses Module 6's `count_by_status`),
    `revoked_sessions` (sessions terminated specifically `risk_revoked` or
    `account_locked` — deliberately not every termination reason, which
    would dilute the one thing this stat is meant to show), `current_acl_rules`
    + `avg_authorization_latency_ms`/`avg_revocation_latency_ms` (reuse
    Module 4's `count_active`/`average_latencies` unchanged), and
    `locked_out_accounts` (MFA + risk lockouts combined).
  - `analytics(days=14)` — `login_activity` (sessions opened per day, oldest
    first; explicitly does NOT attempt a matching failed-login trend, since
    Module 5's failed-login counter is a 15-minute Redis burst counter with
    no historical Postgres record to chart over multiple days — a metric
    with no real source is not offered, not fabricated, per Section 15's
    "do not build fake data" rule), `trust_score_distribution` (10-point
    buckets, ACTIVE sessions), `risk_levels` (ACTIVE sessions by band),
    `mfa_events` (by status, reusing Module 6's own tally), `revoked_sessions`
    (by termination reason — the full set this time, not narrowed to risk
    like the overview stat above), `security_alerts` (by event type), plus
    the same ACL latency averages.
  - `locked_accounts()` / `clear_lockouts(user_id)` — see the lockout panel
    below.
- **Admin lockout panel — the deferred Module 6/7 unlock UI**:
  - `app/services/mfa/service.py` gained `list_mfa_lockouts(db)` (SCANs
    `ztsaacm:mfa_lockout:*`, checks each key's remaining TTL, joins a
    username/email from Postgres) and `clear_mfa_lockout(user_id)` (deletes
    both the lockout key and the underlying wrong-attempt counter — the
    exact `redis-cli DEL` fallback that module's own docstring already
    documented, now a real function).
  - `app/services/trust_score/risk_lockout.py` gained the mirror pair,
    `list_risk_lockouts(db)` / `clear_risk_lockout(user_id)`, additionally
    surfacing the current escalation `tier` (1/2/3) read back from the
    lockout key's own value. That module's docstring, which previously said
    "No admin unlock UI yet (deliberately deferred)," now points to this
    section instead of describing it as unbuilt.
  - Both scans are bounded and cheap (at most one key per currently-locked
    account at any moment) and are only ever called from the admin
    dashboard's own polling — never a per-request hot path.
  - `GET /dashboard/lockouts` (admin) lists both types together;
    `DELETE /dashboard/lockouts/{user_id}` (admin) clears both for one
    account in a single call, reporting which of the two actually had
    something to clear.
- **`WS /ws/dashboard`** (admin-only) — Section 5's "real-time updates via
  WebSocket" line, which nothing before this module actually implemented
  (every admin page so far only polls REST on a 5-second interval).
  - Discovered while reading `app/services/session/store.py` that its own
    docstring already said `EVENT_CHANNEL` ("`ztsaacm:events:session`") is
    "consumed by Module 8" — confirming this was the intended design all
    along, just never built. Module 4's ACL service and Module 6's MFA
    service already had their own equivalent publish calls
    (`ztsaacm:events:acl`, `ztsaacm:events:mfa`) that likewise had no
    consumer until now.
  - Module 7's own `continuous.py` had no such publish call yet — added one,
    `ztsaacm:events:security`, mirroring the exact same fire-and-forget,
    fail-open pattern the other three already used, called once per
    `record_event()` right after its `security_events` row commits. This is
    the only change this module made to a file outside its own new package/
    endpoint — one new private helper and one new call site, nothing about
    scoring, MFA re-triggering, or revocation logic touched.
  - The handshake reuses `app.ws.auth.resolve_ws_user` (the same JWT +
    revocation check every other socket in this app already uses), plus an
    admin check this socket alone needs (its feed spans every user's
    sessions/events, not just the caller's own).
  - The loop polls `pubsub.get_message(ignore_subscribe_messages=True,
    timeout=0)` (non-blocking) roughly every 0.25s from inside the async
    handler, rather than a background thread bridging a blocking
    `pubsub.listen()` — chosen deliberately to match this codebase's
    existing, established style of making sync Redis/DB calls directly
    inside async WS handlers (e.g. `sessions.py`'s own `session_ws` already
    does this for `session_service` calls) instead of introducing a second
    threading model just for this one socket.
  - **Deliberately additive, never a new source of truth**: every existing
    admin page keeps its REST polling exactly as it was — a live push only
    makes a page refetch sooner than its next scheduled poll tick, it never
    replaces the read. If Redis is ever unreachable, the socket still opens
    and simply never pushes; nothing about the underlying REST-driven pages
    depends on it.
- **Frontend**:
  - `frontend/src/api/dashboard.ts` (new) — typed wrappers for the four REST
    endpoints above.
  - `frontend/src/ws/dashboardSocket.ts` + `useDashboardSocket.ts` (new) —
    a small, capped-backoff-reconnect WS client (deliberately simpler than
    `SessionSocket`: no session lifecycle, purely a "something changed"
    signal) and a hook exposing a `tick` counter a page's own polling effect
    adds to its dependency array.
  - `frontend/src/pages/admin/DashboardHome.tsx` (real, replacing the
    Module-1 placeholder) — Section 5's nine stat cards, plus the new Locked
    Accounts panel (table + per-row Unlock button calling the DELETE
    endpoint), refreshing on its own 5-second poll and on every live push.
  - `frontend/src/pages/admin/Analytics.tsx` (real, replacing the Module-1
    placeholder) — every chart from `analytics()` above, rendered with
    Recharts (already a dependency, first used by Module 5's
    `TrustScorePage.tsx`) — a line chart for login activity, bar charts for
    every other bucketed breakdown, and two plain stat tiles for the ACL
    latency averages.
- **`backend/tests/test_health.py`** — `/dashboard/overview` removed from
  the "still a 501 stub" placeholder-endpoint list (it's real now); the
  still-genuinely-unbuilt `/simulate/ip_change` (Module 9) is the only one
  left in it.

### Tests

`backend/tests/test_dashboard.py` (new, 12 tests):

- **RBAC** — `/dashboard/overview`, `/dashboard/analytics`, and
  `/dashboard/lockouts` (both GET and DELETE) all reject an unauthenticated
  caller (401) and a non-admin user (403).
- **Overview reflects real state** — opening one real session shows
  `active_users`/`active_sessions` == 1 and a real `average_trust_score`;
  driving a session to a direct HIGH crossing (reusing the same
  `_post_event`/`_force_score` pattern `test_continuous_trust.py`
  established) increments `revoked_sessions` and drops `active_sessions`
  back to 0.
- **Analytics shape + content** — `?days=7` returns exactly 7 login-activity
  buckets with today's real session counted in the last one; risk-level
  bucket counts sum to the number of active sessions; after an `ip_change`
  event and its session's eventual disconnect-and-grace-window termination,
  the `security_alerts` breakdown shows exactly one `ip_change` and the
  `revoked_sessions` breakdown shows at least one `websocket_disconnect`.
- **Lockout panel, both types** — trips the Module 6 MFA lockout (mirroring
  `test_mfa.py`'s own trigger pattern) and confirms it's listed with the
  right username and a positive `retry_after_seconds`; DELETE clears it and
  confirms both that it's gone from the listing AND that the account can
  immediately verify a fresh code again (not just hidden, actually cleared).
  Separately drives a session into a direct HIGH crossing (reusing
  `test_continuous_trust.py`'s `_drive_session_into_high`-equivalent setup)
  to trip the Module 7 risk lockout, confirms it's listed with `tier: 1` and
  blocks a login attempt with 423, then confirms DELETE clears it and the
  login attempt no longer returns 423.
- **Dashboard WebSocket** — a non-admin token and a missing token both get
  the handshake rejected with WS close code 1008 (mirroring the exact
  assertion style `test_sessions.py`'s own handshake-rejection tests use);
  an admin connection receives a live, real `security` channel event
  end-to-end after a manual `POST /security/events` call, with the pushed
  payload's `event_type`/`session_id` matching what was actually posted.
  This last test needed one small, deliberate timing allowance (a 200ms
  sleep between opening the dashboard socket and publishing the event) —
  documented in the test itself: a real Redis pub/sub channel (fakeredis
  included) never replays a message published before a subscriber attached,
  so this closes a genuine subscribe-vs-publish race rather than papering
  over a flaky assertion.

### Verification

- **Full backend suite**, run from the project's throwaway
  Python-3.14-compatible virtualenv (see the `dev-env-backend-build` memory
  note): **153/153 passing** — the prior 141 (section 24) plus the 12 new
  tests above, with zero prior tests deleted, skipped, or weakened. The new
  suite passed on its very first full run with no fixes needed afterward.
- **No migration** — confirmed by design, not just by outcome: Module 8
  introduces no new SQLAlchemy model and touches no existing one; `alembic
  current` and the migration chain are unchanged from the end of Module 7
  (head is still `0009_security_event_source`).
- **Regression check against Modules 1-7**: every backend change outside the
  new `dashboard` package/endpoint is strictly additive — two new functions
  each on two pre-existing, independent lockout modules, one new private
  helper + one new call site in `continuous.py`'s `record_event()` (the
  publish, placed after the event's own commit — nothing about the
  scoring/action logic above it was touched), and one line removed from
  `test_health.py`'s placeholder list (because the endpoint it referenced is
  no longer a placeholder). No existing model, schema, endpoint field, or
  prior module's behavior was removed, renamed, or altered.
- **Frontend**: `npx tsc -b --noEmit` → 0 errors. `npm run build` →
  succeeds. `npx oxlint` on every new/changed frontend file → 0 issues
  beyond the same `react(set-state-in-effect)` advisory warning already
  present, unchanged, on every one of this project's pre-existing polling
  admin pages (`LiveSessions.tsx`, `TrustScorePage.tsx`,
  `SecurityAlerts.tsx`) — confirmed by running `oxlint` against those
  existing files too, side by side, before concluding this is pre-existing,
  accepted project style rather than a new issue introduced here.

**Conclusion:** Module 8 — Security Dashboard is implemented per Section 5's
field lists, integrates with Modules 1-7 entirely through composition and
existing Redis publish points rather than new coupling, and does not regress
any prior module — verified by a from-scratch full test run (153/153, first
try), a confirmed absence of any migration, and clean frontend
type-checking, build, and linting. The admin lockout-unlock UI flagged as
deferred at the end of the Module 6/7 hardening passes (sections 17b/18) is
now built, and Section 5's "real-time updates via WebSocket" requirement,
previously unmet by every admin page's REST-only polling, is now genuinely
satisfied by a live, additive push channel. Ready to proceed to
**Module 9 — Attack Simulation**.

---

## 26. Module 8 — Independent Regression Verification (2026-09-17)

Independently re-verified Module 8 (section 25's own build) against
`MASTER_PROJECT_CONTEXT.docx` Section 5's field lists, this `Project
status.md` file (sections 1-25) as the "as implemented" record, and the
actual code in the repo — not just section 25's own claims. Method:
connected directly to the developer's machine (git history + working tree),
diffed the isolated `Module 8: Security Dashboard` commit
(`36d1cb4`) against its direct parent to see exactly what that commit
touched (as opposed to the wider range that also includes the unrelated,
already-landed section 23/24 hardening commits it was built on top of), read
every backend/frontend file that diff touched, reinstalled the backend into
a clean virtualenv and re-ran the full suite twice, ran the frontend
TypeScript compiler/build/linter, and confirmed the local `main` branch is
in sync with `origin/main`.

**Requirements checklist (MASTER_PROJECT_CONTEXT.docx Section 5, Module 8's field list):**

| Area | Verified |
|---|---|
| Dashboard Home stat cards | Yes — `GET /dashboard/overview`, real aggregates (`dashboard_service.overview`) over Modules 2-7's own tables/Redis state, no synthetic data |
| Analytics (login activity, trust-score distribution, MFA events, revoked sessions, security alerts, risk levels, authorization/revocation latency) | Yes — `GET /dashboard/analytics`, one real bucket list per chart; a would-be multi-day failed-login trend is honestly omitted rather than fabricated (no historical Postgres record exists for it), matching Section 15's "do not build fake data" instruction |
| Live Session Monitoring / Trust Score Monitoring / Security Alerts / ACL Monitor | Confirmed already real prior to Module 8 (built incrementally by Modules 3-7 per this project's own sequencing rule) — section 25 correctly scoped its own work to the two still-placeholder pages plus the deferred lockout UI, not a rebuild |
| Real-time updates via WebSocket | Yes — new admin-only `WS /ws/dashboard` forwards the four Redis pub/sub channels (session/ACL/MFA/security) that already existed or were given one (`security`, added here) to any open admin dashboard page; purely additive on top of each page's existing REST polling, never a replacement data path |
| Admin lockout visibility/recovery (deferred from sections 17b/18) | Yes — `GET /dashboard/lockouts` + `DELETE /dashboard/lockouts/{user_id}`, backed by real `list_/clear_mfa_lockout` and `list_/clear_risk_lockout` functions added to the two pre-existing lockout modules |

**Isolated-commit diff review (`git diff 36d1cb4^..36d1cb4`, 19 files,
1974(+)/71(-)):** every backend file touched is either wholly new
(`app/services/dashboard/__init__.py`, `service.py`,
`app/api/v1/endpoints/dashboard.py`, `app/schemas/dashboard.py`,
`backend/tests/test_dashboard.py`) or a small, additive change to an
existing one — `app/services/mfa/service.py` and
`app/services/trust_score/risk_lockout.py` each gained exactly two new
functions (`list_*_lockouts` / `clear_*_lockout`) and nothing else in either
file changed; `app/services/trust_score/continuous.py` gained one private
publish helper and one call site inside `record_event()`, placed after the
`security_events` row's own commit, with no line above it touched (scoring,
MFA re-trigger, and revoke logic are byte-for-byte unchanged — confirmed by
reading the diff, not just trusting the docstring's claim); `test_health.py`
lost exactly the one line asserting `/dashboard/overview` is still a 501
stub, correctly, since it no longer is. No Module 1-7 model, schema, or
endpoint field was removed, renamed, or had its behavior altered. No new
Alembic migration exists in this commit — confirmed independently via
`alembic history`, whose head is still `0008_continuous_trust_evaluation ->
0009_security_event_source`, unchanged since section 22.

**Full backend suite**, reinstalled from scratch into a throwaway virtualenv
(`requirements.txt`, Python 3.10) and run twice independently:

- Run 1: **152 passed, 1 failed** — `tests/test_trust_score.py::test_user_trust_history`
  failed with `assert False` on `all(e["trust_score"] is not None for e in
  hist["entries"])`.
- Isolated re-run of just `test_trust_score.py` on its own: **12/12
  passing**, including that same test — confirming the failure is
  order-dependent, not a deterministic defect.
- Run 2 (full suite again, no code change in between): **153/153 passing**,
  including `test_user_trust_history`.
- **Conclusion on this test**: a pre-existing, order-dependent flake in the
  same family already documented in section 22 ("an isolated regression
  check... confirmed to fail identically in isolation... a pre-existing
  order-dependent flake unrelated to this change"), just manifesting in the
  opposite direction here (failed once inside the full run, passed both in
  isolation and on a clean re-run of the full suite) — consistent with a
  timing-sensitive interaction involving the async reconnect-grace-window
  background task (section 24) rather than a deterministic bug. Not caused
  by Module 8: `test_user_trust_history` and every file it exercises
  (`trust_score` history, `session` service) are outside Module 8's own
  diff, and section 25's own single clean run (153/153) did not hit it,
  which is exactly what "order-dependent, not deterministic" predicts.
  Flagged here for the record rather than silently ignored, per this
  project's own "report outcomes faithfully" standard — worth a
  `pytest-randomly` bisect or an explicit `-p no:randomly`/fixed seed
  re-run if it starts showing up more often, but not blocking Module 8.
- Zero prior tests were deleted, skipped, or weakened to reach either
  passing run.

**Frontend:**

- `npx tsc -b --noEmit` → 0 errors.
- `npm run build` (in place) failed with `EPERM: operation not permitted,
  unlink .../dist/assets/...` while clearing the pre-existing `dist/`
  output directory — a file-permission artifact of this verification
  session's sandboxed access to the developer's machine, not a code defect.
  Confirmed by building to a scratch output directory instead
  (`vite build --outDir /tmp/verify_dist --emptyOutDir`): **688 modules
  transformed, build succeeds**, same single pre-existing "chunk larger than
  500 kB" advisory warning already flagged in prior sections, nothing new.
  The `@rolldown/binding-linux-x64-gnu` native-binding error noted in
  earlier Module 4/6 verifications also reappeared on first attempt in this
  session's environment and was resolved the same documented way (`npm
  install` after the fact, without clearing `node_modules`/`package-lock.json`
  first) — environment-specific, not a Module 8 regression.
- `npx oxlint` on every Module 8 file (`DashboardHome.tsx`, `Analytics.tsx`,
  `dashboardSocket.ts`, `useDashboardSocket.ts`, `api/dashboard.ts`,
  `types/index.ts`) → 0 errors, 4 `react(set-state-in-effect)` advisory
  warnings. Independently confirmed these are pre-existing, accepted project
  style rather than new: running the same lint rule against
  `LiveSessions.tsx`, `TrustScorePage.tsx`, `SecurityAlerts.tsx`, and
  `ACLMonitor.tsx` (all pre-Module-8) trips the identical warning on the
  identical `load()`-in-`useEffect` polling pattern.
- No mock/fabricated data found in `DashboardHome.tsx`, `Analytics.tsx`, or
  `dashboard/service.py` — every figure traces to a real query or a reused
  Module 2-7 service call; grepped for `mock`/`fake`/`dummy`/`hardcod` across
  all of Module 8's own files with no hits.

**Repo/deployment hygiene:**

- `git status` shows the local `main` branch up to date with `origin/main`
  (no unpushed local commits); the merge commit
  `2892185 Merge branch 'module-8-security-dashboard' into main` is present
  in history on both.
- The working tree does show ~97 files as modified with a
  15,583(+)/15,583(-) `git diff --shortstat` — confirmed with `git diff
  --ignore-all-space` (empty) to be 100% line-ending churn (LF/CRLF) on this
  Windows checkout, the same pre-existing, harmless condition this file's
  own section 9 housekeeping note first flagged — not a Module 8 issue and
  not new.
- `backend/.env` (which carries the real Gmail SMTP App Password) is
  correctly gitignored and was not part of any commit.
- `backend/app/api/v1/endpoints/simulation.py` (Module 9) has zero diff
  across the entire Module 8 commit — confirmed no scope creep into the
  next module.

**Conclusion:** Module 8 — Security Dashboard, as built and documented in
section 25, is independently confirmed genuinely implemented per Section 5's
field lists, introduces no fabricated/mock data anywhere, adds no new
migration, and does not regress any prior module — every file it touched
outside its own new package/endpoint is strictly additive, and the full
backend suite passes (153/153) with the one observed failure traced to a
pre-existing, order-dependent flake outside Module 8's own diff, not a
Module 8 defect. Frontend type-checks, builds, and lints clean, with the two
build hiccups encountered here (`dist/` permissions, the rolldown native
binding) both confirmed to be artifacts of this verification session's
environment rather than the code. No regression to Modules 1-7 was found.
Ready to proceed to **Module 9 — Attack Simulation** with no known gap
blocking it.

## 27. Module 7 Hardening — Automatic `multiple_failed_logins` Detection (2026-09-17)

**Why:** while explaining to the project owner how to independently verify
the `multiple_failed_logins` alert, the honest answer turned out to be "you
currently can't — it's the one event type in the whole Module 7 catalogue
that only ever fires from the admin's manual `POST /security/events`
Trigger button." Every other event type by this point (Section 18's
heartbeat detectors, the request-rate redesign, the cascading-lockout and
reconnect-reattach hardening above) had a real, automatic detector sitting
behind it; this one didn't, even though the underlying signal — Module 5's
own failed-login burst counter — already existed and was already being
computed on every `POST /auth/login` failure. The project owner
specifically pushed back on this: *"login attempts is checked only during
authentication right and we already have a condition for that then why do
we have to implement this condition since its just a manual one?"* — a fair
critique of the pre-existing state, since a manual-only event has zero
actual protective value; it only demonstrates that the scoring pipeline
*can* react to this event type if told to. The concrete gap: **an attacker
guessing a live user's password produced no live signal on that user's own
already-open session anywhere**, unlike a real IP/device change, which
Section 18 already makes visible to an open session within ~20 seconds.
After confirming the project owner wanted this built — "yes i want you to
implement the dynamic functionality of the above alert without removing the
existing manual option in the admin panel" — this section is that build,
following the exact precedent Section 18 itself set: add the automatic
detector *alongside* the manual path, never replacing it.

**Design — reuse the existing counter, don't build a second one:**
`backend/app/services/trust_score/store.py`'s `ztsaacm:failed_logins:
{user_id}` key (`INCR` + refresh-TTL on every failed login against a known
username, 15-minute window, `trust_failed_login_threshold`) has existed
since Module 5, purely to compute the `-15` login-time scoring penalty on
the *next* successful login. This hardening does not add a parallel
counter; it reads that exact same key mid-burst and, the first time it's
observed at/over threshold within a window, treats that as the trigger to
fire a mid-session event — the identical "reuse an existing signal instead
of inventing a new one" discipline this project has followed since Section
18's `abnormal_request_rate` redesign.

**Fire-once-per-window guard:** a new Redis key,
`ztsaacm:failed_logins_fired:{user_id}`, set (via a plain existence check,
not a real Redis `NX`, since this project's fail-open convention already
tolerates the narrow race) the first time the burst counter crosses
threshold, carrying the *counter's own remaining TTL* so the two expire
together. `store.check_and_mark_burst_fired(user_id) -> bool` is the single
new function this required — returns `True` exactly once per window,
`False` on every attempt before or after that one. This is a byte-for-byte
structural copy of `request_rate.py`'s pre-existing
`check_and_mark_fired` for `abnormal_request_rate`, for the identical
reason: without it, the 4th, 5th, 6th, ... wrong password inside the same
15-minute window would each independently re-fire the mid-session event
again, spamming every open session with duplicate alerts for what is really
one ongoing burst. `clear_failed_logins(user_id)` (used by tests and any
future manual-unlock path) now clears both keys together.

**Where it hooks in — `record_failed_login_attempt`, already the sole
caller from `/auth/login`:** `trust_score/service.py`'s
`record_failed_login_attempt(db, username=...)` already ran on every
`InvalidCredentialsError` inside `POST /auth/login`, purely to `INCR` the
counter. It now, immediately after that increment, calls
`store.check_and_mark_burst_fired(user.id)`; on `True`, it looks up every
currently ACTIVE session on that account via
`app.services.session.store.active_session_ids_for_user(user.id)` — the
same per-user Redis index `request_rate.py` already reuses for its own
cross-endpoint attribution — and calls the completely unmodified
`continuous.record_event(db, session_id=..., event_type=
MULTIPLE_FAILED_LOGINS, source=SecurityEventSource.AUTO)` against **each**
one, not just one arbitrarily chosen session, since an attacker guessing a
password has no way to know (and this system has no reason to guess) which
of the account's open tabs, if any, is the "right" one to warn. A
`SessionNotFound`/`SessionNotActive` on any individual session (a benign
Redis/Postgres drift — the session finished closing in the moment between
the index read and the DB call) is skipped, not raised, so one stale index
entry can never turn a failed-login attempt into a 500 for the *attacker's*
own request. The function's return type changed from `None` to
`list[ContinuousEvalResult]` — empty in the ordinary case (unknown
username, below threshold, already fired this window, or no active session
anywhere on the account) — mirroring the shape every other
`continuous.record_event` call site already returns to its own caller.

**`POST /auth/login` becomes `async`:** pushing each returned
`ContinuousEvalResult` over its session's live WebSocket requires an
`await`, so `login()` in `auth.py` changed from a sync `def` to `async def`
— the same, already-precedented reason Section 16 made `verify_mfa` async.
Nothing else about the endpoint's signature, request/response shape, or
status codes changed. The push itself reuses the exact helper the manual
admin Trigger and the Section 18 heartbeat detector already shared,
renamed from the module-private `_push_result` to the importable
`push_continuous_result` (`security.py`) specifically so `auth.py` could
call it too — a rename only; its logic is untouched.

**The manual admin path is provably untouched:** `POST /security/events`
with `event_type=multiple_failed_logins` still calls
`continuous.record_event(..., source=SecurityEventSource.ADMIN)` exactly as
it always has — no branch, condition, or line inside `ingest_security_event`
changed. A dedicated regression test
(`test_manual_multiple_failed_logins_event_still_works`) asserts this path
end to end, checking specifically for `source == "admin"` in the response,
to guard against ever conflating the two paths later.

**What this looks like end to end (plain terms, as explained to the
project owner):** if someone tries to log into a live user's account and
gets the password wrong repeatedly, the moment that burst crosses the same
threshold Module 5 already used for the login-time penalty, every browser
tab that user currently has open elsewhere gets hit with the identical
`multiple_failed_logins` scoring event a manual admin Trigger would have
produced — same score drop, same risk-band re-evaluation, and (if that
push crosses into HIGH) the same revoke-and-cascade-lockout behavior
Section 23 already built. If the burst happens to push a session across
into HIGH, the account is locked out of future logins for the same tiered
window Section 18's account-lockout hardening already established — no new
policy, just a new, automatic path into policy that already existed.

**Tests:** six new tests in `backend/tests/test_continuous_trust.py`:

- `test_failed_login_burst_auto_fires_against_the_accounts_active_session`
  — three bad passwords against a user with one open session; asserts the
  session's live score drops by the documented weight and the push carries
  `source="auto"`.
- `test_failed_login_burst_auto_fires_against_every_active_session_on_the_account`
  — the same burst with **two** active sessions open on the account (two
  browsers, via the existing `_second_token_for` helper) — both get hit,
  not just one.
- `test_failed_login_burst_auto_detection_fires_only_once_per_window` —
  a fourth and fifth bad password past the threshold, still inside the same
  window, produce no further event (the fire-once guard).
- `test_failed_login_burst_with_no_active_session_is_a_harmless_noop` — the
  same burst against a user with nothing open anywhere: still a plain 401,
  nothing else happens, no error.
- `test_failed_login_burst_direct_high_crossing_cascades_and_locks_the_account`
  — one session forced to a MEDIUM score close enough to the HIGH boundary
  that the burst's own penalty crosses it: confirms the automatic path
  revokes that session, cascades `account_locked` to the account's *other*
  active session (Section 23's machinery, reused unmodified), and that a
  subsequent login attempt correctly returns `423`/`risk_locked`.
- `test_manual_multiple_failed_logins_event_still_works` — the explicit
  regression guard for the pre-existing admin Trigger path described above.

Full backend suite, run twice (isolated file, then the complete suite):
**32/32** in `test_continuous_trust.py` alone, **159 passing** overall (153
prior, per section 26's verification, + 6 new) — no regressions, including
no recurrence of the pre-existing order-dependent `test_user_trust_history`
flake noted in section 22/26 (it passed cleanly in both runs this session).
No migration — this is Redis/service-layer only, no schema or model
changed. `frontend` unaffected: no request/response contract changed on
`POST /auth/login`, and the pushed WebSocket message shapes
(`trust.updated` / `trust.reverify_required` / `session.terminated`) are
byte-for-byte identical regardless of which caller produced the
`ContinuousEvalResult`, so no frontend file needed a change and none was
made.

**Files touched:** `backend/app/services/trust_score/store.py` (new
`_fired_key`/`check_and_mark_burst_fired`, `clear_failed_logins` extended),
`backend/app/services/trust_score/service.py`
(`record_failed_login_attempt` extended, now returns
`list[ContinuousEvalResult]`), `backend/app/api/v1/endpoints/security.py`
(`_push_result` renamed to the importable `push_continuous_result`, no
behavior change), `backend/app/api/v1/endpoints/auth.py` (`login` made
`async`, pushes the new results before raising its 401), `backend/tests/
test_continuous_trust.py` (+6 tests), `docs/architecture.md` (new section),
this file (this section).

---

## 28. Module 9 — Attack Simulation: Implementation + Verification (2026-09-18)

Before starting, re-read `MASTER_PROJECT_CONTEXT.docx` in full (Section 5's
eight named "Simulate ..." buttons; Section 6's "Attack Simulation — VPN
buttons" note — two independent, self-contained buttons, not a generic VPN
toggle; Section 9's Module 9 description, which explicitly keeps the
existing admin "Trigger" control and Module 9's own buttons side by side
with the Section 18 automatic detectors, not as competitors; Section 15's
"these should trigger the actual backend logic rather than simply changing
text on the UI" instruction), this `Project status.md` in full (sections
1-27 — every Module 7 hardening pass through the 2026-09-17 automatic
`multiple_failed_logins` detector, since Module 9 needed to know exactly
which mechanisms were already real before deciding what to reuse),
`docs/architecture.md` in full, and every backend/frontend file this module
needed to read from or extend (`continuous.py`, `trust_score/service.py`,
`session/service.py`, `security.py`'s `push_continuous_result`, the
still-placeholder `simulation.py`/`AttackSimulation.tsx`, and
`LiveSessions.tsx`'s existing per-row "Simulate (Module 7)" control, to
avoid duplicating or conflicting with it) — confirmed against the actual
current code, not any prior description of it. Also re-confirmed the
current git log and working-tree state before starting, since multiple
other sessions had pushed directly to `origin/main` (including two more
docx re-uploads and the section-26/27 work) since this session's own last
turn.

### What was built

- **`backend/app/services/simulation/`** (new content in a package whose
  empty `__init__.py` had existed since Module 1's original scaffold) —
  `service.py` is a thin, admin-only dispatch layer with no scoring/
  revocation logic of its own:
  - `SimulationScenario` — the eight scenario keys + their Section-5
    display labels: `ip_change`, `approved_vpn`, `unknown_vpn`,
    `unknown_device`, `large_download`, `abnormal_requests`,
    `failed_login`, `session_termination`.
  - `run_scenario(db, scenario, session_id)` — looks up the target session
    (404 if unknown, 409 if not ACTIVE) and dispatches:
    - Six scenarios call `continuous.record_event()` — the exact function
      the pre-existing manual admin Trigger (`POST /security/events`,
      Module 7) already calls — with the matching `SecurityEventType` and
      `source=admin`.
    - `approved_vpn` / `unknown_vpn` additionally call a new
      `pick_sample_ip()` helper, which returns the first usable host
      address in the first configured CIDR block
      (`trust_approved_vpn_cidrs` / `trust_known_vpn_cidrs` respectively) —
      so the admin picks a scenario, not an IP, per Section 6's own framing
      of these as two complete, self-contained buttons rather than a
      generic VPN toggle needing a typed address.
    - `ip_change` uses a fixed constant, `203.0.113.10` (RFC 5737
      TEST-NET-3, a documentation-reserved range), deliberately chosen
      outside both configured VPN CIDR lists so it always classifies as a
      plain `ip_change` and never gets accidentally reclassified as
      `vpn_detected` by `continuous.classify_event`.
    - `failed_login` calls `trust_score_service.record_failed_login_attempt()`
      — the REAL Section 27 detector — `trust_failed_login_threshold` times
      in a row against the target session's own username, deterministically
      crossing the real Redis burst counter's threshold every time (a tight
      loop within one request has no unpredictable prior-state dependency,
      unlike the heartbeat detector's "last observed" comparison — see the
      design note below). Hits every currently ACTIVE session on the
      account, not just the one selected in the admin UI, exactly matching
      what a genuine password-guessing burst would do; tagged `source=auto`
      in the audit trail since it is genuinely running the automatic
      detector, not injecting a synthetic event.
    - `session_termination` calls `session_service.terminate_session(reason=
      TerminationReason.ADMIN_TERMINATED)` — the identical call
      `DELETE /sessions/{id}` already makes.
  - `scenario_catalogue()` — the live scenario → label table (mirrors
    `trust_score.factor_catalogue` / `mfa.mfa_config` /
    `continuous.event_catalogue`'s existing "live reference, not a
    hardcoded doc" pattern), so the frontend renders its eight buttons from
    one source of truth instead of a duplicated hardcoded list.
- **Design decision, recorded explicitly**: five of the eight scenarios
  (`ip_change`, `approved_vpn`, `unknown_vpn`, `unknown_device`,
  `abnormal_requests`) call `continuous.record_event()` directly rather
  than routing through the Section 18 heartbeat/request-rate detectors,
  even though those are now real for these exact event types. Reasoning: a
  polished, always-reliable demo control cannot assume a real heartbeat has
  already seeded that session's "last observed" Redis state — if it hasn't,
  the heartbeat detector would silently seed-and-fire-nothing on its first
  call, making a "Simulate IP Change" button appear to do nothing on a
  freshly opened session. Calling `continuous.record_event()` directly is
  deterministic regardless of timing, and is exactly what the pre-existing
  manual admin Trigger already does — so these five scenarios are precisely
  that path with a friendlier name (and, for the two VPN buttons, an
  automatically chosen IP). `failed_login` is the one exception because its
  real detector (a plain Redis counter with a fixed threshold) has no such
  timing dependency — a tight loop deterministically crosses it every time
  — so it safely reuses the real mechanism end to end for a strictly more
  faithful simulation instead of a shortcut.
- **New schemas** (`app/schemas/simulation.py`): `SimulationRequest`
  (`session_id`), `SimulationResultOut` (a superset covering both the six
  continuous-evaluation scenarios' score/risk/action fields — mirroring
  `SecurityEventResultOut` — and `session_termination`'s `state`/
  `termination_reason` fields, with whichever set doesn't apply left null),
  `SimulationScenarioOut` / `SimulationScenariosResponse`.
- **New endpoints** (`app/api/v1/endpoints/simulation.py`, replacing the
  Module 1 `501` stub): `GET /simulate/scenarios` (admin), `POST
  /simulate/{scenario}` (admin; body `{"session_id": ...}`) — 400 on an
  unknown scenario, 404/409 on an unknown/inactive session. Reuses
  `security.py`'s `push_continuous_result` (already made importable, not
  module-private, during section 27's work) for the async WebSocket push
  every continuous-evaluation-producing scenario needs, and pushes the
  session-termination message inline for `session_termination` — the exact
  same message `DELETE /sessions/{id}` sends, in the same pre-close order.
- **`failed_login` pushes to every affected session's own socket, not just
  the selected one**: `SimulationOutcome` carries both a primary
  `continuous_result` (matching the session the admin picked) and an
  `other_results` list (every other active session on the account the real
  detector also hit); the endpoint pushes all of them. Caught by writing
  the first multi-session test for this scenario, before it shipped: an
  earlier draft only returned/pushed the primary result, which would have
  silently left a second open browser tab on the same account never
  finding out its score had also just dropped — a divergence from what the
  real Section 27 mechanism actually does when a genuine burst occurs, not
  a cosmetic gap.
- **Frontend**: `frontend/src/api/simulation.ts` (new) wraps both endpoints.
  `frontend/src/pages/admin/AttackSimulation.tsx` (a disabled-placeholder
  page since Module 1) is now real: a target-session picker (polling active
  sessions the same way `TrustScorePage.tsx` already does), all eight
  scenario buttons rendered from the live catalogue, and a "Recent results"
  table showing each run's actual before/after score, risk-band
  transition, and resulting action or termination state — not just a
  success toast. Deliberately left `LiveSessions.tsx`'s own pre-existing
  per-row "Simulate (Module 7)" dropdown completely untouched: that one
  remains a quick single-event tester for any of Module 7's six event
  types from within the sessions table itself; this page is Section 5's
  actual eight named scenarios (including the VPN split and the two
  scenarios — `failed_login`, `session_termination` — the Live Sessions
  control never offered), as its own dedicated surface.
- **`backend/tests/test_health.py`** — its placeholder-501 test, which had
  checked `POST /api/v1/simulate/ip_change`, no longer has a target
  endpoint to check (the route is real now); renamed to
  `test_no_placeholder_endpoints_remain` and repointed at a smoke check
  that the once-placeholder route is now real and auth-gated (401 without
  credentials) rather than simply deleting the coverage.

### A real bug caught before shipping, not after

The very first test run failed every single test in the new suite with
`AttributeError: module 'app.services.simulation' has no attribute
'UnknownScenario'` — despite that class visibly existing in the file on
disk. Root cause: `app/services/simulation/__init__.py` had existed as an
empty file since Module 1's original project scaffold (every module's
service package got an empty placeholder directory at setup time, the same
pattern `app/services/dashboard/` was filled into for Module 8), but this
module's first draft was written as a flat `app/services/simulation.py`
file sitting alongside that empty package directory. Python's import
system resolves a same-named package over a plain module in that
situation, so `app.services.simulation` silently bound to the empty
package, not the new file — every class/function in the file was
unreachable at runtime even though it imported without error. Fixed before
ever running against a clean environment a second time: moved the
implementation into `app/services/simulation/service.py` and populated the
existing `__init__.py` to re-export its public API, matching every other
module's own package layout exactly. Recorded here because it is a genuine
"looked right, wasn't" class of bug worth remembering — an `ls`/`find`
check for a same-named directory before creating a new top-level service
module would have caught it before writing a line of logic into the wrong
file.

### Tests

`backend/tests/test_simulation.py` (new, 16 tests):

- **RBAC** — `GET /simulate/scenarios` and `POST /simulate/{scenario}` both
  reject an unauthenticated caller (401) and a non-admin user (403).
- **Catalogue** — `GET /simulate/scenarios` lists exactly the eight
  expected scenario keys, including both VPN buttons and Session
  Termination, with human-readable labels.
- **Validation** — an unknown scenario name is a 400; a nonexistent session
  is a 404; a session that has already ended (including waiting out the
  2026-09-16 reconnect-grace window for an ordinary disconnect, not just an
  explicitly-terminated one) is a 409.
- **Each of the eight scenarios' real effect** — `ip_change`,
  `unknown_device`, `large_download`, `abnormal_requests` each assert the
  session's score actually moved by the exact configured weight;
  `approved_vpn` / `unknown_vpn` assert the automatically-picked IP
  classifies correctly (positive weight and an "approved" reason string
  for one, the configured negative weight for the other) with no IP
  supplied by the caller; `failed_login` (with two active sessions open on
  the account, via the same `_second_token_for` direct-mint technique
  `test_continuous_trust.py` already established) asserts BOTH sessions'
  scores drop by the real weight, both receive their own live
  `trust.updated` push, `source=auto` is recorded on both resulting
  `security_events` rows, and a second `failed_login` simulate call inside
  the same window produces no further event (the real fire-once guard);
  `session_termination` asserts the session's real state/termination
  reason, its own `session.terminated` push, and — the same depth of check
  section 23's cascading-lockout test established — that the session
  owner's original access token is genuinely revoked afterward (`GET
  /auth/me` → 401), not just that the row shows `terminated`.
- **Full-pipeline integration check** — an `abnormal_requests` simulation
  that crosses a session from MEDIUM into HIGH is confirmed to drive the
  exact same revoke-and-account-lockout pipeline every other Module 7
  trigger already does (a subsequent login attempt for that account
  correctly returns 423), proving Module 9's scenarios are genuinely
  running through the real pipeline end to end, not a simplified parallel
  path.

### Verification

- **Full backend suite**, run from the project's throwaway
  Python-3.14-compatible virtualenv: **175/175 passing** — the prior 159
  (section 27) plus the 16 new tests above, with zero prior tests deleted,
  skipped, or weakened. `test_simulation.py` alone: 16/16, confirmed
  isolated and in the full run.
- **No migration** — confirmed by design: Module 9 introduces no new
  SQLAlchemy model and touches no existing one; the migration chain's head
  is unchanged since Module 8 (`0009_security_event_source`).
- **Regression check against Modules 1-8**: every change outside the new
  `simulation` package/endpoint/schema is either a rename with no behavior
  change (`test_health.py`'s placeholder test) or genuinely new, additive
  code. No existing model, schema, endpoint field, or prior module's
  behavior was removed, renamed, or altered; `LiveSessions.tsx`'s own
  Module 7 simulate control has zero diff.
- **Frontend**: `npx tsc -b --noEmit` → 0 errors. `npm run build` →
  succeeds. `npx oxlint` on every new/changed frontend file → 0 errors, one
  `react(set-state-in-effect)` advisory warning on `AttackSimulation.tsx`'s
  own `load()`-in-`useEffect` polling pattern — the same pre-existing,
  accepted warning every other polling admin page already carries
  (confirmed again here, as in sections 25/26, by checking it trips on
  those pages identically).

**Conclusion:** Module 9 — Attack Simulation is implemented per Section 5's
eight named scenarios and Section 6's VPN-button framing, triggers real
backend logic for every single one (per Section 15's explicit instruction —
grepped the new files for `mock`/`fake`/`dummy`/`hardcod` with no hits
beyond the deliberate, documented `203.0.113.10` simulation constant),
integrates with Modules 3/5/7 entirely through direct reuse of their
existing real functions, and does not regress any prior module — verified
by a from-scratch full test run (175/175), a confirmed absence of any
migration, and clean frontend type-checking, build, and linting. A genuine
packaging bug (a same-named package/module collision) was caught and fixed
before ever shipping, not discovered later. Ready to proceed to
**Module 10 — Testing & Evaluation**.
