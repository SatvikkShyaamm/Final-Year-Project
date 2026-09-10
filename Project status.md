# PROJECT STATE

## 1. Current Status

Current Module: Module 7 – Continuous Trust Evaluation (next)
Overall Project Status: Core base-paper flow complete (Modules 1-4) + static
Trust Score (Module 5) + risk-gated Adaptive MFA at login (Module 6), plus a
post-Module-6 hardening pass closing the server-side token-revocation and
cross-tab storage gaps found during live testing.
Modules 7-10 not started.

|         Module                         |              Status          |
|----------------------------------------|------------------------------|
| Module 1 – Project Foundation          | Completed                    |
| Module 2 – Authentication              | Completed                    |
| Module 3 – Session Lifecycle           | Completed                    |
| Module 4 – Dynamic ACL                 | Completed & independently verified |
| Module 5 – Trust Score Engine          | Completed                    |
| Module 6 – Adaptive MFA                | Completed & independently verified |
| Module 7 – Continuous Trust Evaluation | Not started                  |
| Module 8 – Security Dashboard          | Not started                  |
| Module 9 – Attack Simulation           | Not started                  |
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
- Adaptive MFA: TOTP (pyotp / RFC 6238), risk-band gated at `POST /auth/login` (Module 6)
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
