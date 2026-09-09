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
Score** at the S1→S2 transition (Module 5 — implemented), an Adaptive MFA
policy that will *gate* that transition based on the score's risk band
(Module 6 — not yet built), and Continuous Trust Evaluation that keeps
recalculating the score during S2 and can force the same S2→S3
revocation path the base paper already defines (Module 7) — it does not
invent a new FSM state.

Module 5 as implemented deliberately does **not** gate S1→S2: the session
still opens unconditionally, the score is computed by a `session_opened`
hook and stored (`sessions.trust_score` / `sessions.risk_level` +
`trust_score_factors` breakdown), and it is informational until Module 6
reads the risk band and turns it into allow / require-MFA / block.

## Mapping paper concepts -> this codebase

| Paper concept        | This codebase (from the module that implements it)         |
|-----------------------|--------------------------------------------------------------|
| SS-PDP                | `backend/app/ws/` + `app/api/v1/endpoints/sessions.py` (M3) + `app/api` auth (M2) + `app/services/acl/service.py` task producer (M4) |
| L-PEP                 | `app/services/acl/worker.py` (in-process) / `app/lpep/` (standalone) + `infra/l-pep/` + `app/services/acl/enforcer.py` (ipset vs simulated) (Module 4) |
| Intermediate layer     | Redis — session active-set + `ztsaacm:events:session` (M3); ACL task queue `ztsaacm:acl:tasks` + ref-counts + receipts + `ztsaacm:events:acl` (M4). Postgres stays source of truth for both |
| FSM S0->S1 (`auth_success`) | Module 2 (Authentication)                              |
| FSM S1->S2 (`session_open`) | Module 3 — WebSocket connect creates the `sessions` row; the `session_opened` hook fires Module 4's `request_acl_for_session` **and** Module 5's `evaluate_for_session` (compute + store the static trust score). Module 6 will *gate* the transition on the risk band |
| FSM S2->S3 (`session_close`)| Module 3 — `terminate_session` (ws drop / logout / admin / idle+lifetime sweep); the `session_closed` hook fires Module 4's `remove_acl_for_session`. Additionally triggered by Module 7 on unacceptable risk |
| Trust Score            | `backend/app/services/trust_score/` (Module 5) — `evaluator.py` implements the finalized Section-6 formula `clamp(70 + Σ+ - Σ-, 0, 100)`; config-driven weights; `sessions.trust_score`/`risk_level` + `trust_score_factors` audit rows; Redis `ztsaacm:failed_logins:{user_id}` (15-min TTL) fed from `POST /auth/login` failures |
| Adaptive MFA            | `backend/app/services/mfa/` (Module 6)                        |
| Continuous evaluation   | Composition of trust_score + mfa + acl services (Module 7), no separate service package |

## Module -> folder map (Module 1 baseline)

```
backend/app/api/v1/endpoints/   one file per module's REST surface (+ the WS route in sessions.py)
backend/app/api/deps.py          shared deps: get_db, get_current_user, get_current_admin (Module 2)
backend/app/core/security.py     password hashing + JWT primitives (Module 2)
backend/app/services/            one sub-package per module (auth/ M2, session/ M3, acl/ M4, trust_score/ M5)
backend/app/services/session/hooks.py   session_opened/closed callback registry — how M4 (ACL) and M5 (trust score) react without the session layer importing them
backend/app/services/trust_score/       evaluator (Section-6 algo) + factors + history + store (Redis) + service + wiring
backend/app/models/              one file per module (user M2, session M3, acl M4, trust_score M5)
backend/app/ws/                  connection_manager.py + handshake auth.py (Module 3)
backend/app/lpep/                `python -m app.lpep` — standalone L-PEP worker (Module 4)
frontend/src/auth/               token store, AuthProvider, useAuth, ProtectedRoute (Module 2)
frontend/src/session/            SessionProvider, useSession (Module 3)
frontend/src/ws/socket.ts        SessionSocket signalling client (Module 3)
frontend/src/pages/admin/        one page per Module 8 dashboard section
infra/l-pep/                     setup-ipset.sh + run notes for the standalone L-PEP (Module 4)
```

Status: Modules 1-5 implemented. The core base-paper flow works end to end and
every session carries a static trust score. The SS-PDP's "JWT verification" is
`app/core/security.decode_access_token` (REST `get_current_user` M2 /
`app/ws/auth.resolve_ws_user` M3). Session, ACL, and trust-score state all live
in Postgres (authoritative); Redis is the intermediate layer — session
active-set + events (M3), ACL task queue + ref-counts + receipts + events (M4),
failed-login burst counter (M5).

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
