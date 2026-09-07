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
`ipset add`/`del` executor). Our extension inserts a Trust Score at the
S1→S2 transition (Module 5), an Adaptive MFA policy that gates that
transition based on the score (Module 6), and Continuous Trust
Evaluation that keeps recalculating the score during S2 and can force
the same S2→S3 revocation path the base paper already defines
(Module 7) — it does not invent a new FSM state.

## Mapping paper concepts -> this codebase

| Paper concept        | This codebase (from the module that implements it)         |
|-----------------------|--------------------------------------------------------------|
| SS-PDP                | `backend/app/ws/` + `app/api/v1/endpoints/sessions.py` (M3) + `app/api` auth (M2) |
| L-PEP                 | `infra/l-pep/` + `backend/app/services/acl/` (Module 4)       |
| Intermediate layer     | Redis — active-session index + `ztsaacm:events:session` pub/sub in `app/services/session/store.py` (Module 3); Postgres stays source of truth |
| FSM S0->S1 (`auth_success`) | Module 2 (Authentication)                              |
| FSM S1->S2 (`session_open`) | Module 3 — WebSocket connect creates the `sessions` row. Modules 5/6 will gate this; Module 4 will attach an ACL rule here |
| FSM S2->S3 (`session_close`)| Module 3 — `terminate_session` (ws drop / logout / admin / idle+lifetime sweep); additionally triggered by Module 7 on unacceptable risk |
| Trust Score            | `backend/app/services/trust_score/` (Module 5)                |
| Adaptive MFA            | `backend/app/services/mfa/` (Module 6)                        |
| Continuous evaluation   | Composition of trust_score + mfa + acl services (Module 7), no separate service package |

## Module -> folder map (Module 1 baseline)

```
backend/app/api/v1/endpoints/   one file per module's REST surface (+ the WS route in sessions.py)
backend/app/api/deps.py          shared deps: get_db, get_current_user, get_current_admin (Module 2)
backend/app/core/security.py     password hashing + JWT primitives (Module 2)
backend/app/services/            one sub-package per module (auth/ M2, session/ M3: fsm+store+service)
backend/app/models/              one file per module's ORM model(s) (user.py M2, session.py M3)
backend/app/ws/                  connection_manager.py + handshake auth.py (Module 3)
frontend/src/auth/               token store, AuthProvider, useAuth, ProtectedRoute (Module 2)
frontend/src/session/            SessionProvider, useSession (Module 3)
frontend/src/ws/socket.ts        SessionSocket signalling client (Module 3)
frontend/src/pages/admin/        one page per Module 8 dashboard section
infra/l-pep/                     Module 4's enforcement component
```

Status: Modules 1-3 implemented. The base paper's "JWT verification" step of
the SS-PDP is `app/core/security.decode_access_token` — reused by the REST
`get_current_user` dependency (M2) and by `app/ws/auth.resolve_ws_user` for
the `?token=` WebSocket handshake (M3). Session state lives in Postgres
(`sessions` table, authoritative); Redis mirrors the active set and carries
`session.opened`/`session.closed` events for Module 8 to subscribe to.
Module 4 hooks ACL create/remove onto those same events / the
`terminate_session` path.

Do not add cross-module imports that blur these boundaries (e.g. the MFA
service should not import ACL internals directly — it returns a decision;
the session/continuous-evaluation layer acts on it). This mirrors the
project's explicit instruction to keep Authentication, Authorization,
Session Management, Trust Evaluation, Adaptive MFA, and ACL Enforcement
conceptually separate.
