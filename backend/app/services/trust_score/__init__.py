"""
services/trust_score/ -> Module 5: Trust Score Engine.

  factors.py    canonical factor names + result types + risk classifier
  history.py    per-user prior-session lookups (devices, IPs, login hours)
  store.py      Redis failed-login burst counter (Section 6 finalized storage)
  evaluator.py  the Section-6 scoring algorithm (static score at session open)
  service.py    session_opened hook target + reads + config catalogue
  wiring.py     registers the session_opened hook at import
  continuous.py Module 7: mid-session re-evaluation (event -> new score ->
                risk-based action), composing this package with mfa/ and
                session/ rather than a separate service package -- see
                docs/architecture.md and continuous.py's own docstring

Importing this package wires the hook, so a session opening also computes and
stores its static trust score with no code in the session layer aware of it.
The score is informational in Module 5 — Module 6 turns it into an
allow / MFA / block decision. Module 7's continuous.py is a plain submodule,
not re-exported here, to avoid this package eagerly importing the mfa/ and
session/ packages it composes at every import site (see continuous.py).
"""
from app.services.trust_score.factors import (
    Factor,
    FactorOutcome,
    TrustEvaluation,
    classify_risk,
)
from app.services.trust_score.service import (
    average_trust_score,
    evaluate_for_session,
    evaluate_login,
    factor_catalogue,
    get_factors_for_session,
    get_user_score_history,
    record_failed_login_attempt,
    risk_bands,
)
from app.services.trust_score import wiring as _wiring  # noqa: F401  (registers hook)

__all__ = [
    "Factor",
    "FactorOutcome",
    "TrustEvaluation",
    "classify_risk",
    "average_trust_score",
    "evaluate_for_session",
    "evaluate_login",
    "factor_catalogue",
    "get_factors_for_session",
    "get_user_score_history",
    "record_failed_login_attempt",
    "risk_bands",
]
