"""
services/trust_score/ -> Module 5: Trust Score Engine.

  factors.py    canonical factor names + result types + risk classifier
  history.py    per-user prior-session lookups (devices, IPs, login hours)
  store.py      Redis failed-login burst counter (Section 6 finalized storage)
  evaluator.py  the Section-6 scoring algorithm (static score at session open)
  service.py    session_opened hook target + reads + config catalogue
  wiring.py     registers the session_opened hook at import

Importing this package wires the hook, so a session opening also computes and
stores its static trust score with no code in the session layer aware of it.
The score is informational in Module 5 — Module 6 turns it into an
allow / MFA / block decision.
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
    "factor_catalogue",
    "get_factors_for_session",
    "get_user_score_history",
    "record_failed_login_attempt",
    "risk_bands",
]
