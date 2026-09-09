"""
ORM models package.

Empty in Module 1 by design — no business tables exist yet. Each module
that owns persistent state adds its model(s) here and a matching Alembic
migration:

  Module 2 -> user.py            (User)
  Module 3 -> session.py         (Session)
  Module 4 -> acl.py             (ACLRule)
  Module 5 -> trust_score.py     (TrustScoreEvent, TrustFactorWeight)
  Module 6 -> mfa.py             (MFAChallenge)
  Module 7 -> security_event.py  (SecurityEvent)

Import new models in this file so Alembic's autogenerate can discover them
via Base.metadata.
"""
from app.models.acl import (  # noqa: F401  (Module 4)
    ACLRule,
    ACLState,
    EnforcementBackend,
)
from app.models.session import (  # noqa: F401  (Module 3)
    Session,
    SessionState,
    TerminationReason,
)
from app.models.trust_score import (  # noqa: F401  (Module 5)
    FactorKind,
    RiskLevel,
    TrustScoreFactor,
)
from app.models.user import User, UserRole  # noqa: F401  (Module 2)

__all__ = [
    "User",
    "UserRole",
    "Session",
    "SessionState",
    "TerminationReason",
    "ACLRule",
    "ACLState",
    "EnforcementBackend",
    "TrustScoreFactor",
    "FactorKind",
    "RiskLevel",
]
