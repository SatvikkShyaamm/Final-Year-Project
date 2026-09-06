"""
Business-logic services package, separated from the API layer.

Sub-packages are pre-created (empty except for __init__.py) so the intended
module boundaries are visible from the start:

  services/session/     -> Module 3: session lifecycle FSM, connection manager glue
  services/acl/         -> Module 4: ACL create/remove, ipset integration (L-PEP role)
  services/trust_score/ -> Module 5: weighted trust factor calculation
  services/mfa/         -> Module 6: TOTP generation/verification
  services/simulation/  -> Module 9: attack simulation triggers

Module 7 (Continuous Trust Evaluation) does not get its own sub-package: it
composes services/trust_score, services/mfa, and services/acl rather than
owning separate business logic, per the architectural separation the
project instructions call for (trust evaluation != trust scoring != MFA).
"""
