"""
Business-logic services package, separated from the API layer.

Sub-packages map one-to-one to the module that owns that business logic:

  services/auth/        -> Module 2: registration + credential verification
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
