"""
services/dashboard/ -> Module 8: Security Dashboard.

  service.py   aggregation queries over Modules 2-7's own tables + their
               Redis-backed lockout state -- Dashboard Home's stat cards,
               the Analytics charts, and the admin lockout list/clear
               endpoints.

Pure reads (plus, for lockouts, a couple of targeted Redis deletes) -- this
package owns no persisted state of its own and needs no model, schema
migration, or session hook. Kept as a package (not a bare module file), one
file for now, to match this project's one-sub-package-per-module convention
(see docs/architecture.md's "Module -> folder map").
"""
from app.services.dashboard.service import (
    analytics,
    clear_lockouts,
    locked_accounts,
    overview,
)

__all__ = ["analytics", "clear_lockouts", "locked_accounts", "overview"]
