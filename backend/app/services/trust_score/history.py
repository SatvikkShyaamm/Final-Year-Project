"""
Per-user session history lookups for the Trust Score engine — Module 5.

All history-dependent factors (known/unknown device, known IP, IP changed,
typical hour) are derived from prior ``sessions`` rows for the same user. This
module does the reads; the evaluator turns them into factor outcomes.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.models.session import Session

# How many recent sessions to consider "recent" for known-IP / hour-range.
_RECENT_WINDOW = 20


@dataclass
class UserHistory:
    session_count: int = 0
    known_user_agents: set[str] = field(default_factory=set)
    recent_ips: list[str] = field(default_factory=list)
    last_ip: str | None = None
    login_hours: list[int] = field(default_factory=list)  # hour-of-day of prior logins

    @property
    def has_history(self) -> bool:
        return self.session_count > 0


def _subnet(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    prefix = 64 if addr.version == 6 else 24
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def load_user_history(
    db: DbSession, user_id: int, *, exclude_session_id: str | None, offset_hours: int
) -> UserHistory:
    """Prior sessions for this user (newest first), excluding the one being scored."""
    stmt = (
        select(Session)
        .where(Session.user_id == user_id)
        .order_by(Session.created_at.desc())
        .limit(_RECENT_WINDOW + 1)
    )
    rows = [s for s in db.scalars(stmt) if s.id != exclude_session_id]

    hist = UserHistory(session_count=len(rows))
    for i, s in enumerate(rows):
        if s.user_agent:
            hist.known_user_agents.add(s.user_agent.strip())
        if s.ip_address:
            hist.recent_ips.append(s.ip_address)
            if i == 0:
                hist.last_ip = s.ip_address
        local = _shift(s.created_at, offset_hours)
        hist.login_hours.append(local.hour)
    return hist


def _shift(dt: datetime, offset_hours: int) -> datetime:
    from datetime import timedelta

    return dt + timedelta(hours=offset_hours)


def ip_matches_recent(candidate_ip: str, history: UserHistory) -> bool:
    """True if the IP exactly matches, or is in the same /24 (or /64) as, a recent session."""
    if candidate_ip in history.recent_ips:
        return True
    cand_net = _subnet(candidate_ip)
    if cand_net is None:
        return False
    return any(_subnet(ip) == cand_net for ip in history.recent_ips)
