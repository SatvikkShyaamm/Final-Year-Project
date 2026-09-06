"""
User ORM model — Module 2 (Authentication).

This is the "user database" deliverable from the project spec. It stays
strictly about *identity* ("who are you?"): credentials, role, active flag,
and a small amount of audit metadata. It deliberately does NOT hold session
state, trust score, or MFA secrets — those belong to Modules 3, 5, and 6
respectively and get their own tables/foreign keys back to this one.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class UserRole:
    """Allowed values for `User.role`.

    Kept as plain string constants (not a DB enum) so adding a role later is a
    code change, not a migration. Authorization ("what can this role do?") is a
    separate concern from authentication and is enforced in the API deps layer.
    """

    USER = "user"
    ADMIN = "admin"

    ALL = (USER, ADMIN)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)

    username: Mapped[str] = mapped_column(
        String(50), unique=True, index=True, nullable=False
    )
    email: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)

    role: Mapped[str] = mapped_column(
        String(20), nullable=False, default=UserRole.USER, server_default=UserRole.USER
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid only
        return f"<User id={self.id} username={self.username!r} role={self.role}>"

    @property
    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN
