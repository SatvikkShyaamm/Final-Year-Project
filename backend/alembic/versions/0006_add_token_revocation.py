"""add token_jti + token_exp to sessions (server-side JWT revocation)

Hardening fix (Project status.md, section 6b): lets terminating a session
revoke the specific access token that opened it, instead of only ending the
session row. Additive only — no other Module 1-6 table touched.

Revision ID: 0006_add_token_revocation
Revises: 0005_add_mfa
Create Date: 2026-09-10

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0006_add_token_revocation"
down_revision: Union[str, None] = "0005_add_mfa"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "sessions", sa.Column("token_jti", sa.String(length=32), nullable=True)
    )
    op.add_column(
        "sessions",
        sa.Column("token_exp", sa.DateTime(timezone=False), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("sessions", "token_exp")
    op.drop_column("sessions", "token_jti")
