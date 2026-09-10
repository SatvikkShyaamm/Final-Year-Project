"""mfa: replace TOTP credentials with email one-time codes

Module 6 (Adaptive MFA), 2026-09-10. At the user's explicit request, TOTP
(authenticator-app) MFA is replaced with email-delivered one-time codes for
every login, not just a first-time bootstrap -- see docs/architecture.md and
Project status.md section 11 for the full rationale.

  - Drops mfa_credentials (the one-secret-per-user TOTP table): an emailed
    code needs nothing durable per user, so there is nothing left to store
    between challenges.
  - Adds code_hash / code_salt / delivered_via to mfa_challenges: the salted
    hash of the one-time code that was emailed for THIS challenge (never the
    plaintext), and how it was delivered (sent / dev_logged / failed).
    Nullable, since existing challenge rows predate this column and have no
    meaningful code to backfill.

Revision ID: 0007_mfa_email_otp
Revises: 0006_add_token_revocation
Create Date: 2026-09-10

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007_mfa_email_otp"
down_revision: Union[str, None] = "0006_add_token_revocation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "mfa_challenges", sa.Column("code_hash", sa.String(length=64), nullable=True)
    )
    op.add_column(
        "mfa_challenges", sa.Column("code_salt", sa.String(length=32), nullable=True)
    )
    op.add_column(
        "mfa_challenges", sa.Column("delivered_via", sa.String(length=16), nullable=True)
    )

    op.drop_index("ix_mfa_credentials_user_id", table_name="mfa_credentials")
    op.drop_table("mfa_credentials")


def downgrade() -> None:
    op.create_table(
        "mfa_credentials",
        sa.Column("id", sa.String(length=32), primary_key=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("secret", sa.String(length=64), nullable=False),
        sa.Column(
            "confirmed", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=False),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("confirmed_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=False), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_mfa_credentials_user_id", "mfa_credentials", ["user_id"], unique=True
    )

    op.drop_column("mfa_challenges", "delivered_via")
    op.drop_column("mfa_challenges", "code_salt")
    op.drop_column("mfa_challenges", "code_hash")
