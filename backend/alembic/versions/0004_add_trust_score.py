"""add trust score columns + trust_score_factors table

Module 5 (Trust Score Engine). Additive only — Modules 1-4 tables are
otherwise untouched.

Revision ID: 0004_add_trust_score
Revises: 0003_create_acl_rules_table
Create Date: 2026-09-09

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004_add_trust_score"
down_revision: Union[str, None] = "0003_create_acl_rules_table"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("sessions", sa.Column("trust_score", sa.Integer(), nullable=True))
    op.add_column("sessions", sa.Column("risk_level", sa.String(length=16), nullable=True))

    op.create_table(
        "trust_score_factors",
        sa.Column("id", sa.String(length=32), primary_key=True, nullable=False),
        sa.Column("session_id", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("factor_name", sa.String(length=64), nullable=False),
        sa.Column("factor_kind", sa.String(length=16), nullable=False),
        sa.Column("weight_applied", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(length=256), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=False),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_trust_score_factors_session_id", "trust_score_factors", ["session_id"]
    )
    op.create_index(
        "ix_trust_score_factors_user_id", "trust_score_factors", ["user_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_trust_score_factors_user_id", table_name="trust_score_factors")
    op.drop_index("ix_trust_score_factors_session_id", table_name="trust_score_factors")
    op.drop_table("trust_score_factors")
    op.drop_column("sessions", "risk_level")
    op.drop_column("sessions", "trust_score")
