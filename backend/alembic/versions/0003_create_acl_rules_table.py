"""create acl_rules table

Module 4 (Dynamic ACL Management). One row per session-bound allow-list entry.

Revision ID: 0003_create_acl_rules_table
Revises: 0002_create_sessions_table
Create Date: 2026-09-08

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003_create_acl_rules_table"
down_revision: Union[str, None] = "0002_create_sessions_table"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "acl_rules",
        sa.Column("id", sa.String(length=32), primary_key=True, nullable=False),
        sa.Column("session_id", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("client_ip", sa.String(length=64), nullable=False),
        sa.Column("resource", sa.String(length=128), nullable=False),
        sa.Column("ipset_name", sa.String(length=64), nullable=False),
        sa.Column(
            "state", sa.String(length=16), nullable=False, server_default="pending"
        ),
        sa.Column("enforcement", sa.String(length=16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=False),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("activated_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("removed_at", sa.DateTime(timezone=False), nullable=True),
        sa.Column("authorization_latency_ms", sa.Integer(), nullable=True),
        sa.Column("revocation_latency_ms", sa.Integer(), nullable=True),
        sa.Column("removal_reason", sa.String(length=32), nullable=True),
        sa.Column("last_error", sa.String(length=256), nullable=True),
        sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_acl_rules_session_id", "acl_rules", ["session_id"], unique=True)
    op.create_index("ix_acl_rules_user_id", "acl_rules", ["user_id"])
    op.create_index("ix_acl_rules_client_ip", "acl_rules", ["client_ip"])
    op.create_index("ix_acl_rules_state", "acl_rules", ["state"])


def downgrade() -> None:
    op.drop_index("ix_acl_rules_state", table_name="acl_rules")
    op.drop_index("ix_acl_rules_client_ip", table_name="acl_rules")
    op.drop_index("ix_acl_rules_user_id", table_name="acl_rules")
    op.drop_index("ix_acl_rules_session_id", table_name="acl_rules")
    op.drop_table("acl_rules")
