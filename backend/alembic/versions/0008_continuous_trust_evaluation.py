"""continuous trust evaluation: security_events table + mfa_challenges.session_id

Module 7 (Continuous Trust Evaluation), 2026-09-13.

  - Creates security_events: one row per mid-session security-relevant event
    ingested by POST /security/events (ip_change / vpn_detected /
    unknown_device / abnormal_request_rate / large_download /
    multiple_failed_logins), recording the trust score and risk band
    immediately before and after, and which risk-based action (none /
    reverify / revoke) resulted.
  - Adds mfa_challenges.session_id (nullable FK to sessions.id): scopes a
    re-verification challenge (reason=risk_retrigger) to the session that
    triggered it, so that challenge's failure/expiry can revoke that specific
    session. Nullable because login_risk/step_up challenges are not tied to
    an already-open session.

Revision ID: 0008_continuous_trust_evaluation
Revises: 0007_mfa_email_otp
Create Date: 2026-09-13

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0008_continuous_trust_evaluation"
down_revision: Union[str, None] = "0007_mfa_email_otp"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # batch_alter_table: SQLite can't ALTER a table to add a foreign key
    # constraint in place (no direct ALTER-constraint support -- it requires
    # the copy-and-move "batch" strategy). Postgres runs the same batch as a
    # single native ALTER, so this is portable both ways -- needed so this
    # migration can still be dry-run against a throwaway SQLite database, per
    # this project's own migration-verification convention.
    with op.batch_alter_table("mfa_challenges") as batch_op:
        batch_op.add_column(sa.Column("session_id", sa.String(length=32), nullable=True))
        batch_op.create_index("ix_mfa_challenges_session_id", ["session_id"])
        batch_op.create_foreign_key(
            "fk_mfa_challenges_session_id_sessions",
            "sessions", ["session_id"], ["id"], ondelete="CASCADE",
        )

    op.create_table(
        "security_events",
        sa.Column("id", sa.String(length=32), primary_key=True, nullable=False),
        sa.Column("session_id", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("weight_applied", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(length=256), nullable=False),
        sa.Column("previous_score", sa.Integer(), nullable=False),
        sa.Column("new_score", sa.Integer(), nullable=False),
        sa.Column("previous_risk", sa.String(length=16), nullable=False),
        sa.Column("new_risk", sa.String(length=16), nullable=False),
        sa.Column("action", sa.String(length=16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=False),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["session_id"], ["sessions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_security_events_session_id", "security_events", ["session_id"])
    op.create_index("ix_security_events_user_id", "security_events", ["user_id"])
    op.create_index("ix_security_events_created_at", "security_events", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_security_events_created_at", table_name="security_events")
    op.drop_index("ix_security_events_user_id", table_name="security_events")
    op.drop_index("ix_security_events_session_id", table_name="security_events")
    op.drop_table("security_events")

    with op.batch_alter_table("mfa_challenges") as batch_op:
        batch_op.drop_constraint("fk_mfa_challenges_session_id_sessions", type_="foreignkey")
        batch_op.drop_index("ix_mfa_challenges_session_id")
        batch_op.drop_column("session_id")
