"""security_events.source -- auto/admin tag (Module 7 hardening, Section 18)

Module 7 hardening -- Real Passive Network Detection (Section 18 of
MASTER_PROJECT_CONTEXT.docx, FINALIZED 2026-09-14, implemented 2026-09-15),
2026-09-15.

  - Adds security_events.source: "auto" (raised automatically by the new
    heartbeat detector -- app.services.trust_score.heartbeat) or "admin"
    (raised manually via POST /security/events, the existing "Trigger"
    control). NOT NULL, server_default 'admin' -- every event ingested
    before this column existed was, by construction, admin-raised (the
    heartbeat detector did not exist yet), so the backfill default is
    historically correct, not a placeholder.

Revision ID: 0009_security_event_source
Revises: 0008_continuous_trust_evaluation
Create Date: 2026-09-15

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009_security_event_source"
down_revision: Union[str, None] = "0008_continuous_trust_evaluation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # batch_alter_table: SQLite-portable (see 0008's own comment on why this
    # project always adds columns this way) even though a plain ADD COLUMN
    # with a server_default doesn't strictly need it on Postgres -- kept
    # consistent with this codebase's established migration style.
    with op.batch_alter_table("security_events") as batch_op:
        batch_op.add_column(
            sa.Column(
                "source", sa.String(length=16), nullable=False, server_default="admin"
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("security_events") as batch_op:
        batch_op.drop_column("source")
