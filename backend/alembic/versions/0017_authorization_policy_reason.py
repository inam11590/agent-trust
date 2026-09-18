"""Retain the organization rule that originally required manual approval."""

from alembic import op
import sqlalchemy as sa

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("authorization_requests", sa.Column("policy_reason", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("authorization_requests", "policy_reason")
