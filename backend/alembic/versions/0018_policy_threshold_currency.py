"""Tie organization purchase thresholds to one currency."""

from alembic import op
import sqlalchemy as sa

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("organization_security_policies", sa.Column(
        "approval_threshold_currency", sa.String(length=3), server_default="USD", nullable=False,
    ))
    op.create_check_constraint("approval_threshold_currency_format", "organization_security_policies",
        "approval_threshold_currency ~ '^[A-Z]{3}$'")


def downgrade() -> None:
    op.drop_constraint("approval_threshold_currency_format", "organization_security_policies", type_="check")
    op.drop_column("organization_security_policies", "approval_threshold_currency")
