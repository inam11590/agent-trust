"""Preserve verified MFA assurance across the one-time OIDC exchange."""

from alembic import op
import sqlalchemy as sa

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("sso_login_tickets", sa.Column("mfa_verified", sa.Boolean(), server_default=sa.text("false"), nullable=False))


def downgrade() -> None:
    op.drop_column("sso_login_tickets", "mfa_verified")
