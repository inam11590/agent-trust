"""Allow irreversible agent revocation.

Revision ID: 0006
Revises: 0005
"""

from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("agent_status", "agents", type_="check")
    op.create_check_constraint(
        "agent_status",
        "agents",
        "status IN ('active', 'inactive', 'suspended', 'revoked')",
    )


def downgrade() -> None:
    op.execute(sa.text("UPDATE agents SET status = 'suspended' WHERE status = 'revoked'"))
    op.drop_constraint("agent_status", "agents", type_="check")
    op.create_check_constraint(
        "agent_status",
        "agents",
        "status IN ('active', 'inactive', 'suspended')",
    )
