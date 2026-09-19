"""Make target_organization_id and target_agent_id nullable in atp_messages.

Revision ID: 0024
Revises: 0023
Create Date: 2026-09-19
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0024"
down_revision: Union[str, None] = "0023"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column("atp_messages", "target_organization_id", nullable=True)
    op.alter_column("atp_messages", "target_agent_id", nullable=True)


def downgrade() -> None:
    op.alter_column("atp_messages", "target_organization_id", nullable=False)
    op.alter_column("atp_messages", "target_agent_id", nullable=False)
