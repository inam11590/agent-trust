"""Associate authorization audit records with their organization tenant.

Revision ID: 0010
Revises: 0009
"""

from alembic import op
import sqlalchemy as sa

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_logs", sa.Column("organization_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        "fk_audit_logs_organization_id_organizations",
        "audit_logs", "organizations", ["organization_id"], ["id"], ondelete="RESTRICT",
    )
    op.execute(sa.text(
        "UPDATE audit_logs AS audit SET organization_id = agents.organization_id "
        "FROM agents WHERE audit.agent_id = agents.id"
    ))
    op.create_index("ix_audit_logs_org_requested", "audit_logs", ["organization_id", "requested_at"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_org_requested", table_name="audit_logs")
    op.drop_constraint("fk_audit_logs_organization_id_organizations", "audit_logs", type_="foreignkey")
    op.drop_column("audit_logs", "organization_id")
