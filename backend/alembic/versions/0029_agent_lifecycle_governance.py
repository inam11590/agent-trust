"""Enterprise Agent Lifecycle Governance tables and schema extensions (Step 28).

Revision ID: 0029
Revises: 0028
Create Date: 2026-09-22
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0029"
down_revision: Union[str, None] = "0028"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add governance metadata columns to agents table
    op.add_column("agents", sa.Column("owner_type", sa.String(length=32), server_default="USER", nullable=False))
    op.add_column("agents", sa.Column("team", sa.String(length=128), nullable=True))
    op.add_column("agents", sa.Column("purpose", sa.Text(), nullable=True))
    op.add_column("agents", sa.Column("business_function", sa.String(length=128), nullable=True))
    op.add_column("agents", sa.Column("expected_actions", sa.JSON(), server_default="[]", nullable=False))
    op.add_column("agents", sa.Column("data_access_description", sa.Text(), nullable=True))
    op.add_column("agents", sa.Column("risk_classification", sa.String(length=32), server_default="LOW", nullable=False))
    op.add_column("agents", sa.Column("classification_reasons", sa.JSON(), server_default="[]", nullable=False))
    op.add_column("agents", sa.Column("business_criticality", sa.String(length=32), server_default="LOW", nullable=False))
    op.add_column("agents", sa.Column("data_classification", sa.String(length=32), server_default="INTERNAL", nullable=False))
    op.add_column("agents", sa.Column("source", sa.String(length=32), server_default="MANUAL", nullable=False))
    op.add_column("agents", sa.Column("external_reference", sa.String(length=255), nullable=True))
    op.add_column("agents", sa.Column("tags", sa.JSON(), server_default="[]", nullable=False))
    op.add_column("agents", sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("agents", sa.Column("last_reviewed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("agents", sa.Column("next_review_due_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("agents", sa.Column("certified_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column("agents", sa.Column("certification_status", sa.String(length=32), server_default="UNREVIEWED", nullable=False))

    op.create_index("ix_agents_lifecycle_status", "agents", ["organization_id", "status"])
    op.create_index("ix_agents_owner_type", "agents", ["organization_id", "owner_type"])

    # 2. agent_ownership_history
    op.create_table(
        "agent_ownership_history",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=True),
        sa.Column("old_owner_type", sa.String(length=32), nullable=False),
        sa.Column("old_owner_id", sa.String(length=255), nullable=False),
        sa.Column("new_owner_type", sa.String(length=32), nullable=False),
        sa.Column("new_owner_id", sa.String(length=255), nullable=False),
        sa.Column("changed_by", sa.Uuid(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["changed_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_agent_ownership_hist_agent", "agent_ownership_history", ["agent_id", "created_at"])
    op.create_index("ix_agent_ownership_hist_org", "agent_ownership_history", ["organization_id"])

    # 3. agent_certifications
    op.create_table(
        "agent_certifications",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("certification_id", sa.String(length=64), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=True),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="PENDING", nullable=False),
        sa.Column("reviewer_id", sa.Uuid(), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision", sa.String(length=32), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("snapshot_reference", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["reviewer_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("certification_id"),
    )
    op.create_index("ix_agent_cert_org_status", "agent_certifications", ["organization_id", "status"])
    op.create_index("ix_agent_cert_agent", "agent_certifications", ["agent_id", "created_at"])

    # 4. agent_governance_policies
    op.create_table(
        "agent_governance_policies",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("periodic_review_days", sa.Integer(), server_default="90", nullable=False),
        sa.Column("expiry_behavior", sa.String(length=32), server_default="ALERT_ONLY", nullable=False),
        sa.Column("dormancy_days", sa.Integer(), server_default="90", nullable=False),
        sa.Column("enforce_separation_of_duties", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("require_classification_on_promotion", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("require_purpose_on_promotion", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id"),
    )
    op.create_index("ix_agent_gov_pol_org", "agent_governance_policies", ["organization_id"], unique=True)


def downgrade() -> None:
    op.drop_table("agent_governance_policies")
    op.drop_table("agent_certifications")
    op.drop_table("agent_ownership_history")
    op.drop_index("ix_agents_owner_type", table_name="agents")
    op.drop_index("ix_agents_lifecycle_status", table_name="agents")
    for col in [
        "certification_status", "certified_until", "next_review_due_at", "last_reviewed_at",
        "last_activity_at", "tags", "external_reference", "source", "data_classification",
        "business_criticality", "classification_reasons", "risk_classification",
        "data_access_description", "expected_actions", "business_function", "purpose",
        "team", "owner_type"
    ]:
        op.drop_column("agents", col)
