"""Agent Service Registry and Communication tables (Step 30).

Revision ID: 0031
Revises: 0030
Create Date: 2026-09-23
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0031"
down_revision: Union[str, None] = "0030"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. agent_services
    op.create_table(
        "agent_services",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("service_id", sa.String(length=64), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("version", sa.String(length=32), server_default="1.0.0", nullable=False),
        sa.Column("status", sa.String(length=32), server_default="ACTIVE", nullable=False),
        sa.Column("visibility", sa.String(length=32), server_default="ORGANIZATION", nullable=False),
        sa.Column("environment", sa.String(length=32), server_default="production", nullable=False),
        sa.Column("metadata_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("service_id"),
    )
    op.create_index("ix_agent_services_service_id", "agent_services", ["service_id"], unique=True)
    op.create_index("ix_agent_services_org_status", "agent_services", ["organization_id", "status"])
    op.create_index("ix_agent_services_agent", "agent_services", ["agent_id"])
    op.create_index("ix_agent_services_name", "agent_services", ["organization_id", "name"], unique=True)

    # 2. Add columns to agent_capabilities
    op.add_column("agent_capabilities", sa.Column("capability_id", sa.String(length=64), nullable=True))
    op.add_column("agent_capabilities", sa.Column("service_id", sa.Uuid(), nullable=True))
    op.add_column("agent_capabilities", sa.Column("risk_classification", sa.String(length=32), server_default="LOW", nullable=False))
    op.add_column("agent_capabilities", sa.Column("requires_approval", sa.Boolean(), server_default="false", nullable=False))
    op.add_column("agent_capabilities", sa.Column("approval_threshold_amount", sa.Float(), nullable=True))
    op.add_column("agent_capabilities", sa.Column("rate_limit_per_minute", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "fk_agent_capabilities_service_id",
        "agent_capabilities",
        "agent_services",
        ["service_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index("ix_agent_capabilities_capability_id", "agent_capabilities", ["capability_id"], unique=True)
    op.create_index("ix_agent_cap_service", "agent_capabilities", ["service_id"])

    # 3. agent_service_endpoints
    op.create_table(
        "agent_service_endpoints",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("endpoint_id", sa.String(length=64), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("service_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("protocol", sa.String(length=32), server_default="HTTPS", nullable=False),
        sa.Column("url", sa.String(length=1024), nullable=False),
        sa.Column("environment", sa.String(length=32), server_default="production", nullable=False),
        sa.Column("priority", sa.Integer(), server_default="1", nullable=False),
        sa.Column("weight", sa.Integer(), server_default="100", nullable=False),
        sa.Column("health_status", sa.String(length=32), server_default="UNKNOWN", nullable=False),
        sa.Column("consecutive_failures", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_health_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verification_challenge", sa.String(length=128), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["service_id"], ["agent_services.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("endpoint_id"),
    )
    op.create_index("ix_agent_service_endpoints_endpoint_id", "agent_service_endpoints", ["endpoint_id"], unique=True)
    op.create_index("ix_service_ep_service_prio", "agent_service_endpoints", ["service_id", "priority"])
    op.create_index("ix_service_ep_health", "agent_service_endpoints", ["service_id", "health_status"])

    # 4. service_verification_challenges
    op.create_table(
        "service_verification_challenges",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("challenge_id", sa.String(length=64), nullable=False),
        sa.Column("endpoint_id", sa.Uuid(), nullable=False),
        sa.Column("challenge_token", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="PENDING", nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["endpoint_id"], ["agent_service_endpoints.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("challenge_id"),
    )
    op.create_index("ix_service_verification_challenges_challenge_id", "service_verification_challenges", ["challenge_id"], unique=True)
    op.create_index("ix_service_verification_challenges_endpoint_id", "service_verification_challenges", ["endpoint_id"])

    # 5. agent_call_records
    op.create_table(
        "agent_call_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("call_id", sa.String(length=64), nullable=False),
        sa.Column("message_id", sa.String(length=64), nullable=False),
        sa.Column("source_organization_id", sa.Uuid(), nullable=False),
        sa.Column("source_agent_id", sa.Uuid(), nullable=False),
        sa.Column("target_organization_id", sa.Uuid(), nullable=True),
        sa.Column("target_agent_id", sa.Uuid(), nullable=True),
        sa.Column("service_id", sa.Uuid(), nullable=True),
        sa.Column("capability_name", sa.String(length=128), nullable=False),
        sa.Column("call_chain", sa.JSON(), server_default="[]", nullable=False),
        sa.Column("depth", sa.Integer(), server_default="1", nullable=False),
        sa.Column("status", sa.String(length=32), server_default="COMPLETED", nullable=False),
        sa.Column("decision_reason", sa.String(length=255), nullable=True),
        sa.Column("duration_ms", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("response_digest", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["source_organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["source_agent_id"], ["agents.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["target_organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["target_agent_id"], ["agents.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["service_id"], ["agent_services.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("call_id"),
    )
    op.create_index("ix_agent_call_records_call_id", "agent_call_records", ["call_id"], unique=True)
    op.create_index("ix_agent_call_records_message_id", "agent_call_records", ["message_id"])
    op.create_index("ix_call_rec_src_target", "agent_call_records", ["source_agent_id", "target_agent_id"])
    op.create_index("ix_call_rec_created", "agent_call_records", ["created_at"])
    op.create_index("ix_call_rec_service", "agent_call_records", ["service_id"])


def downgrade() -> None:
    op.drop_table("agent_call_records")
    op.drop_table("service_verification_challenges")
    op.drop_table("agent_service_endpoints")
    op.drop_index("ix_agent_cap_service", table_name="agent_capabilities")
    op.drop_index("ix_agent_capabilities_capability_id", table_name="agent_capabilities")
    op.drop_constraint("fk_agent_capabilities_service_id", "agent_capabilities", type_="foreignkey")
    op.drop_column("agent_capabilities", "rate_limit_per_minute")
    op.drop_column("agent_capabilities", "approval_threshold_amount")
    op.drop_column("agent_capabilities", "requires_approval")
    op.drop_column("agent_capabilities", "risk_classification")
    op.drop_column("agent_capabilities", "service_id")
    op.drop_column("agent_capabilities", "capability_id")
    op.drop_table("agent_services")
