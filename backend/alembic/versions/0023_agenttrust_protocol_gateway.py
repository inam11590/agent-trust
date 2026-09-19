"""Step 21: AgentTrust Protocol (ATP/1.0) and Gateway."""

from alembic import op
import sqlalchemy as sa

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. agent_endpoints
    op.create_table(
        "agent_endpoints",
        sa.Column("id", sa.Uuid(), nullable=False, primary_key=True),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("endpoint_url", sa.String(512), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="PENDING"),
        sa.Column("verification_token", sa.String(128), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_agent_endpoints_org", "agent_endpoints", ["organization_id"])
    op.create_index("ix_agent_endpoints_agent", "agent_endpoints", ["agent_id"])

    # 2. agent_capabilities
    op.create_table(
        "agent_capabilities",
        sa.Column("id", sa.Uuid(), nullable=False, primary_key=True),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("version", sa.String(32), nullable=False, server_default="1.0"),
        sa.Column("description", sa.String(512), nullable=True),
        sa.Column("input_schema", sa.JSON(), nullable=True),
        sa.Column("output_schema", sa.JSON(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("agent_id", "name", "version", name="uq_agent_capability_name_ver"),
    )
    op.create_index("ix_agent_cap_org", "agent_capabilities", ["organization_id"])
    op.create_index("ix_agent_cap_agent", "agent_capabilities", ["agent_id"])

    # 3. atp_messages
    op.create_table(
        "atp_messages",
        sa.Column("id", sa.Uuid(), nullable=False, primary_key=True),
        sa.Column("message_id", sa.String(64), nullable=False, unique=True),
        sa.Column("atp_version", sa.String(16), nullable=False, server_default="1.0"),
        sa.Column("message_type", sa.String(32), nullable=False, server_default="request"),
        sa.Column("source_organization_id", sa.Uuid(), nullable=False),
        sa.Column("source_agent_id", sa.Uuid(), nullable=False),
        sa.Column("target_organization_id", sa.Uuid(), nullable=False),
        sa.Column("target_agent_id", sa.Uuid(), nullable=False),
        sa.Column("capability", sa.String(128), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="PENDING"),
        sa.Column("decision_reason", sa.String(255), nullable=True),
        sa.Column("idempotency_key", sa.String(128), nullable=True),
        sa.Column("idempotency_hash", sa.String(64), nullable=True),
        sa.Column("payload_summary", sa.JSON(), nullable=True),
        sa.Column("attestation_id", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["source_organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["source_agent_id"], ["agents.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["target_organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["target_agent_id"], ["agents.id"], ondelete="RESTRICT"),
    )
    op.create_index("ix_atp_messages_msgid", "atp_messages", ["message_id"])
    op.create_index("ix_atp_messages_source", "atp_messages", ["source_organization_id", "created_at"])
    op.create_index("ix_atp_messages_target", "atp_messages", ["target_organization_id", "created_at"])
    op.create_index("ix_atp_messages_idem", "atp_messages", ["idempotency_key"])

    # 4. atp_message_deliveries
    op.create_table(
        "atp_message_deliveries",
        sa.Column("id", sa.Uuid(), nullable=False, primary_key=True),
        sa.Column("message_id", sa.String(64), nullable=False),
        sa.Column("target_endpoint_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="PENDING"),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("response_payload", sa.JSON(), nullable=True),
        sa.Column("error_message", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["message_id"], ["atp_messages.message_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_endpoint_id"], ["agent_endpoints.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_atp_deliv_msgid", "atp_message_deliveries", ["message_id"])


def downgrade() -> None:
    op.drop_table("atp_message_deliveries")
    op.drop_table("atp_messages")
    op.drop_table("agent_capabilities")
    op.drop_table("agent_endpoints")
