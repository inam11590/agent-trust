"""Step 20: Cross-Organization Agent-to-Agent Trust."""

from alembic import op
import sqlalchemy as sa

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. organization_trust_relationships
    op.create_table(
        "organization_trust_relationships",
        sa.Column("id", sa.Uuid(), nullable=False, primary_key=True),
        sa.Column("trust_id", sa.String(32), nullable=False, unique=True),
        sa.Column("source_organization_id", sa.Uuid(), nullable=False),
        sa.Column("target_organization_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="PENDING"),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=False),
        sa.Column("accepted_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(255), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["source_organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["accepted_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("source_organization_id", "target_organization_id", name="uq_source_target_organization_trust"),
        sa.CheckConstraint("trust_id ~ '^trust_[0-9a-f]{24}$'", name="trust_id_format"),
        sa.CheckConstraint("source_organization_id <> target_organization_id", name="no_self_organization_trust"),
    )
    op.create_index("idx_org_trust_source", "organization_trust_relationships", ["source_organization_id", "status"])
    op.create_index("idx_org_trust_target", "organization_trust_relationships", ["target_organization_id", "status"])
    op.create_index("idx_org_trust_lookup", "organization_trust_relationships", ["trust_id"])

    # 2. organization_trust_policies
    op.create_table(
        "organization_trust_policies",
        sa.Column("id", sa.Uuid(), nullable=False, primary_key=True),
        sa.Column("trust_relationship_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column("allowed_actions", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("allowed_resources", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("max_amount", sa.Numeric(19, 4), nullable=True),
        sa.Column("currency", sa.String(3), nullable=True),
        sa.Column("require_human_approval", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("approval_threshold", sa.Numeric(19, 4), nullable=True),
        sa.Column("approval_type", sa.String(20), nullable=False, server_default="TARGET_APPROVAL"),
        sa.Column("allow_agent_delegation", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("max_delegation_depth", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("risk_threshold", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["trust_relationship_id"], ["organization_trust_relationships.id"], ondelete="CASCADE"),
        sa.CheckConstraint("max_amount IS NULL OR max_amount > 0", name="trust_policy_amount_positive"),
        sa.CheckConstraint("(max_amount IS NULL) = (currency IS NULL)", name="trust_policy_amount_currency_pair"),
        sa.CheckConstraint("max_delegation_depth >= 1 AND max_delegation_depth <= 5", name="trust_policy_depth_range"),
    )

    # 3. organization_public_profiles
    op.create_table(
        "organization_public_profiles",
        sa.Column("id", sa.Uuid(), nullable=False, primary_key=True),
        sa.Column("organization_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column("public_name", sa.String(200), nullable=False),
        sa.Column("description", sa.String(1000), nullable=False, server_default=""),
        sa.Column("website_domain", sa.String(255), nullable=True),
        sa.Column("discoverable", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("supported_capabilities", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("verification_status", sa.String(20), nullable=False, server_default="UNVERIFIED"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    )

    # 4. target_organization_policies
    op.create_table(
        "target_organization_policies",
        sa.Column("id", sa.Uuid(), nullable=False, primary_key=True),
        sa.Column("organization_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column("allowed_actions", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("allowed_resources", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("max_amount", sa.Numeric(19, 4), nullable=True),
        sa.Column("currency", sa.String(3), nullable=True),
        sa.Column("require_human_approval", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("approval_threshold", sa.Numeric(19, 4), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.CheckConstraint("max_amount IS NULL OR max_amount > 0", name="target_policy_amount_positive"),
        sa.CheckConstraint("(max_amount IS NULL) = (currency IS NULL)", name="target_policy_amount_currency_pair"),
    )

    # 5. external_agent_connections
    op.create_table(
        "external_agent_connections",
        sa.Column("id", sa.Uuid(), nullable=False, primary_key=True),
        sa.Column("connection_id", sa.String(32), nullable=False, unique=True),
        sa.Column("trust_relationship_id", sa.Uuid(), nullable=False),
        sa.Column("source_agent_id", sa.Uuid(), nullable=False),
        sa.Column("target_agent_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="ACTIVE"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(255), nullable=True),
        sa.ForeignKeyConstraint(["trust_relationship_id"], ["organization_trust_relationships.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("trust_relationship_id", "source_agent_id", "target_agent_id", name="uq_trust_source_target_agent_connection"),
        sa.CheckConstraint("connection_id ~ '^eac_[0-9a-f]{24}$'", name="connection_id_format"),
        sa.CheckConstraint("source_agent_id <> target_agent_id", name="no_self_agent_connection"),
    )
    op.create_index("idx_ext_conn_lookup", "external_agent_connections", ["connection_id"])
    op.create_index("idx_ext_conn_agents", "external_agent_connections", ["source_agent_id", "target_agent_id"])

    # 6. cross_organization_requests
    op.create_table(
        "cross_organization_requests",
        sa.Column("id", sa.Uuid(), nullable=False, primary_key=True),
        sa.Column("request_id", sa.String(32), nullable=False, unique=True),
        sa.Column("trust_relationship_id", sa.Uuid(), nullable=False),
        sa.Column("connection_id", sa.Uuid(), nullable=True),
        sa.Column("source_organization_id", sa.Uuid(), nullable=False),
        sa.Column("target_organization_id", sa.Uuid(), nullable=False),
        sa.Column("source_agent_id", sa.Uuid(), nullable=False),
        sa.Column("target_agent_id", sa.Uuid(), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("resource", sa.String(64), nullable=False),
        sa.Column("amount", sa.Numeric(19, 4), nullable=True),
        sa.Column("currency", sa.String(3), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="PENDING"),
        sa.Column("decision_reason", sa.String(255), nullable=True),
        sa.Column("risk_level", sa.String(20), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("idempotency_key", sa.String(128), nullable=True),
        sa.Column("idempotency_hash", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["trust_relationship_id"], ["organization_trust_relationships.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["connection_id"], ["external_agent_connections.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["source_organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.CheckConstraint("request_id ~ '^xreq_[0-9a-f]{24}$'", name="cross_org_request_id_format"),
        sa.CheckConstraint("amount IS NULL OR amount > 0", name="cross_org_amount_positive"),
    )
    op.create_index("idx_xreq_lookup", "cross_organization_requests", ["request_id"])
    op.create_index("idx_xreq_source_org", "cross_organization_requests", ["source_organization_id", "status"])
    op.create_index("idx_xreq_target_org", "cross_organization_requests", ["target_organization_id", "status"])
    op.create_index("idx_xreq_idempotency", "cross_organization_requests", ["source_organization_id", "idempotency_key"])

    # 7. cross_organization_approvals
    op.create_table(
        "cross_organization_approvals",
        sa.Column("id", sa.Uuid(), nullable=False, primary_key=True),
        sa.Column("cross_org_request_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("approval_stage", sa.String(20), nullable=False),
        sa.Column("required_role", sa.String(20), nullable=False, server_default="admin"),
        sa.Column("status", sa.String(20), nullable=False, server_default="PENDING"),
        sa.Column("decided_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reason", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["cross_org_request_id"], ["cross_organization_requests.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["decided_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("cross_org_request_id", "organization_id", "approval_stage", name="uq_cross_org_req_org_stage"),
    )
    op.create_index("idx_cross_org_appr_org", "cross_organization_approvals", ["organization_id", "status"])


def downgrade() -> None:
    op.drop_table("cross_organization_approvals")
    op.drop_table("cross_organization_requests")
    op.drop_table("external_agent_connections")
    op.drop_table("target_organization_policies")
    op.drop_table("organization_public_profiles")
    op.drop_table("organization_trust_policies")
    op.drop_table("organization_trust_relationships")
