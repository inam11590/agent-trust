"""Step 19: Agent-to-Agent Trust (Delegation)."""

from alembic import op
import sqlalchemy as sa

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Update permissions table
    op.add_column(
        "permissions",
        sa.Column("allow_delegation", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )

    # 2. Update authorization_requests table
    op.add_column(
        "authorization_requests",
        sa.Column("delegation_id", sa.String(28), nullable=True),
    )
    op.add_column(
        "authorization_requests",
        sa.Column("parent_agent_id", sa.Uuid(), nullable=True),
    )
    op.create_foreign_key(
        "fk_authorization_requests_parent_agent_id",
        "authorization_requests",
        "agents",
        ["parent_agent_id"],
        ["id"],
        ondelete="SET NULL",
    )

    # 3. Update audit_logs table
    op.add_column(
        "audit_logs",
        sa.Column("delegation_id", sa.String(28), nullable=True),
    )
    op.add_column(
        "audit_logs",
        sa.Column("parent_agent_id", sa.Uuid(), nullable=True),
    )
    op.create_foreign_key(
        "fk_audit_logs_parent_agent_id",
        "audit_logs",
        "agents",
        ["parent_agent_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_audit_logs_delegation", "audit_logs", ["delegation_id"])

    # 4. Create agent_delegations table
    op.create_table(
        "agent_delegations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("delegation_id", sa.String(28), nullable=False, unique=True),
        sa.Column("parent_agent_id", sa.Uuid(), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("child_agent_id", sa.Uuid(), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("parent_permission_id", sa.Uuid(), sa.ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("parent_delegation_id", sa.Uuid(), sa.ForeignKey("agent_delegations.id", ondelete="CASCADE"), nullable=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("resource", sa.String(64), nullable=False),
        sa.Column("maximum_amount", sa.Numeric(19, 4), nullable=True),
        sa.Column("currency", sa.String(3), nullable=True),
        sa.Column("requires_approval", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("allow_further_delegation", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("current_depth", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("max_delegation_depth", sa.Integer(), nullable=False, server_default=sa.text("3")),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "status",
            sa.Enum("ACTIVE", "EXPIRED", "REVOKED", "SUSPENDED", name="delegation_status", native_enum=False, create_constraint=True),
            nullable=False,
            server_default="ACTIVE",
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(255), nullable=True),
        sa.Column("revoked_by_agent_id", sa.Uuid(), sa.ForeignKey("agents.id", ondelete="SET NULL"), nullable=True),
        sa.Column("revoked_by_user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("delegation_id ~ '^dlg_[0-9a-f]{24}$'", name="delegation_id_format"),
        sa.CheckConstraint("parent_agent_id <> child_agent_id", name="no_self_delegation"),
        sa.CheckConstraint("expires_at > valid_from", name="delegation_valid_time_window"),
        sa.CheckConstraint("maximum_amount IS NULL OR maximum_amount > 0", name="delegation_maximum_amount_positive"),
        sa.CheckConstraint("(maximum_amount IS NULL) = (currency IS NULL)", name="delegation_amount_currency_pair"),
        sa.CheckConstraint("currency IS NULL OR currency ~ '^[A-Z]{3}$'", name="delegation_currency_format"),
        sa.CheckConstraint("current_depth > 0 AND current_depth <= max_delegation_depth", name="delegation_depth_bounds"),
    )

    op.create_index("ix_agent_delegations_delegation_id", "agent_delegations", ["delegation_id"])
    op.create_index("ix_agent_delegations_parent_agent_id", "agent_delegations", ["parent_agent_id"])
    op.create_index("ix_agent_delegations_child_agent_id", "agent_delegations", ["child_agent_id"])
    op.create_index("ix_agent_delegations_parent_permission_id", "agent_delegations", ["parent_permission_id"])
    op.create_index("ix_agent_delegations_parent_delegation_id", "agent_delegations", ["parent_delegation_id"])
    op.create_index("ix_agent_delegations_organization_id", "agent_delegations", ["organization_id"])
    op.create_index("ix_agent_delegations_org_status", "agent_delegations", ["organization_id", "status"])
    op.create_index("ix_agent_delegations_child_status", "agent_delegations", ["child_agent_id", "status"])
    op.create_index("ix_agent_delegations_parent_status", "agent_delegations", ["parent_agent_id", "status"])


def downgrade() -> None:
    op.drop_table("agent_delegations")
    op.drop_index("ix_audit_logs_delegation", table_name="audit_logs")
    op.drop_constraint("fk_audit_logs_parent_agent_id", "audit_logs", type_="foreignkey")
    op.drop_column("audit_logs", "parent_agent_id")
    op.drop_column("audit_logs", "delegation_id")

    op.drop_constraint("fk_authorization_requests_parent_agent_id", "authorization_requests", type_="foreignkey")
    op.drop_column("authorization_requests", "parent_agent_id")
    op.drop_column("authorization_requests", "delegation_id")

    op.drop_column("permissions", "allow_delegation")
