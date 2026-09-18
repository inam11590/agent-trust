"""Add rule-based risk assessments and workspace policies.

Revision ID: 0012
Revises: 0011
"""

from alembic import op
import sqlalchemy as sa

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_audit_logs_agent_decision_requested", "audit_logs", ["agent_id", "decision", "requested_at"])
    op.add_column("audit_logs", sa.Column("risk_score", sa.Integer(), nullable=True))
    op.add_column("audit_logs", sa.Column("risk_level", sa.String(16), nullable=True))
    op.add_column("audit_logs", sa.Column("risk_recommendation", sa.String(24), nullable=True))
    op.add_column("authorization_requests", sa.Column("risk_score", sa.Integer(), nullable=True))
    op.add_column("authorization_requests", sa.Column("risk_level", sa.String(16), nullable=True))
    op.add_column("authorization_requests", sa.Column("risk_recommendation", sa.String(24), nullable=True))

    op.create_table(
        "risk_assessments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("request_id", sa.String(28), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=True),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("permission_id", sa.Uuid(), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("risk_level", sa.Enum("LOW", "MEDIUM", "HIGH", "CRITICAL", name="risk_level", native_enum=False, create_constraint=True), nullable=False),
        sa.Column("decision_recommendation", sa.Enum("ALLOW", "REQUIRE_APPROVAL", "REJECT", name="risk_action", native_enum=False, create_constraint=True), nullable=False),
        sa.Column("reasons", sa.JSON(), nullable=False),
        sa.Column("features", sa.JSON(), nullable=False),
        sa.Column("model_version", sa.String(40), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("request_id ~ '^req_[0-9a-f]{24}$'", name="request_id_format"),
        sa.CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="score_range"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["permission_id"], ["permissions.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("request_id"),
    )
    op.create_index("ix_risk_assessments_user_created", "risk_assessments", ["user_id", "created_at"])
    op.create_index("ix_risk_assessments_org_created", "risk_assessments", ["organization_id", "created_at"])
    op.create_index("ix_risk_assessments_agent_created", "risk_assessments", ["agent_id", "created_at"])
    op.create_index("ix_risk_assessments_org_level_created", "risk_assessments", ["organization_id", "risk_level", "created_at"])

    op.create_table(
        "risk_policies",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=True),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("medium_action", sa.Enum("ALLOW", "REQUIRE_APPROVAL", "REJECT", name="risk_policy_medium_action", native_enum=False, create_constraint=True), server_default="ALLOW", nullable=False),
        sa.Column("high_action", sa.Enum("ALLOW", "REQUIRE_APPROVAL", "REJECT", name="risk_policy_high_action", native_enum=False, create_constraint=True), server_default="REQUIRE_APPROVAL", nullable=False),
        sa.Column("critical_action", sa.Enum("ALLOW", "REQUIRE_APPROVAL", "REJECT", name="risk_policy_critical_action", native_enum=False, create_constraint=True), server_default="REJECT", nullable=False),
        sa.Column("amount_anomaly_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("velocity_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("rejection_history_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("(organization_id IS NULL) <> (user_id IS NULL)", name="one_scope"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("uq_risk_policies_organization", "risk_policies", ["organization_id"], unique=True)
    op.create_index("uq_risk_policies_user", "risk_policies", ["user_id"], unique=True)

    op.drop_constraint(op.f("ck_notifications_notification_type"), "notifications", type_="check")
    op.alter_column("notifications", "type", type_=sa.String(40), existing_type=sa.String(22), nullable=False)
    op.create_check_constraint(
        "notification_type", "notifications",
        "type IN ('authorization_pending','authorization_approved','authorization_rejected','permission_expiring','permission_expired','agent_suspended','agent_revoked','api_key_revoked','security_alert','team_invitation','high_risk_approval_required')",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_notifications_notification_type"), "notifications", type_="check")
    op.alter_column("notifications", "type", type_=sa.String(22), existing_type=sa.String(40), nullable=False)
    op.create_check_constraint(
        "notification_type", "notifications",
        "type IN ('authorization_pending','authorization_approved','authorization_rejected','permission_expiring','permission_expired','agent_suspended','agent_revoked','api_key_revoked','security_alert','team_invitation')",
    )
    op.drop_index("uq_risk_policies_user", table_name="risk_policies")
    op.drop_index("uq_risk_policies_organization", table_name="risk_policies")
    op.drop_table("risk_policies")
    op.drop_index("ix_risk_assessments_org_level_created", table_name="risk_assessments")
    op.drop_index("ix_risk_assessments_agent_created", table_name="risk_assessments")
    op.drop_index("ix_risk_assessments_org_created", table_name="risk_assessments")
    op.drop_index("ix_risk_assessments_user_created", table_name="risk_assessments")
    op.drop_table("risk_assessments")
    op.drop_column("authorization_requests", "risk_recommendation")
    op.drop_column("authorization_requests", "risk_level")
    op.drop_column("authorization_requests", "risk_score")
    op.drop_column("audit_logs", "risk_recommendation")
    op.drop_column("audit_logs", "risk_level")
    op.drop_column("audit_logs", "risk_score")
    op.execute("DROP INDEX IF EXISTS ix_audit_logs_agent_decision_requested")
