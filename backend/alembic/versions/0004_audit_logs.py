"""Create immutable authorization audit history.

Revision ID: 0004
Revises: 0003
"""

from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("request_id", sa.String(28), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=True),
        sa.Column("agent_identifier", sa.String(255), nullable=False),
        sa.Column("permission_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("resource", sa.String(64), nullable=False),
        sa.Column("amount", sa.Numeric(19, 4), nullable=True),
        sa.Column("currency", sa.String(3), nullable=True),
        sa.Column(
            "decision",
            sa.Enum(
                "APPROVED",
                "REJECTED",
                name="audit_decision",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column("reason", sa.String(255), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("request_id ~ '^req_[0-9a-f]{24}$'", name="request_id_format"),
        sa.CheckConstraint("amount IS NULL OR amount >= 0", name="amount_not_negative"),
        sa.CheckConstraint("(amount IS NULL) = (currency IS NULL)", name="amount_currency_pair"),
        sa.CheckConstraint("currency IS NULL OR currency ~ '^[A-Z]{3}$'", name="currency_format"),
        sa.CheckConstraint("length(action) > 0", name="action_not_empty"),
        sa.CheckConstraint("length(resource) > 0", name="resource_not_empty"),
        sa.ForeignKeyConstraint(
            ["agent_id"], ["agents.id"], name="fk_audit_logs_agent_id_agents", ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["permission_id"], ["permissions.id"], name="fk_audit_logs_permission_id_permissions", ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_audit_logs_user_id_users", ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_logs"),
        sa.UniqueConstraint("request_id", name="uq_audit_logs_request_id"),
    )
    op.create_index(
        "ix_audit_logs_user_requested", "audit_logs", ["user_id", "requested_at"], unique=False,
    )
    op.create_index(
        "ix_audit_logs_user_agent_requested",
        "audit_logs",
        ["user_id", "agent_id", "requested_at"],
        unique=False,
    )
    op.create_index(
        "ix_audit_logs_user_decision_requested",
        "audit_logs",
        ["user_id", "decision", "requested_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("audit_logs")
