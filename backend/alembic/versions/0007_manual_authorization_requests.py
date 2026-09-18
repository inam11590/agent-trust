"""Add opt-in manual approval requests.

Revision ID: 0007
Revises: 0006
"""

from alembic import op
import sqlalchemy as sa

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "permissions",
        sa.Column("requires_approval", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )
    op.create_table(
        "authorization_requests",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("request_id", sa.String(28), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("permission_id", sa.Uuid(), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("resource", sa.String(64), nullable=False),
        sa.Column("amount", sa.Numeric(19, 4), nullable=True),
        sa.Column("currency", sa.String(3), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "PENDING",
                "APPROVED",
                "REJECTED",
                "EXPIRED",
                name="authorization_request_status",
                native_enum=False,
                create_constraint=True,
            ),
            server_default="PENDING",
            nullable=False,
        ),
        sa.Column("reason", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("request_id ~ '^req_[0-9a-f]{24}$'", name="request_id_format"),
        sa.CheckConstraint("amount IS NULL OR amount >= 0", name="amount_not_negative"),
        sa.CheckConstraint("(amount IS NULL) = (currency IS NULL)", name="amount_currency_pair"),
        sa.CheckConstraint("currency IS NULL OR currency ~ '^[A-Z]{3}$'", name="currency_format"),
        sa.CheckConstraint("expires_at > created_at", name="valid_expiry"),
        sa.CheckConstraint(
            "(status = 'PENDING' AND decided_at IS NULL) OR "
            "(status <> 'PENDING' AND decided_at IS NOT NULL)",
            name="decision_timestamp",
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"], ["agents.id"], name="fk_authorization_requests_agent_id_agents", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["permission_id"], ["permissions.id"], name="fk_authorization_requests_permission_id_permissions", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_authorization_requests_user_id_users", ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_authorization_requests"),
        sa.UniqueConstraint("request_id", name="uq_authorization_requests_request_id"),
    )
    op.create_index(
        "ix_authorization_requests_user_status_created",
        "authorization_requests",
        ["user_id", "status", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("authorization_requests")
    op.drop_column("permissions", "requires_approval")
