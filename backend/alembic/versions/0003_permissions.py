"""Create time-bound agent permissions.

Revision ID: 0003
Revises: 0002
"""

from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "permissions",
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("resource", sa.String(64), nullable=False),
        sa.Column("maximum_amount", sa.Numeric(19, 4), nullable=True),
        sa.Column("currency", sa.String(3), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "active",
                "revoked",
                "expired",
                name="permission_status",
                native_enum=False,
                create_constraint=True,
            ),
            server_default="active",
            nullable=False,
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "maximum_amount IS NULL OR maximum_amount > 0",
            name="maximum_amount_positive",
        ),
        sa.CheckConstraint(
            "(maximum_amount IS NULL) = (currency IS NULL)",
            name="amount_currency_pair",
        ),
        sa.CheckConstraint(
            "currency IS NULL OR currency ~ '^[A-Z]{3}$'",
            name="currency_format",
        ),
        sa.CheckConstraint(
            "expires_at > valid_from",
            name="valid_time_window",
        ),
        sa.CheckConstraint("length(action) > 0", name="action_not_empty"),
        sa.CheckConstraint("length(resource) > 0", name="resource_not_empty"),
        sa.ForeignKeyConstraint(
            ["agent_id"], ["agents.id"], name="fk_permissions_agent_id_agents", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["owner_id"], ["users.id"], name="fk_permissions_owner_id_users", ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_permissions"),
    )
    op.create_index("ix_permissions_agent_id", "permissions", ["agent_id"])
    op.create_index("ix_permissions_owner_id", "permissions", ["owner_id"])


def downgrade() -> None:
    op.drop_table("permissions")
