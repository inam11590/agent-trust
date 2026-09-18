"""Create users, organizations, and agents.

Revision ID: 0001
Revises: None
"""

from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def timestamps():
    return [
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(200), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        *timestamps(),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_table(
        "organizations",
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        *timestamps(),
        sa.PrimaryKeyConstraint("id", name="pk_organizations"),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], name="fk_organizations_owner_id_users", ondelete="RESTRICT"),
    )
    op.create_index("ix_organizations_owner_id", "organizations", ["owner_id"])
    op.create_table(
        "agents",
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("agent_identifier", sa.String(255), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.Enum("active", "inactive", "suspended", name="agent_status", native_enum=False, create_constraint=True), server_default="inactive", nullable=False),
        *timestamps(),
        sa.PrimaryKeyConstraint("id", name="pk_agents"),
        sa.UniqueConstraint("agent_identifier", name="uq_agents_agent_identifier"),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], name="fk_agents_owner_id_users", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], name="fk_agents_organization_id_organizations", ondelete="SET NULL"),
    )
    op.create_index("ix_agents_owner_id", "agents", ["owner_id"])
    op.create_index("ix_agents_organization_id", "agents", ["organization_id"])


def downgrade() -> None:
    op.drop_table("agents")
    op.drop_table("organizations")
    op.drop_table("users")
