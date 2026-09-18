"""Add organization teams, invitations, security events, and login protection.

Revision ID: 0009
Revises: 0008
"""

from datetime import datetime, timezone
from uuid import uuid4

from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("failed_login_attempts", sa.Integer(), server_default="0", nullable=False))
    op.add_column("users", sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        "organization_members",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.Enum("owner", "admin", "developer", "viewer", name="organization_role", native_enum=False, create_constraint=True), nullable=False),
        sa.Column("status", sa.Enum("active", "removed", name="organization_member_status", native_enum=False, create_constraint=True), server_default="active", nullable=False),
        sa.Column("invited_by", sa.Uuid(), nullable=True),
        sa.Column("joined_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], name="fk_organization_members_organization_id_organizations", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name="fk_organization_members_user_id_users", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["invited_by"], ["users.id"], name="fk_organization_members_invited_by_users", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name="pk_organization_members"),
        sa.UniqueConstraint("organization_id", "user_id", name="uq_organization_members_org_user"),
    )
    op.create_index("ix_organization_members_organization_id", "organization_members", ["organization_id"])
    op.create_index("ix_organization_members_user_status", "organization_members", ["user_id", "status"])
    op.create_table(
        "organization_invitations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("role", sa.Enum("owner", "admin", "developer", "viewer", name="organization_invitation_role", native_enum=False, create_constraint=True), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.Enum("pending", "accepted", "expired", "revoked", name="organization_invitation_status", native_enum=False, create_constraint=True), server_default="pending", nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("invited_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], name="fk_organization_invitations_organization_id_organizations", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["invited_by"], ["users.id"], name="fk_organization_invitations_invited_by_users", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name="pk_organization_invitations"),
        sa.UniqueConstraint("token_hash", name="uq_organization_invitations_token_hash"),
    )
    op.create_index("ix_organization_invitations_org_status", "organization_invitations", ["organization_id", "status"])
    op.create_index("ix_organization_invitations_email_status", "organization_invitations", ["email", "status"])
    op.create_table(
        "security_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=True),
        sa.Column("actor_user_id", sa.Uuid(), nullable=False),
        sa.Column("target_user_id", sa.Uuid(), nullable=True),
        sa.Column("event_type", sa.String(80), nullable=False),
        sa.Column("description", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], name="fk_security_events_organization_id_organizations", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], name="fk_security_events_actor_user_id_users", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["target_user_id"], ["users.id"], name="fk_security_events_target_user_id_users", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name="pk_security_events"),
    )
    op.create_index("ix_security_events_org_created", "security_events", ["organization_id", "created_at"])
    op.create_index("ix_security_events_actor_created", "security_events", ["actor_user_id", "created_at"])

    bind = op.get_bind()
    organizations = bind.execute(sa.text("SELECT id, owner_id FROM organizations")).fetchall()
    if organizations:
        table = sa.table(
            "organization_members",
            sa.column("id", sa.Uuid()), sa.column("organization_id", sa.Uuid()),
            sa.column("user_id", sa.Uuid()), sa.column("role", sa.String()),
            sa.column("status", sa.String()), sa.column("invited_by", sa.Uuid()),
            sa.column("joined_at", sa.DateTime(timezone=True)), sa.column("created_at", sa.DateTime(timezone=True)),
        )
        now = datetime.now(timezone.utc)
        op.bulk_insert(table, [{
            "id": uuid4(), "organization_id": row.id, "user_id": row.owner_id,
            "role": "owner", "status": "active", "invited_by": None,
            "joined_at": now, "created_at": now,
        } for row in organizations])


def downgrade() -> None:
    op.drop_table("security_events")
    op.drop_table("organization_invitations")
    op.drop_table("organization_members")
    op.drop_column("users", "locked_until")
    op.drop_column("users", "failed_login_attempts")
