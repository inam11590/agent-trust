"""Add developer API keys, idempotency, and webhook foundations.

Revision ID: 0008
Revises: 0007
"""

from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("organizations", sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False))
    op.create_table(
        "api_keys",
        sa.Column("organization_id", sa.Uuid(), nullable=True),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("key_prefix", sa.String(20), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.Enum("active", "revoked", "expired", name="api_key_status", native_enum=False, create_constraint=True), server_default="active", nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], name="fk_api_keys_created_by_user_id_users", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], name="fk_api_keys_organization_id_organizations", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name="pk_api_keys"),
        sa.UniqueConstraint("key_hash", name="uq_api_keys_key_hash"),
        sa.UniqueConstraint("key_prefix", name="uq_api_keys_key_prefix"),
    )
    op.create_index("ix_api_keys_created_by_user_id", "api_keys", ["created_by_user_id"])
    op.create_index("ix_api_keys_organization_id", "api_keys", ["organization_id"])
    op.create_index("ix_api_keys_creator_status", "api_keys", ["created_by_user_id", "status"])
    op.create_table(
        "developer_requests",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("api_key_id", sa.Uuid(), nullable=False),
        sa.Column("idempotency_hash", sa.String(64), nullable=True),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("request_id", sa.String(28), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["api_key_id"], ["api_keys.id"], name="fk_developer_requests_api_key_id_api_keys", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name="pk_developer_requests"),
        sa.UniqueConstraint("request_id", name="uq_developer_requests_request_id"),
    )
    op.create_index("ix_developer_requests_api_created", "developer_requests", ["api_key_id", "created_at"])
    op.create_index("uq_developer_requests_api_idempotency", "developer_requests", ["api_key_id", "idempotency_hash"], unique=True)
    op.create_table(
        "webhook_endpoints",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("secret_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.Enum("active", "disabled", name="webhook_status", native_enum=False, create_constraint=True), server_default="active", nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], name="fk_webhook_endpoints_organization_id_organizations", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name="pk_webhook_endpoints"),
        sa.UniqueConstraint("organization_id", name="uq_webhook_endpoints_organization_id"),
    )
    op.create_table(
        "webhook_deliveries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("webhook_endpoint_id", sa.Uuid(), nullable=False),
        sa.Column("request_id", sa.String(28), nullable=False),
        sa.Column("event_type", sa.String(80), nullable=False),
        sa.Column("status", sa.String(20), server_default="pending", nullable=False),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["webhook_endpoint_id"], ["webhook_endpoints.id"], name="fk_webhook_deliveries_webhook_endpoint_id_webhook_endpoints", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name="pk_webhook_deliveries"),
    )
    op.create_index("ix_webhook_deliveries_endpoint_created", "webhook_deliveries", ["webhook_endpoint_id", "created_at"])


def downgrade() -> None:
    op.drop_table("webhook_deliveries")
    op.drop_table("webhook_endpoints")
    op.drop_table("developer_requests")
    op.drop_table("api_keys")
    op.drop_column("organizations", "is_active")
