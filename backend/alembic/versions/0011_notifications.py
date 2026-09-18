"""Add notification records, preferences, devices, and delivery queue.

Revision ID: 0011
Revises: 0010
"""

from alembic import op
import sqlalchemy as sa

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("permissions", sa.Column("expiry_warning_sent_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("permissions", sa.Column("expiry_notification_sent_at", sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        "notifications",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=True),
        sa.Column("type", sa.Enum("authorization_pending", "authorization_approved", "authorization_rejected", "permission_expiring", "permission_expired", "agent_suspended", "agent_revoked", "api_key_revoked", "security_alert", "team_invitation", name="notification_type", native_enum=False, create_constraint=True), nullable=False),
        sa.Column("title", sa.String(160), nullable=False), sa.Column("message", sa.String(500), nullable=False),
        sa.Column("status", sa.Enum("unread", "read", "archived", name="notification_status", native_enum=False, create_constraint=True), server_default="unread", nullable=False),
        sa.Column("priority", sa.Enum("low", "normal", "high", "critical", name="notification_priority", native_enum=False, create_constraint=True), server_default="normal", nullable=False),
        sa.Column("related_request_id", sa.Uuid(), nullable=True), sa.Column("related_agent_id", sa.Uuid(), nullable=True),
        sa.Column("related_permission_id", sa.Uuid(), nullable=True), sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("deduplication_key", sa.String(180), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["related_request_id"], ["authorization_requests.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["related_agent_id"], ["agents.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["related_permission_id"], ["permissions.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("deduplication_key"),
    )
    op.create_index("ix_notifications_user_status_created", "notifications", ["user_id", "status", "created_at"])
    op.create_index("ix_notifications_org_created", "notifications", ["organization_id", "created_at"])
    op.create_table(
        "notification_preferences",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("push_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("email_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("in_app_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("security_email_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("approval_push_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("approval_email_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("permission_expiry_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("general_activity_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("user_id"),
    )
    op.create_table(
        "devices",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("push_token", sa.Text(), nullable=False),
        sa.Column("platform", sa.Enum("android", "ios", name="device_platform", native_enum=False, create_constraint=True), nullable=False),
        sa.Column("device_name", sa.String(120), nullable=True),
        sa.Column("status", sa.Enum("active", "revoked", name="device_status", native_enum=False, create_constraint=True), server_default="active", nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("push_token"),
    )
    op.create_index("ix_devices_user_status", "devices", ["user_id", "status"])
    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("notification_id", sa.Uuid(), nullable=False),
        sa.Column("channel", sa.Enum("in_app", "push", "email", name="notification_delivery_channel", native_enum=False, create_constraint=True), nullable=False),
        sa.Column("status", sa.Enum("pending", "sent", "delivered", "failed", name="notification_delivery_status", native_enum=False, create_constraint=True), server_default="pending", nullable=False),
        sa.Column("provider_message_id", sa.String(255), nullable=True),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_error", sa.String(255), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["notification_id"], ["notifications.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_notification_deliveries_status_next", "notification_deliveries", ["status", "next_attempt_at"])
    op.create_index("ix_notification_deliveries_notification", "notification_deliveries", ["notification_id", "channel"])


def downgrade() -> None:
    op.drop_index("ix_notification_deliveries_notification", table_name="notification_deliveries")
    op.drop_index("ix_notification_deliveries_status_next", table_name="notification_deliveries")
    op.drop_table("notification_deliveries")
    op.drop_index("ix_devices_user_status", table_name="devices")
    op.drop_table("devices")
    op.drop_table("notification_preferences")
    op.drop_index("ix_notifications_org_created", table_name="notifications")
    op.drop_index("ix_notifications_user_status_created", table_name="notifications")
    op.drop_table("notifications")
    op.drop_column("permissions", "expiry_notification_sent_at")
    op.drop_column("permissions", "expiry_warning_sent_at")
