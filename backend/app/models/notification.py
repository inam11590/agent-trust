"""User notifications, channel delivery jobs, preferences, and mobile devices."""

from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, Enum as SqlEnum, ForeignKey, Index, Integer, JSON, String, Text, Uuid, func, text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, UUIDTimestampMixin


class NotificationStatus(str, Enum):
    UNREAD = "unread"
    READ = "read"
    ARCHIVED = "archived"


class NotificationPriority(str, Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class NotificationType(str, Enum):
    AUTHORIZATION_PENDING = "authorization_pending"
    AUTHORIZATION_APPROVED = "authorization_approved"
    AUTHORIZATION_REJECTED = "authorization_rejected"
    PERMISSION_EXPIRING = "permission_expiring"
    PERMISSION_EXPIRED = "permission_expired"
    AGENT_SUSPENDED = "agent_suspended"
    AGENT_REVOKED = "agent_revoked"
    API_KEY_REVOKED = "api_key_revoked"
    SECURITY_ALERT = "security_alert"
    TEAM_INVITATION = "team_invitation"
    HIGH_RISK_APPROVAL_REQUIRED = "high_risk_approval_required"
    BILLING_USAGE_WARNING = "billing_usage_warning"
    BILLING_PLAN_CHANGED = "billing_plan_changed"
    BILLING_PAYMENT_FAILED = "billing_payment_failed"
    BILLING_CANCELING = "billing_canceling"


class DeliveryChannel(str, Enum):
    IN_APP = "in_app"
    PUSH = "push"
    EMAIL = "email"


class DeliveryStatus(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    FAILED = "failed"


class DevicePlatform(str, Enum):
    ANDROID = "android"
    IOS = "ios"


class DeviceStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


def _enum(enum_type, name: str, *, length: int | None = None):
    return SqlEnum(
        enum_type, name=name, native_enum=False, create_constraint=True,
        values_callable=lambda values: [value.value for value in values], validate_strings=True,
        length=length,
    )


class Notification(Base):
    __tablename__ = "notifications"
    __table_args__ = (
        Index("ix_notifications_user_status_created", "user_id", "status", "created_at"),
        Index("ix_notifications_org_created", "organization_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=True,
    )
    type: Mapped[NotificationType] = mapped_column(
        _enum(NotificationType, "notification_type", length=40), nullable=False,
    )
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    message: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[NotificationStatus] = mapped_column(
        _enum(NotificationStatus, "notification_status"), server_default="unread", nullable=False,
    )
    priority: Mapped[NotificationPriority] = mapped_column(
        _enum(NotificationPriority, "notification_priority"), server_default="normal", nullable=False,
    )
    related_request_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("authorization_requests.id", ondelete="RESTRICT"), nullable=True,
    )
    related_agent_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("agents.id", ondelete="RESTRICT"), nullable=True,
    )
    related_permission_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("permissions.id", ondelete="RESTRICT"), nullable=True,
    )
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSON, nullable=True)
    deduplication_key: Mapped[str | None] = mapped_column(String(180), unique=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class NotificationPreference(UUIDTimestampMixin, Base):
    __tablename__ = "notification_preferences"

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), unique=True, nullable=False,
    )
    push_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    email_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    in_app_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    security_email_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    approval_push_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    approval_email_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    permission_expiry_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    general_activity_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)


class Device(UUIDTimestampMixin, Base):
    __tablename__ = "devices"
    __table_args__ = (Index("ix_devices_user_status", "user_id", "status"),)

    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    push_token: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    platform: Mapped[DevicePlatform] = mapped_column(_enum(DevicePlatform, "device_platform"), nullable=False)
    device_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    status: Mapped[DeviceStatus] = mapped_column(
        _enum(DeviceStatus, "device_status"), server_default="active", nullable=False,
    )
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"
    __table_args__ = (
        Index("ix_notification_deliveries_status_next", "status", "next_attempt_at"),
        Index("ix_notification_deliveries_notification", "notification_id", "channel"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    notification_id: Mapped[UUID] = mapped_column(
        ForeignKey("notifications.id", ondelete="RESTRICT"), nullable=False,
    )
    channel: Mapped[DeliveryChannel] = mapped_column(
        _enum(DeliveryChannel, "notification_delivery_channel"), nullable=False,
    )
    status: Mapped[DeliveryStatus] = mapped_column(
        _enum(DeliveryStatus, "notification_delivery_status"), server_default="pending", nullable=False,
    )
    provider_message_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    last_error: Mapped[str | None] = mapped_column(String(255), nullable=True)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False,
    )
