"""Developer credentials, request ownership, and webhook delivery records."""

from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, Enum as SqlEnum, ForeignKey, Index, Integer, String, Text, Uuid, func, text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, UUIDTimestampMixin


class APIKeyStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class APIKey(UUIDTimestampMixin, Base):
    __tablename__ = "api_keys"
    __table_args__ = (
        Index("ix_api_keys_creator_status", "created_by_user_id", "status"),
        Index("ix_api_keys_org_env", "organization_id", "environment"),
    )

    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=True, index=True,
    )
    created_by_user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True,
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    environment: Mapped[str] = mapped_column(String(16), server_default="production", default="production", nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    status: Mapped[APIKeyStatus] = mapped_column(
        SqlEnum(APIKeyStatus, name="api_key_status", native_enum=False, create_constraint=True,
                values_callable=lambda values: [value.value for value in values]),
        server_default="active", nullable=False,
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class DeveloperRequest(Base):
    __tablename__ = "developer_requests"
    __table_args__ = (
        Index("ix_developer_requests_api_created", "api_key_id", "created_at"),
        Index("uq_developer_requests_api_idempotency", "api_key_id", "idempotency_hash", unique=True),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    api_key_id: Mapped[UUID] = mapped_column(
        ForeignKey("api_keys.id", ondelete="RESTRICT"), nullable=False,
    )
    idempotency_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(28), unique=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )


class WebhookStatus(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"


class WebhookEndpoint(UUIDTimestampMixin, Base):
    __tablename__ = "webhook_endpoints"

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), unique=True, nullable=False,
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    environment: Mapped[str] = mapped_column(String(16), server_default="production", default="production", nullable=False)
    secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[WebhookStatus] = mapped_column(
        SqlEnum(WebhookStatus, name="webhook_status", native_enum=False, create_constraint=True,
                values_callable=lambda values: [value.value for value in values]),
        server_default="active", nullable=False,
    )


class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"
    __table_args__ = (
        Index("ix_webhook_deliveries_endpoint_created", "webhook_endpoint_id", "created_at"),
        Index("ix_webhook_deliveries_status_next", "status", "next_attempt_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    webhook_endpoint_id: Mapped[UUID] = mapped_column(
        ForeignKey("webhook_endpoints.id", ondelete="RESTRICT"), nullable=False,
    )
    request_id: Mapped[str] = mapped_column(String(28), nullable=False)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    is_test: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), default=False, nullable=False)
    status: Mapped[str] = mapped_column(String(20), server_default="pending", nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
