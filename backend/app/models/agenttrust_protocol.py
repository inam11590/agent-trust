"""Models for Step 21: AgentTrust Protocol (ATP/1.0) and Gateway."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import secrets
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base

if TYPE_CHECKING:
    from app.models.agent import Agent
    from app.models.agent_service import AgentService
    from app.models.organization import Organization


class EndpointStatus(str, Enum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    DISABLED = "DISABLED"


class ATPDeliveryStatus(str, Enum):
    PENDING = "PENDING"
    DELIVERING = "DELIVERING"
    DELIVERED = "DELIVERED"
    RETRYING = "RETRYING"
    FAILED = "FAILED"


class AgentEndpoint(Base):
    """Registered controlled HTTP(S) destination for target AI agents."""
    __tablename__ = "agent_endpoints"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    endpoint_url: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default=EndpointStatus.PENDING.value, nullable=False)
    verification_token: Mapped[str] = mapped_column(
        String(128), default=lambda: f"vtok_{secrets.token_hex(24)}", nullable=False
    )
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    agent: Mapped[Agent] = relationship("Agent", foreign_keys=[agent_id])
    organization: Mapped[Organization] = relationship("Organization", foreign_keys=[organization_id])


class AgentCapability(Base):
    """Versioned public capabilities published by an agent or service."""
    __tablename__ = "agent_capabilities"
    __table_args__ = (
        Index("ix_agent_cap_name_ver", "agent_id", "name", "version", unique=True),
        Index("ix_agent_cap_service", "service_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    capability_id: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, default=lambda: f"cap_{uuid4().hex[:16]}", nullable=False
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    service_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("agent_services.id", ondelete="CASCADE"), index=True, nullable=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(32), default="1.0", nullable=False)
    description: Mapped[str | None] = mapped_column(String(512), nullable=True)
    input_schema: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    output_schema: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    risk_classification: Mapped[str] = mapped_column(String(32), default="LOW", nullable=False)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    approval_threshold_amount: Mapped[float | None] = mapped_column(Float, nullable=True)
    rate_limit_per_minute: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    agent: Mapped[Agent] = relationship("Agent", foreign_keys=[agent_id])
    service: Mapped[AgentService | None] = relationship("AgentService", back_populates="capabilities")


class ATPMessageRecord(Base):
    """Authoritative record of ATP/1.0 messages routed through the Gateway."""
    __tablename__ = "atp_messages"
    __table_args__ = (
        Index("ix_atp_messages_source", "source_organization_id", "created_at"),
        Index("ix_atp_messages_target", "target_organization_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    message_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    atp_version: Mapped[str] = mapped_column(String(16), default="1.0", nullable=False)
    message_type: Mapped[str] = mapped_column(String(32), default="request", nullable=False)

    source_organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    source_agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="RESTRICT"), nullable=False
    )
    target_organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=True
    )
    target_agent_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("agents.id", ondelete="RESTRICT"), nullable=True
    )

    capability: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", nullable=False)
    decision_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)

    idempotency_key: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    idempotency_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    payload_summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    attestation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ATPMessageDelivery(Base):
    """Delivery lifecycle tracking for routed ATP requests."""
    __tablename__ = "atp_message_deliveries"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    message_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("atp_messages.message_id", ondelete="CASCADE"), index=True, nullable=False
    )
    target_endpoint_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("agent_endpoints.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(32), default=ATPDeliveryStatus.PENDING.value, nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(512), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
