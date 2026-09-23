"""Models for Step 30: Trusted Agent-to-Agent Communication & Service Registry."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import secrets
from typing import TYPE_CHECKING, Any, Dict, List, Optional
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
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base

if TYPE_CHECKING:
    from app.models.agent import Agent
    from app.models.agenttrust_protocol import AgentCapability
    from app.models.organization import Organization


class ServiceStatus(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    DISABLED = "DISABLED"
    RETIRED = "RETIRED"


class ServiceVisibility(str, Enum):
    PRIVATE = "PRIVATE"
    ORGANIZATION = "ORGANIZATION"
    TRUSTED_ORGANIZATIONS = "TRUSTED_ORGANIZATIONS"
    PUBLIC_DISCOVERABLE = "PUBLIC_DISCOVERABLE"


class EndpointProtocol(str, Enum):
    HTTPS = "HTTPS"
    AGENTTRUST_GATEWAY = "AGENTTRUST_GATEWAY"
    SIDECAR = "SIDECAR"
    INTERNAL_ROUTE = "INTERNAL_ROUTE"


class EndpointHealthStatus(str, Enum):
    UNKNOWN = "UNKNOWN"
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"


class AgentService(Base):
    """Tenant-isolated, agent-hosted Service published in the Service Registry."""
    __tablename__ = "agent_services"
    __table_args__ = (
        Index("ix_agent_services_org_status", "organization_id", "status"),
        Index("ix_agent_services_agent", "agent_id"),
        Index("ix_agent_services_name", "organization_id", "name", unique=True),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    service_id: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, default=lambda: f"svc_{uuid4().hex[:16]}", nullable=False
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    version: Mapped[str] = mapped_column(String(32), default="1.0.0", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default=ServiceStatus.ACTIVE.value, nullable=False)
    visibility: Mapped[str] = mapped_column(
        String(32), default=ServiceVisibility.ORGANIZATION.value, nullable=False
    )
    environment: Mapped[str] = mapped_column(String(32), default="production", nullable=False)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

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
    capabilities: Mapped[List[AgentCapability]] = relationship(
        "AgentCapability", back_populates="service", cascade="all, delete-orphan"
    )
    endpoints: Mapped[List[AgentServiceEndpoint]] = relationship(
        "AgentServiceEndpoint", back_populates="service", cascade="all, delete-orphan"
    )


class AgentServiceEndpoint(Base):
    """Network-routable, verified endpoint destination for an AgentService."""
    __tablename__ = "agent_service_endpoints"
    __table_args__ = (
        Index("ix_service_ep_service_prio", "service_id", "priority"),
        Index("ix_service_ep_health", "service_id", "health_status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    endpoint_id: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, default=lambda: f"ep_{uuid4().hex[:16]}", nullable=False
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    service_id: Mapped[UUID] = mapped_column(
        ForeignKey("agent_services.id", ondelete="CASCADE"), index=True, nullable=False
    )
    agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), index=True, nullable=False
    )

    protocol: Mapped[str] = mapped_column(
        String(32), default=EndpointProtocol.HTTPS.value, nullable=False
    )
    url: Mapped[str] = mapped_column(String(1024), nullable=False)
    environment: Mapped[str] = mapped_column(String(32), default="production", nullable=False)

    priority: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    weight: Mapped[int] = mapped_column(Integer, default=100, nullable=False)

    health_status: Mapped[str] = mapped_column(
        String(32), default=EndpointHealthStatus.UNKNOWN.value, nullable=False
    )
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_health_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    verification_challenge: Mapped[str | None] = mapped_column(String(128), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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

    service: Mapped[AgentService] = relationship("AgentService", back_populates="endpoints")
    agent: Mapped[Agent] = relationship("Agent", foreign_keys=[agent_id])
    organization: Mapped[Organization] = relationship("Organization", foreign_keys=[organization_id])


class ServiceVerificationChallenge(Base):
    """Cryptographic challenge issued to verify Agent ownership of an endpoint."""
    __tablename__ = "service_verification_challenges"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    challenge_id: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, default=lambda: f"ch_{uuid4().hex[:16]}", nullable=False
    )
    endpoint_id: Mapped[UUID] = mapped_column(
        ForeignKey("agent_service_endpoints.id", ondelete="CASCADE"), index=True, nullable=False
    )
    challenge_token: Mapped[str] = mapped_column(
        String(128), default=lambda: f"svc_ch_{secrets.token_hex(24)}", nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), default="PENDING", nullable=False)  # PENDING, VERIFIED, EXPIRED
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class AgentCallRecord(Base):
    """Immutable audit and telemetry trace of an agent-to-agent invocation."""
    __tablename__ = "agent_call_records"
    __table_args__ = (
        Index("ix_call_rec_src_target", "source_agent_id", "target_agent_id"),
        Index("ix_call_rec_created", "created_at"),
        Index("ix_call_rec_service", "service_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    call_id: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, default=lambda: f"call_{uuid4().hex[:16]}", nullable=False
    )
    message_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)

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
    service_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("agent_services.id", ondelete="SET NULL"), nullable=True
    )

    capability_name: Mapped[str] = mapped_column(String(128), nullable=False)
    call_chain: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    depth: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    status: Mapped[str] = mapped_column(
        String(32), default="COMPLETED", nullable=False
    )  # COMPLETED, FAILED, LOOP_PREVENTED, DEPTH_EXCEEDED, PENDING_APPROVAL
    decision_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    response_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
