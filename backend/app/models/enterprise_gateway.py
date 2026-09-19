"""Enterprise Gateway and Configuration Bundle models (Step 23).

Defines the Control Plane models for managing self-hosted gateways, sidecars,
enrollment tokens, mutual public key identities, and signed configuration bundles.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import secrets
from typing import TYPE_CHECKING, Any, Dict, Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    DateTime,
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
    from app.models.organization import Organization
    from app.models.user import User


class GatewayDeploymentType(str, Enum):
    SELF_HOSTED_GATEWAY = "SELF_HOSTED_GATEWAY"
    SIDECAR = "SIDECAR"
    CLOUD_GATEWAY = "CLOUD_GATEWAY"


class GatewayEnvironment(str, Enum):
    PRODUCTION = "PRODUCTION"
    SANDBOX = "SANDBOX"


class GatewayStatus(str, Enum):
    ENROLLING = "ENROLLING"
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"
    UPGRADE_REQUIRED = "UPGRADE_REQUIRED"


class GatewayOfflinePolicy(str, Enum):
    FAIL_CLOSED = "FAIL_CLOSED"
    LIMITED_OFFLINE = "LIMITED_OFFLINE"


def generate_gateway_id() -> str:
    """Generate a stable, secure public identifier for an Enterprise Gateway."""
    return f"gw_{secrets.token_hex(8)}"


def generate_enrollment_token() -> str:
    """Generate a high-entropy single-use enrollment token."""
    return f"gw_tok_{secrets.token_hex(24)}"


class EnterpriseGateway(Base):
    """Authoritative Control Plane registration record for an Enterprise Gateway or Sidecar."""
    __tablename__ = "enterprise_gateways"
    __table_args__ = (
        Index("ix_enterprise_gateways_org_env", "organization_id", "environment"),
        Index("ix_enterprise_gateways_status", "status"),
        Index("ix_enterprise_gateways_last_seen", "last_seen_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    gateway_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False, default=generate_gateway_id)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    deployment_type: Mapped[str] = mapped_column(
        String(32), default=GatewayDeploymentType.SELF_HOSTED_GATEWAY.value, nullable=False
    )
    environment: Mapped[str] = mapped_column(
        String(32), default=GatewayEnvironment.PRODUCTION.value, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(32), default=GatewayStatus.ENROLLING.value, nullable=False
    )
    version: Mapped[str] = mapped_column(String(32), default="1.0.0", nullable=False)
    
    # Cryptographic identity: Ed25519 public key generated locally by the Gateway
    public_key: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    fingerprint: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    
    # One-time enrollment token: only SHA-256 hash is persisted server-side
    enrollment_token_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    enrollment_token_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    config_version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    labels: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    offline_policy: Mapped[str] = mapped_column(
        String(32), default=GatewayOfflinePolicy.FAIL_CLOSED.value, nullable=False
    )
    
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_heartbeat_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    suspended_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    organization: Mapped[Organization] = relationship("Organization", foreign_keys=[organization_id])


class GatewayConfigBundle(Base):
    """Authoritative versioned, signed configuration bundle published by the Control Plane."""
    __tablename__ = "gateway_config_bundles"
    __table_args__ = (
        Index("ix_config_bundles_org_ver", "organization_id", "config_version", unique=True),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    environment: Mapped[str] = mapped_column(String(32), default="production", nullable=False)
    config_version: Mapped[int] = mapped_column(Integer, nullable=False)
    bundle_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    bundle_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    published_by_user_id: Mapped[Optional[UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    organization: Mapped[Organization] = relationship("Organization", foreign_keys=[organization_id])
