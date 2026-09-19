"""Models for Step 20 Cross-Organization Agent-to-Agent Trust."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
import secrets
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum as SqlEnum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    Numeric,
    String,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base

if TYPE_CHECKING:
    from app.models.agent import Agent
    from app.models.organization import Organization
    from app.models.user import User


class TrustStatus(str, Enum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    REJECTED = "REJECTED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    SUSPENDED = "SUSPENDED"


class CrossOrgRequestStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CANCELED = "CANCELED"


class ApprovalStage(str, Enum):
    SOURCE = "SOURCE"
    TARGET = "TARGET"


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


def generate_trust_id() -> str:
    return f"trust_{secrets.token_hex(12)}"


def generate_connection_id() -> str:
    return f"eac_{secrets.token_hex(12)}"


def generate_cross_org_request_id() -> str:
    return f"xreq_{secrets.token_hex(12)}"


class OrganizationTrustRelationship(Base):
    __tablename__ = "organization_trust_relationships"
    __table_args__ = (
        CheckConstraint("trust_id ~ '^trust_[0-9a-f]{24}$'", name="trust_id_format"),
        CheckConstraint(
            "source_organization_id <> target_organization_id",
            name="no_self_organization_trust",
        ),
        UniqueConstraint(
            "source_organization_id",
            "target_organization_id",
            name="uq_source_target_organization_trust",
        ),
        Index("idx_org_trust_source", "source_organization_id", "status"),
        Index("idx_org_trust_target", "target_organization_id", "status"),
        Index("idx_org_trust_lookup", "trust_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    trust_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, default=generate_trust_id)

    source_organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    status: Mapped[TrustStatus] = mapped_column(
        SqlEnum(
            TrustStatus,
            name="trust_relationship_status",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda values: [v.value for v in values],
        ),
        nullable=False,
        default=TrustStatus.PENDING,
    )

    created_by_user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    accepted_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    source_organization: Mapped[Organization] = relationship(
        "Organization",
        foreign_keys=[source_organization_id],
    )
    target_organization: Mapped[Organization] = relationship(
        "Organization",
        foreign_keys=[target_organization_id],
    )
    policy: Mapped[OrganizationTrustPolicy | None] = relationship(
        "OrganizationTrustPolicy",
        back_populates="trust_relationship",
        uselist=False,
        cascade="all, delete-orphan",
    )
    agent_connections: Mapped[list[ExternalAgentConnection]] = relationship(
        "ExternalAgentConnection",
        back_populates="trust_relationship",
        cascade="all, delete-orphan",
    )

    def is_usable(self, checked_at: datetime | None = None) -> bool:
        at = checked_at or datetime.now(timezone.utc)
        if self.status != TrustStatus.ACTIVE:
            return False
        if self.expires_at is not None and self.expires_at <= at:
            return False
        if self.revoked_at is not None and self.revoked_at <= at:
            return False
        return True


class OrganizationTrustPolicy(Base):
    __tablename__ = "organization_trust_policies"
    __table_args__ = (
        CheckConstraint("max_amount IS NULL OR max_amount > 0", name="trust_policy_amount_positive"),
        CheckConstraint(
            "(max_amount IS NULL) = (currency IS NULL)",
            name="trust_policy_amount_currency_pair",
        ),
        CheckConstraint("max_delegation_depth >= 1 AND max_delegation_depth <= 5", name="trust_policy_depth_range"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    trust_relationship_id: Mapped[UUID] = mapped_column(
        ForeignKey("organization_trust_relationships.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )

    allowed_actions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    allowed_resources: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    max_amount: Mapped[Decimal | None] = mapped_column(Numeric(19, 4), nullable=True)
    currency: Mapped[str | None] = mapped_column(String(3), nullable=True)

    require_human_approval: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    approval_threshold: Mapped[Decimal | None] = mapped_column(Numeric(19, 4), nullable=True)
    approval_type: Mapped[str] = mapped_column(String(20), default="TARGET_APPROVAL", nullable=False)

    allow_agent_delegation: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    max_delegation_depth: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    risk_threshold: Mapped[int | None] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    trust_relationship: Mapped[OrganizationTrustRelationship] = relationship(
        "OrganizationTrustRelationship",
        back_populates="policy",
    )


class OrganizationPublicProfile(Base):
    __tablename__ = "organization_public_profiles"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )

    public_name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), default="", nullable=False)
    website_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    discoverable: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    supported_capabilities: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    verification_status: Mapped[str] = mapped_column(String(20), default="UNVERIFIED", nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    organization: Mapped[Organization] = relationship("Organization")


class TargetOrganizationPolicy(Base):
    __tablename__ = "target_organization_policies"
    __table_args__ = (
        CheckConstraint("max_amount IS NULL OR max_amount > 0", name="target_policy_amount_positive"),
        CheckConstraint(
            "(max_amount IS NULL) = (currency IS NULL)",
            name="target_policy_amount_currency_pair",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )

    allowed_actions: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    allowed_resources: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    max_amount: Mapped[Decimal | None] = mapped_column(Numeric(19, 4), nullable=True)
    currency: Mapped[str | None] = mapped_column(String(3), nullable=True)

    require_human_approval: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    approval_threshold: Mapped[Decimal | None] = mapped_column(Numeric(19, 4), nullable=True)
    required_credential_types: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    organization: Mapped[Organization] = relationship("Organization")


class ExternalAgentConnection(Base):
    __tablename__ = "external_agent_connections"
    __table_args__ = (
        CheckConstraint("connection_id ~ '^eac_[0-9a-f]{24}$'", name="connection_id_format"),
        CheckConstraint("source_agent_id <> target_agent_id", name="no_self_agent_connection"),
        UniqueConstraint(
            "trust_relationship_id",
            "source_agent_id",
            "target_agent_id",
            name="uq_trust_source_target_agent_connection",
        ),
        Index("idx_ext_conn_lookup", "connection_id"),
        Index("idx_ext_conn_agents", "source_agent_id", "target_agent_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    connection_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, default=generate_connection_id)

    trust_relationship_id: Mapped[UUID] = mapped_column(
        ForeignKey("organization_trust_relationships.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(String(20), default="ACTIVE", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)

    trust_relationship: Mapped[OrganizationTrustRelationship] = relationship(
        "OrganizationTrustRelationship",
        back_populates="agent_connections",
    )
    source_agent: Mapped[Agent] = relationship("Agent", foreign_keys=[source_agent_id])
    target_agent: Mapped[Agent] = relationship("Agent", foreign_keys=[target_agent_id])

    def is_usable(self, checked_at: datetime | None = None) -> bool:
        at = checked_at or datetime.now(timezone.utc)
        if self.status != "ACTIVE":
            return False
        if self.expires_at is not None and self.expires_at <= at:
            return False
        if self.revoked_at is not None and self.revoked_at <= at:
            return False
        return True


class CrossOrganizationRequest(Base):
    __tablename__ = "cross_organization_requests"
    __table_args__ = (
        CheckConstraint("request_id ~ '^xreq_[0-9a-f]{24}$'", name="cross_org_request_id_format"),
        CheckConstraint("amount IS NULL OR amount > 0", name="cross_org_amount_positive"),
        Index("idx_xreq_lookup", "request_id"),
        Index("idx_xreq_source_org", "source_organization_id", "status"),
        Index("idx_xreq_target_org", "target_organization_id", "status"),
        Index("idx_xreq_idempotency", "source_organization_id", "idempotency_key"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    request_id: Mapped[str] = mapped_column(
        String(32), unique=True, nullable=False, default=generate_cross_org_request_id
    )

    trust_relationship_id: Mapped[UUID] = mapped_column(
        ForeignKey("organization_trust_relationships.id", ondelete="CASCADE"),
        nullable=False,
    )
    connection_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("external_agent_connections.id", ondelete="SET NULL"),
        nullable=True,
    )

    source_organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    source_agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
    )

    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[str] = mapped_column(String(64), nullable=False)
    amount: Mapped[Decimal | None] = mapped_column(Numeric(19, 4), nullable=True)
    currency: Mapped[str | None] = mapped_column(String(3), nullable=True)

    status: Mapped[CrossOrgRequestStatus] = mapped_column(
        SqlEnum(
            CrossOrgRequestStatus,
            name="cross_org_request_status",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda values: [v.value for v in values],
        ),
        default=CrossOrgRequestStatus.PENDING,
        nullable=False,
    )

    decision_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(20), nullable=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)

    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    idempotency_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    trust_relationship: Mapped[OrganizationTrustRelationship] = relationship("OrganizationTrustRelationship")
    connection: Mapped[ExternalAgentConnection | None] = relationship("ExternalAgentConnection")
    source_organization: Mapped[Organization] = relationship("Organization", foreign_keys=[source_organization_id])
    target_organization: Mapped[Organization] = relationship("Organization", foreign_keys=[target_organization_id])
    source_agent: Mapped[Agent] = relationship("Agent", foreign_keys=[source_agent_id])
    target_agent: Mapped[Agent] = relationship("Agent", foreign_keys=[target_agent_id])
    approvals: Mapped[list[CrossOrganizationApproval]] = relationship(
        "CrossOrganizationApproval",
        back_populates="request",
        cascade="all, delete-orphan",
    )


class CrossOrganizationApproval(Base):
    __tablename__ = "cross_organization_approvals"
    __table_args__ = (
        UniqueConstraint(
            "cross_org_request_id",
            "organization_id",
            "approval_stage",
            name="uq_cross_org_req_org_stage",
        ),
        Index("idx_cross_org_appr_org", "organization_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    cross_org_request_id: Mapped[UUID] = mapped_column(
        ForeignKey("cross_organization_requests.id", ondelete="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    approval_stage: Mapped[ApprovalStage] = mapped_column(
        SqlEnum(
            ApprovalStage,
            name="cross_org_approval_stage",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda values: [v.value for v in values],
        ),
        nullable=False,
    )

    required_role: Mapped[str] = mapped_column(String(20), default="admin", nullable=False)
    status: Mapped[ApprovalStatus] = mapped_column(
        SqlEnum(
            ApprovalStatus,
            name="cross_org_approval_status",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda values: [v.value for v in values],
        ),
        default=ApprovalStatus.PENDING,
        nullable=False,
    )

    decided_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    request: Mapped[CrossOrganizationRequest] = relationship("CrossOrganizationRequest", back_populates="approvals")
    organization: Mapped[Organization] = relationship("Organization")
    decided_by: Mapped[User | None] = relationship("User")
