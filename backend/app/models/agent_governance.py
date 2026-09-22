"""Enterprise Agent Lifecycle Governance models.

Tracks ownership history, periodic access certification reviews,
and organization-level governance policies.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Enum as SqlEnum, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, UUIDTimestampMixin

if TYPE_CHECKING:
    from app.models.agent import Agent
    from app.models.organization import Organization
    from app.models.user import User


class OwnerType(str, Enum):
    USER = "USER"
    TEAM = "TEAM"
    SERVICE_OWNER = "SERVICE_OWNER"


class CertificationStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ExpiryBehavior(str, Enum):
    ALERT_ONLY = "ALERT_ONLY"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    SUSPEND = "SUSPEND"


class AgentOwnershipHistory(UUIDTimestampMixin, Base):
    """Audit trail of agent ownership transfers."""

    __tablename__ = "agent_ownership_history"
    __table_args__ = (
        Index("ix_agent_ownership_hist_agent", "agent_id", "created_at"),
        Index("ix_agent_ownership_hist_org", "organization_id"),
    )

    agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    old_owner_type: Mapped[str] = mapped_column(String(32), nullable=False)
    old_owner_id: Mapped[str] = mapped_column(String(255), nullable=False)
    new_owner_type: Mapped[str] = mapped_column(String(32), nullable=False)
    new_owner_id: Mapped[str] = mapped_column(String(255), nullable=False)
    changed_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False
    )

    agent: Mapped[Agent] = relationship("Agent", back_populates="ownership_history")
    changer: Mapped[User | None] = relationship("User")


class AgentCertification(UUIDTimestampMixin, Base):
    """Periodic access and posture certification record for an agent."""

    __tablename__ = "agent_certifications"
    __table_args__ = (
        Index("ix_agent_cert_org_status", "organization_id", "status"),
        Index("ix_agent_cert_agent", "agent_id", "created_at"),
    )

    certification_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[CertificationStatus] = mapped_column(
        SqlEnum(CertificationStatus, name="cert_status", native_enum=False, create_constraint=False),
        default=CertificationStatus.PENDING,
        nullable=False,
    )
    reviewer_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False
    )
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decision: Mapped[str | None] = mapped_column(String(32), nullable=True)  # APPROVED, REJECTED, EXPIRED
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    snapshot_reference: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, server_default="{}")

    agent: Mapped[Agent] = relationship("Agent", back_populates="certifications")
    reviewer: Mapped[User | None] = relationship("User")


class AgentGovernancePolicy(UUIDTimestampMixin, Base):
    """Organization-level agent governance policies and review thresholds."""

    __tablename__ = "agent_governance_policies"
    __table_args__ = (
        Index("ix_agent_gov_pol_org", "organization_id", unique=True),
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    periodic_review_days: Mapped[int] = mapped_column(Integer, default=90, nullable=False)
    expiry_behavior: Mapped[ExpiryBehavior] = mapped_column(
        SqlEnum(ExpiryBehavior, name="expiry_behavior", native_enum=False, create_constraint=False),
        default=ExpiryBehavior.ALERT_ONLY,
        nullable=False,
    )
    dormancy_days: Mapped[int] = mapped_column(Integer, default=90, nullable=False)
    enforce_separation_of_duties: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    require_classification_on_promotion: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    require_purpose_on_promotion: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    organization: Mapped[Organization] = relationship("Organization")
