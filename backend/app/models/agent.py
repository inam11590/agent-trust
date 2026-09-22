"""Registered agents and their ownership links."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import DateTime, Enum as SqlEnum, ForeignKey, Index, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, UUIDTimestampMixin

if TYPE_CHECKING:
    from app.models.agent_delegation import AgentDelegation
    from app.models.agent_governance import AgentCertification, AgentOwnershipHistory
    from app.models.audit_log import AuditLog
    from app.models.authorization_request import AuthorizationRequestRecord
    from app.models.organization import Organization
    from app.models.permission import Permission
    from app.models.user import User


class AgentStatus(str, Enum):
    DRAFT = "draft"
    REGISTERED = "registered"
    REVIEW_REQUIRED = "review_required"
    APPROVED = "approved"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    RETIREMENT_PENDING = "retirement_pending"
    RETIRED = "retired"
    # Legacy backwards compatibility aliases
    INACTIVE = "inactive"
    REVOKED = "revoked"


class Agent(UUIDTimestampMixin, Base):
    __tablename__ = "agents"
    __table_args__ = (
        Index("ix_agents_org_env", "organization_id", "environment"),
        Index("ix_agents_lifecycle_status", "organization_id", "status"),
        Index("ix_agents_owner_type", "organization_id", "owner_type"),
    )

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    agent_identifier: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    environment: Mapped[str] = mapped_column(String(16), server_default="production", default="production", nullable=False)
    owner_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="SET NULL"), index=True, nullable=True,
    )
    status: Mapped[AgentStatus] = mapped_column(
        SqlEnum(
            AgentStatus, name="agent_status", native_enum=False, create_constraint=False,
            values_callable=lambda values: [value.value for value in values],
            validate_strings=True,
        ),
        server_default="registered", default=AgentStatus.REGISTERED, nullable=False,
    )

    # Step 28: Enterprise Governance Attributes
    owner_type: Mapped[str] = mapped_column(String(32), server_default="USER", default="USER", nullable=False)
    team: Mapped[str | None] = mapped_column(String(128), nullable=True)
    purpose: Mapped[str | None] = mapped_column(Text, nullable=True)
    business_function: Mapped[str | None] = mapped_column(String(128), nullable=True)
    expected_actions: Mapped[list[str]] = mapped_column(JSON, default=list, server_default="[]")
    data_access_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_classification: Mapped[str] = mapped_column(String(32), server_default="LOW", default="LOW", nullable=False)
    classification_reasons: Mapped[list[str]] = mapped_column(JSON, default=list, server_default="[]")
    business_criticality: Mapped[str] = mapped_column(String(32), server_default="LOW", default="LOW", nullable=False)
    data_classification: Mapped[str] = mapped_column(String(32), server_default="INTERNAL", default="INTERNAL", nullable=False)
    source: Mapped[str] = mapped_column(String(32), server_default="MANUAL", default="MANUAL", nullable=False)
    external_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list, server_default="[]")
    last_activity_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_review_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    certified_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    certification_status: Mapped[str] = mapped_column(String(32), server_default="UNREVIEWED", default="UNREVIEWED", nullable=False)

    owner: Mapped[User] = relationship(back_populates="agents")
    organization: Mapped[Organization | None] = relationship(back_populates="agents")
    permissions: Mapped[list[Permission]] = relationship(back_populates="agent", passive_deletes="all")
    audit_logs: Mapped[list[AuditLog]] = relationship(
        "AuditLog", foreign_keys="AuditLog.agent_id", back_populates="agent", passive_deletes="all"
    )
    authorization_requests: Mapped[list[AuthorizationRequestRecord]] = relationship(
        "AuthorizationRequestRecord", foreign_keys="AuthorizationRequestRecord.agent_id", back_populates="agent", passive_deletes="all",
    )
    outgoing_delegations: Mapped[list[AgentDelegation]] = relationship(
        "AgentDelegation", foreign_keys="AgentDelegation.parent_agent_id", back_populates="parent_agent", passive_deletes="all"
    )
    incoming_delegations: Mapped[list[AgentDelegation]] = relationship(
        "AgentDelegation", foreign_keys="AgentDelegation.child_agent_id", back_populates="child_agent", passive_deletes="all"
    )
    ownership_history: Mapped[list[AgentOwnershipHistory]] = relationship(
        "AgentOwnershipHistory", foreign_keys="AgentOwnershipHistory.agent_id", back_populates="agent", passive_deletes="all"
    )
    certifications: Mapped[list[AgentCertification]] = relationship(
        "AgentCertification", foreign_keys="AgentCertification.agent_id", back_populates="agent", passive_deletes="all"
    )
