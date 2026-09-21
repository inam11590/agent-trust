"""Organizations are owned by users."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, Enum as SqlEnum, ForeignKey, Index, JSON, String, Uuid, UniqueConstraint, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, UUIDTimestampMixin

if TYPE_CHECKING:
    from app.models.agent import Agent
    from app.models.user import User


class Organization(UUIDTimestampMixin, Base):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    owner_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    production_access_status: Mapped[str] = mapped_column(String(20), server_default="NOT_REQUESTED", default="NOT_REQUESTED", nullable=False)
    production_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    production_approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    owner: Mapped[User] = relationship(back_populates="organizations")
    agents: Mapped[list[Agent]] = relationship(back_populates="organization", passive_deletes="all")


class OrganizationRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    DEVELOPER = "developer"
    VIEWER = "viewer"


class MemberStatus(str, Enum):
    ACTIVE = "active"
    REMOVED = "removed"


class InvitationStatus(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    EXPIRED = "expired"
    REVOKED = "revoked"


def _enum(enum_type, name: str):
    return SqlEnum(
        enum_type, name=name, native_enum=False, create_constraint=True,
        values_callable=lambda values: [value.value for value in values],
    )


class OrganizationMember(Base):
    __tablename__ = "organization_members"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_organization_members_org_user"),
        Index("ix_organization_members_user_status", "user_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True,
    )
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False,
    )
    role: Mapped[OrganizationRole] = mapped_column(
        _enum(OrganizationRole, "organization_role"), nullable=False,
    )
    status: Mapped[MemberStatus] = mapped_column(
        _enum(MemberStatus, "organization_member_status"), server_default="active", nullable=False,
    )
    invited_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=True,
    )
    joined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )


class OrganizationInvitation(Base):
    __tablename__ = "organization_invitations"
    __table_args__ = (
        Index("ix_organization_invitations_org_status", "organization_id", "status"),
        Index("ix_organization_invitations_email_status", "email", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False,
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    role: Mapped[OrganizationRole] = mapped_column(
        _enum(OrganizationRole, "organization_invitation_role"), nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    status: Mapped[InvitationStatus] = mapped_column(
        _enum(InvitationStatus, "organization_invitation_status"), server_default="pending", nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    invited_by: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_security_events_org_created", "organization_id", "created_at"),
        Index("ix_security_events_actor_created", "actor_user_id", "created_at"),
        Index("ix_security_events_event_id", "event_id"),
        Index("ix_security_events_category", "category"),
        Index("ix_security_events_correlation", "correlation_id"),
        Index("ix_security_events_agent_id", "agent_id"),
        Index("ix_security_events_gateway_id", "gateway_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    event_id: Mapped[str | None] = mapped_column(String(64), unique=True, index=True, nullable=True)
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=True,
    )
    actor_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=True,
    )
    target_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=True,
    )
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    category: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), server_default="info", nullable=False)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    agent_id: Mapped[UUID | None] = mapped_column(Uuid, index=True, nullable=True)
    gateway_id: Mapped[UUID | None] = mapped_column(Uuid, index=True, nullable=True)
    credential_id: Mapped[UUID | None] = mapped_column(Uuid, index=True, nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    trace_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    actor_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actor_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    target_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    action: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decision: Mapped[str | None] = mapped_column(String(64), nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(32), nullable=True)
    region: Mapped[str | None] = mapped_column(String(64), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(32), server_default="production", nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict, server_default=text("'{}'::json"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    @property
    def safe_metadata(self) -> dict:
        return self.details or {}

