"""Registered agents and their ownership links."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import Enum as SqlEnum, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, UUIDTimestampMixin

if TYPE_CHECKING:
    from app.models.agent_delegation import AgentDelegation
    from app.models.audit_log import AuditLog
    from app.models.authorization_request import AuthorizationRequestRecord
    from app.models.organization import Organization
    from app.models.permission import Permission
    from app.models.user import User


class AgentStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class Agent(UUIDTimestampMixin, Base):
    __tablename__ = "agents"
    __table_args__ = (
        Index("ix_agents_org_env", "organization_id", "environment"),
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
            AgentStatus, name="agent_status", native_enum=False, create_constraint=True,
            values_callable=lambda values: [value.value for value in values],
            validate_strings=True,
        ),
        server_default="inactive", nullable=False,
    )

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
