"Agent-to-Agent Delegation model for Step 19 Agent-to-Agent Trust."

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
    Numeric,
    String,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base

if TYPE_CHECKING:
    from app.models.agent import Agent
    from app.models.organization import Organization
    from app.models.permission import Permission
    from app.models.user import User


class DelegationStatus(str, Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    SUSPENDED = "SUSPENDED"


def generate_delegation_id() -> str:
    return f"dlg_{secrets.token_hex(12)}"


class AgentDelegation(Base):
    __tablename__ = "agent_delegations"
    __table_args__ = (
        CheckConstraint("delegation_id ~ '^dlg_[0-9a-f]{24}$'", name="delegation_id_format"),
        CheckConstraint("parent_agent_id <> child_agent_id", name="no_self_delegation"),
        CheckConstraint("expires_at > valid_from", name="delegation_valid_time_window"),
        CheckConstraint(
            "maximum_amount IS NULL OR maximum_amount > 0",
            name="delegation_maximum_amount_positive",
        ),
        CheckConstraint(
            "(maximum_amount IS NULL) = (currency IS NULL)",
            name="delegation_amount_currency_pair",
        ),
        CheckConstraint(
            "currency IS NULL OR currency ~ '^[A-Z]{3}$'",
            name="delegation_currency_format",
        ),
        CheckConstraint(
            "current_depth > 0 AND current_depth <= max_delegation_depth",
            name="delegation_depth_bounds",
        ),
        Index("ix_agent_delegations_org_status", "organization_id", "status"),
        Index("ix_agent_delegations_child_status", "child_agent_id", "status"),
        Index("ix_agent_delegations_parent_status", "parent_agent_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    delegation_id: Mapped[str] = mapped_column(
        String(28), unique=True, nullable=False, index=True, default=generate_delegation_id
    )
    parent_agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    child_agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    parent_permission_id: Mapped[UUID] = mapped_column(
        ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    parent_delegation_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("agent_delegations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )

    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[str] = mapped_column(String(64), nullable=False)
    maximum_amount: Mapped[Decimal | None] = mapped_column(Numeric(19, 4), nullable=True)
    currency: Mapped[str | None] = mapped_column(String(3), nullable=True)
    requires_approval: Mapped[bool] = mapped_column(
        Boolean, server_default=text("false"), default=False, nullable=False
    )
    allow_further_delegation: Mapped[bool] = mapped_column(
        Boolean, server_default=text("false"), default=False, nullable=False
    )

    current_depth: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    max_delegation_depth: Mapped[int] = mapped_column(Integer, nullable=False, default=3)

    valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[DelegationStatus] = mapped_column(
        SqlEnum(
            DelegationStatus,
            name="delegation_status",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda values: [value.value for value in values],
            validate_strings=True,
        ),
        server_default="ACTIVE",
        nullable=False,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    revoked_by_agent_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("agents.id", ondelete="SET NULL"), nullable=True
    )
    revoked_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    parent_agent: Mapped[Agent] = relationship(
        "Agent", foreign_keys=[parent_agent_id], back_populates="outgoing_delegations"
    )
    child_agent: Mapped[Agent] = relationship(
        "Agent", foreign_keys=[child_agent_id], back_populates="incoming_delegations"
    )
    parent_permission: Mapped[Permission] = relationship(
        "Permission", foreign_keys=[parent_permission_id], back_populates="delegations"
    )
    parent_delegation: Mapped[AgentDelegation | None] = relationship(
        "AgentDelegation", remote_side=[id], back_populates="child_delegations"
    )
    child_delegations: Mapped[list[AgentDelegation]] = relationship(
        "AgentDelegation", back_populates="parent_delegation", passive_deletes="all"
    )
    organization: Mapped[Organization] = relationship("Organization")

    def is_usable(self, at: datetime | None = None) -> bool:
        """Return boolean whether delegation itself is active and within time window."""
        checked_at = at or datetime.now(timezone.utc)
        return (
            self.status == DelegationStatus.ACTIVE
            and self.valid_from <= checked_at < self.expires_at
        )
