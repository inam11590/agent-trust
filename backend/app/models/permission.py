"""Time-bound permissions granted by a user to one of their agents."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import Boolean, CheckConstraint, DateTime, Enum as SqlEnum, ForeignKey, Numeric, String, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, UUIDTimestampMixin

if TYPE_CHECKING:
    from app.models.agent import Agent
    from app.models.agent_delegation import AgentDelegation
    from app.models.audit_log import AuditLog
    from app.models.authorization_request import AuthorizationRequestRecord
    from app.models.user import User


class PermissionStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class Permission(UUIDTimestampMixin, Base):
    __tablename__ = "permissions"
    __table_args__ = (
        CheckConstraint(
            "maximum_amount IS NULL OR maximum_amount > 0",
            name="maximum_amount_positive",
        ),
        CheckConstraint(
            "(maximum_amount IS NULL) = (currency IS NULL)",
            name="amount_currency_pair",
        ),
        CheckConstraint(
            "currency IS NULL OR currency ~ '^[A-Z]{3}$'",
            name="currency_format",
        ),
        CheckConstraint("expires_at > valid_from", name="valid_time_window"),
        CheckConstraint("length(action) > 0", name="action_not_empty"),
        CheckConstraint("length(resource) > 0", name="resource_not_empty"),
    )

    owner_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True, nullable=False,
    )
    agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="RESTRICT"), index=True, nullable=False,
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[str] = mapped_column(String(64), nullable=False)
    maximum_amount: Mapped[Decimal | None] = mapped_column(Numeric(19, 4), nullable=True)
    currency: Mapped[str | None] = mapped_column(String(3), nullable=True)
    requires_approval: Mapped[bool] = mapped_column(
        Boolean, server_default=text("false"), nullable=False,
    )
    allow_delegation: Mapped[bool] = mapped_column(
        Boolean, server_default=text("false"), default=False, nullable=False,
    )
    valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[PermissionStatus] = mapped_column(
        SqlEnum(
            PermissionStatus,
            name="permission_status",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda values: [value.value for value in values],
            validate_strings=True,
        ),
        server_default="active",
        nullable=False,
    )
    expiry_warning_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expiry_notification_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    owner: Mapped[User] = relationship(back_populates="permissions")
    agent: Mapped[Agent] = relationship(back_populates="permissions")
    audit_logs: Mapped[list[AuditLog]] = relationship(back_populates="permission", passive_deletes="all")
    authorization_requests: Mapped[list[AuthorizationRequestRecord]] = relationship(
        back_populates="permission", passive_deletes="all",
    )
    delegations: Mapped[list[AgentDelegation]] = relationship(
        "AgentDelegation", back_populates="parent_permission", passive_deletes="all",
    )

    def is_usable(self, at: datetime | None = None) -> bool:
        """Return the security decision from current persisted state and time."""
        checked_at = at or datetime.now(timezone.utc)
        return (
            self.status == PermissionStatus.ACTIVE
            and self.valid_from <= checked_at < self.expires_at
        )
