"""Append-only history of authorization decisions."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, Enum as SqlEnum, ForeignKey, Index, Numeric, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base

if TYPE_CHECKING:
    from app.models.agent import Agent
    from app.models.permission import Permission
    from app.models.user import User


class AuditDecision(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        CheckConstraint("request_id ~ '^req_[0-9a-f]{24}$'", name="request_id_format"),
        CheckConstraint("amount IS NULL OR amount >= 0", name="amount_not_negative"),
        CheckConstraint("(amount IS NULL) = (currency IS NULL)", name="amount_currency_pair"),
        CheckConstraint("currency IS NULL OR currency ~ '^[A-Z]{3}$'", name="currency_format"),
        CheckConstraint("length(action) > 0", name="action_not_empty"),
        CheckConstraint("length(resource) > 0", name="resource_not_empty"),
        Index("ix_audit_logs_user_requested", "user_id", "requested_at"),
        Index("ix_audit_logs_user_agent_requested", "user_id", "agent_id", "requested_at"),
        Index("ix_audit_logs_user_decision_requested", "user_id", "decision", "requested_at"),
        Index("ix_audit_logs_org_requested", "organization_id", "requested_at"),
        Index("ix_audit_logs_org_env", "organization_id", "environment"),
        Index("ix_audit_logs_agent_decision_requested", "agent_id", "decision", "requested_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    request_id: Mapped[str] = mapped_column(String(28), unique=True, nullable=False)
    environment: Mapped[str] = mapped_column(String(16), server_default="production", default="production", nullable=False)
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False,
    )
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=True,
    )
    agent_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("agents.id", ondelete="SET NULL"), nullable=True,
    )
    agent_identifier: Mapped[str] = mapped_column(String(255), nullable=False)
    permission_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("permissions.id", ondelete="SET NULL"), nullable=True,
    )
    delegation_id: Mapped[str | None] = mapped_column(String(28), nullable=True)
    parent_agent_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("agents.id", ondelete="SET NULL"), nullable=True,
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[str] = mapped_column(String(64), nullable=False)
    amount: Mapped[Decimal | None] = mapped_column(Numeric(19, 4), nullable=True)
    currency: Mapped[str | None] = mapped_column(String(3), nullable=True)
    decision: Mapped[AuditDecision] = mapped_column(
        SqlEnum(
            AuditDecision,
            name="audit_decision",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda values: [value.value for value in values],
            validate_strings=True,
        ),
        nullable=False,
    )
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    risk_score: Mapped[int | None] = mapped_column(nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    risk_recommendation: Mapped[str | None] = mapped_column(String(24), nullable=True)
    signature_verified: Mapped[bool] = mapped_column(default=False, nullable=False)
    signing_key_id: Mapped[str | None] = mapped_column(String(31), nullable=True)
    signature_version: Mapped[str | None] = mapped_column(String(8), nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    user: Mapped[User] = relationship(back_populates="audit_logs")
    agent: Mapped[Agent | None] = relationship(back_populates="audit_logs", foreign_keys=[agent_id])
    parent_agent: Mapped[Agent | None] = relationship("Agent", foreign_keys=[parent_agent_id])
    permission: Mapped[Permission | None] = relationship(back_populates="audit_logs")
