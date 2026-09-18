"""Short-lived requests waiting for an owner's manual decision."""

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


class AuthorizationRequestStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class AuthorizationRequestRecord(Base):
    __tablename__ = "authorization_requests"
    __table_args__ = (
        CheckConstraint("request_id ~ '^req_[0-9a-f]{24}$'", name="request_id_format"),
        CheckConstraint("amount IS NULL OR amount >= 0", name="amount_not_negative"),
        CheckConstraint("(amount IS NULL) = (currency IS NULL)", name="amount_currency_pair"),
        CheckConstraint("currency IS NULL OR currency ~ '^[A-Z]{3}$'", name="currency_format"),
        CheckConstraint("expires_at > created_at", name="valid_expiry"),
        CheckConstraint(
            "(status = 'PENDING' AND decided_at IS NULL) OR "
            "(status <> 'PENDING' AND decided_at IS NOT NULL)",
            name="decision_timestamp",
        ),
        Index("ix_authorization_requests_user_status_created", "user_id", "status", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    request_id: Mapped[str] = mapped_column(String(28), unique=True, nullable=False)
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False,
    )
    agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="RESTRICT"), nullable=False,
    )
    permission_id: Mapped[UUID] = mapped_column(
        ForeignKey("permissions.id", ondelete="RESTRICT"), nullable=False,
    )
    environment: Mapped[str] = mapped_column(String(16), server_default="production", default="production", nullable=False)
    delegation_id: Mapped[str | None] = mapped_column(String(28), nullable=True)
    parent_agent_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("agents.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[str] = mapped_column(String(64), nullable=False)
    amount: Mapped[Decimal | None] = mapped_column(Numeric(19, 4), nullable=True)
    currency: Mapped[str | None] = mapped_column(String(3), nullable=True)
    status: Mapped[AuthorizationRequestStatus] = mapped_column(
        SqlEnum(
            AuthorizationRequestStatus,
            name="authorization_request_status",
            native_enum=False,
            create_constraint=True,
            values_callable=lambda values: [value.value for value in values],
            validate_strings=True,
        ),
        server_default="PENDING",
        nullable=False,
    )
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    risk_score: Mapped[int | None] = mapped_column(nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    risk_recommendation: Mapped[str | None] = mapped_column(String(24), nullable=True)
    signature_verified: Mapped[bool] = mapped_column(default=False, nullable=False)
    signing_key_id: Mapped[str | None] = mapped_column(String(31), nullable=True)
    signature_version: Mapped[str | None] = mapped_column(String(8), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship(back_populates="authorization_requests")
    agent: Mapped[Agent] = relationship(back_populates="authorization_requests", foreign_keys=[agent_id])
    parent_agent: Mapped[Agent | None] = relationship("Agent", foreign_keys=[parent_agent_id])
    permission: Mapped[Permission] = relationship(back_populates="authorization_requests")
