"""Persisted, explainable risk assessments and tenant policy."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Boolean, CheckConstraint, DateTime, Enum as SqlEnum, ForeignKey, Index, Integer, JSON, String, Uuid, func, text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskAction(str, Enum):
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    REJECT = "REJECT"


def _enum(enum_type, name: str):
    return SqlEnum(
        enum_type, name=name, native_enum=False, create_constraint=True,
        values_callable=lambda values: [value.value for value in values],
        validate_strings=True,
    )


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"
    __table_args__ = (
        CheckConstraint("request_id ~ '^req_[0-9a-f]{24}$'", name="request_id_format"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="score_range"),
        Index("ix_risk_assessments_user_created", "user_id", "created_at"),
        Index("ix_risk_assessments_org_created", "organization_id", "created_at"),
        Index("ix_risk_assessments_agent_created", "agent_id", "created_at"),
        Index("ix_risk_assessments_org_level_created", "organization_id", "risk_level", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    request_id: Mapped[str] = mapped_column(String(28), unique=True, nullable=False)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=True,
    )
    agent_id: Mapped[UUID] = mapped_column(ForeignKey("agents.id", ondelete="RESTRICT"), nullable=False)
    permission_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("permissions.id", ondelete="SET NULL"), nullable=True,
    )
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel, "risk_level"), nullable=False)
    decision_recommendation: Mapped[RiskAction] = mapped_column(
        _enum(RiskAction, "risk_action"), nullable=False,
    )
    reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    features: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    model_version: Mapped[str] = mapped_column(String(40), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )


class RiskPolicy(Base):
    __tablename__ = "risk_policies"
    __table_args__ = (
        CheckConstraint(
            "(organization_id IS NULL) <> (user_id IS NULL)",
            name="one_scope",
        ),
        Index("uq_risk_policies_organization", "organization_id", unique=True),
        Index("uq_risk_policies_user", "user_id", unique=True),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=True,
    )
    user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=True,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    medium_action: Mapped[RiskAction] = mapped_column(
        _enum(RiskAction, "risk_policy_medium_action"), server_default="ALLOW", nullable=False,
    )
    high_action: Mapped[RiskAction] = mapped_column(
        _enum(RiskAction, "risk_policy_high_action"), server_default="REQUIRE_APPROVAL", nullable=False,
    )
    critical_action: Mapped[RiskAction] = mapped_column(
        _enum(RiskAction, "risk_policy_critical_action"), server_default="REJECT", nullable=False,
    )
    amount_anomaly_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    velocity_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    rejection_history_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False,
    )
