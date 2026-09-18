"""Subscription catalog, organization billing state, and non-sensitive usage counters."""

from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from uuid import UUID, uuid4

from sqlalchemy import Boolean, CheckConstraint, Date, DateTime, Enum as SqlEnum, ForeignKey, Index, Integer, Numeric, String, Uuid, UniqueConstraint, func, text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, UUIDTimestampMixin


class SubscriptionStatus(str, Enum):
    TRIALING = "trialing"
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    INCOMPLETE = "incomplete"
    SUSPENDED = "suspended"


class UsageMetric(str, Enum):
    AUTHORIZATION_REQUESTS = "authorization_requests"
    API_REQUESTS = "api_requests"
    ACTIVE_AGENTS = "active_agents"
    API_KEYS = "api_keys"
    TEAM_MEMBERS = "team_members"
    WEBHOOK_DELIVERIES = "webhook_deliveries"
    PUSH_NOTIFICATIONS = "push_notifications"


class BillingEventStatus(str, Enum):
    PROCESSED = "processed"
    IGNORED = "ignored"
    FAILED = "failed"


def _enum(enum_type, name: str, length: int = 32):
    return SqlEnum(
        enum_type, name=name, native_enum=False, create_constraint=True, length=length,
        values_callable=lambda values: [value.value for value in values], validate_strings=True,
    )


class SubscriptionPlan(UUIDTimestampMixin, Base):
    __tablename__ = "subscription_plans"
    __table_args__ = (
        CheckConstraint("monthly_price IS NULL OR monthly_price >= 0", name="monthly_price_nonnegative"),
        CheckConstraint("yearly_price IS NULL OR yearly_price >= 0", name="yearly_price_nonnegative"),
    )

    name: Mapped[str] = mapped_column(String(80), nullable=False)
    code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=False)
    monthly_price: Mapped[Decimal | None] = mapped_column(Numeric(10, 2), nullable=True)
    yearly_price: Mapped[Decimal | None] = mapped_column(Numeric(10, 2), nullable=True)
    currency: Mapped[str] = mapped_column(String(3), server_default="USD", nullable=False)
    max_organizations: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_members: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_agents: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_api_keys: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_authorization_requests_monthly: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_webhooks: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_engine_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    advanced_risk_controls: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    advanced_notifications_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    priority_support: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)


class OrganizationSubscription(UUIDTimestampMixin, Base):
    __tablename__ = "organization_subscriptions"

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), unique=True, nullable=False,
    )
    plan_id: Mapped[UUID] = mapped_column(ForeignKey("subscription_plans.id", ondelete="RESTRICT"), nullable=False)
    status: Mapped[SubscriptionStatus] = mapped_column(
        _enum(SubscriptionStatus, "subscription_status"), server_default="active", nullable=False,
    )
    billing_provider: Mapped[str] = mapped_column(String(32), server_default="test", nullable=False)
    provider_customer_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    provider_subscription_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    current_period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    current_period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    grace_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    canceled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class UsageRecord(Base):
    __tablename__ = "usage_records"
    __table_args__ = (
        UniqueConstraint("organization_id", "metric", "period_start", name="uq_usage_org_metric_period"),
        CheckConstraint("quantity >= 0", name="quantity_nonnegative"),
        CheckConstraint("period_end > period_start", name="period_valid"),
        Index("ix_usage_records_org_period", "organization_id", "period_start", "period_end"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False)
    metric: Mapped[UsageMetric] = mapped_column(_enum(UsageMetric, "usage_metric"), nullable=False)
    period_start: Mapped[date] = mapped_column(Date, nullable=False)
    period_end: Mapped[date] = mapped_column(Date, nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class BillingEvent(Base):
    __tablename__ = "billing_events"
    __table_args__ = (Index("ix_billing_events_org_created", "organization_id", "created_at"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID | None] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=True)
    provider_event_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[BillingEventStatus] = mapped_column(_enum(BillingEventStatus, "billing_event_status"), nullable=False)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class BillingCheckout(Base):
    __tablename__ = "billing_checkouts"
    __table_args__ = (Index("ix_billing_checkouts_org_created", "organization_id", "created_at"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False)
    plan_id: Mapped[UUID] = mapped_column(ForeignKey("subscription_plans.id", ondelete="RESTRICT"), nullable=False)
    created_by_user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    provider_session_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(24), server_default="pending", nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
