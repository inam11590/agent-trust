"""Public billing and usage contracts. Provider identifiers and secrets stay private."""

from datetime import date, datetime
from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models import SubscriptionStatus


class PlanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    code: str
    name: str
    description: str
    monthly_price: Decimal | None
    yearly_price: Decimal | None
    currency: str
    max_organizations: int | None
    max_members: int | None
    max_agents: int | None
    max_api_keys: int | None
    max_authorization_requests_monthly: int | None
    max_webhooks: int | None
    risk_engine_enabled: bool
    advanced_risk_controls: bool
    advanced_notifications_enabled: bool
    priority_support: bool


class UsageItem(BaseModel):
    used: int
    limit: int | None


class SubscriptionResponse(BaseModel):
    organization_id: UUID
    plan: PlanResponse
    status: SubscriptionStatus
    current_period_start: datetime
    current_period_end: datetime
    cancel_at_period_end: bool
    trial_ends_at: datetime | None
    grace_ends_at: datetime | None
    usage: dict[str, UsageItem]
class UsageResponse(BaseModel):
    organization_id: UUID
    plan_code: str
    period_start: date
    period_end: date
    usage: dict[str, UsageItem]


class CheckoutRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    plan_code: str = Field(min_length=2, max_length=32, pattern=r"^[a-z_]+$")


class CheckoutResponse(BaseModel):
    checkout_url: str


class PortalResponse(BaseModel):
    portal_url: str


class CancelResponse(BaseModel):
    status: SubscriptionStatus
    cancel_at_period_end: bool
    current_period_end: datetime
