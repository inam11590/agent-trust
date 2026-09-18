"""Risk views for owners and safe policy updates."""

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models import RiskAction, RiskLevel


class RiskFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")
    level: RiskLevel | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


class RiskAssessmentResponse(BaseModel):
    id: UUID
    request_id: str
    agent_id: UUID
    agent_identifier: str
    agent_name: str
    action: str
    resource: str
    amount: Decimal | None
    currency: str | None
    risk_score: int
    risk_level: RiskLevel
    recommendation: RiskAction
    reasons: list[str]
    final_status: str
    model_version: str
    created_at: datetime


class PaginatedRiskAssessments(BaseModel):
    items: list[RiskAssessmentResponse]
    page: int
    page_size: int
    total: int
    total_pages: int


class RiskOverview(BaseModel):
    low: int
    medium: int
    high: int
    critical: int


class RiskPolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    medium_action: RiskAction | None = None
    high_action: RiskAction | None = None
    critical_action: RiskAction | None = None
    amount_anomaly_enabled: bool | None = None
    velocity_enabled: bool | None = None
    rejection_history_enabled: bool | None = None


class RiskPolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    organization_id: UUID | None
    enabled: bool
    medium_action: RiskAction
    high_action: RiskAction
    critical_action: RiskAction
    amount_anomaly_enabled: bool
    velocity_enabled: bool
    rejection_history_enabled: bool
    created_at: datetime
    updated_at: datetime
