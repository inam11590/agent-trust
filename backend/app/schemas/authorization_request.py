"""Public views and bounded filters for manual authorization requests."""

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.authorization_request import AuthorizationRequestStatus


class AuthorizationRequestFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AuthorizationRequestStatus | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


class AuthorizationRequestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    request_id: str
    user_id: UUID
    agent_id: UUID
    agent_identifier: str
    agent_name: str
    permission_id: UUID
    action: str
    resource: str
    amount: Decimal | None
    currency: str | None
    status: AuthorizationRequestStatus
    reason: str
    policy_reason: str | None = None
    created_at: datetime
    expires_at: datetime
    decided_at: datetime | None
    risk_score: int | None = None
    risk_level: str | None = None
    risk_recommendation: str | None = None
    risk_reasons: list[str] = Field(default_factory=list)


class PaginatedAuthorizationRequests(BaseModel):
    items: list[AuthorizationRequestResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
