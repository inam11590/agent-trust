"""Read-only audit log responses and bounded query filters."""

from datetime import datetime
from decimal import Decimal
from typing import Annotated
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator, field_validator

from app.models.audit_log import AuditDecision

AuditDateTime = Annotated[datetime, AwareDatetime]


class AuditLogFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: AuditDecision | None = None
    agent_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        pattern=r"^agt_[0-9a-f]{24}$",
    )
    action: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9:_-]*$",
    )
    resource: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9:_-]*$",
    )
    start_date: AuditDateTime | None = None
    end_date: AuditDateTime | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)

    @field_validator("action", "resource", mode="before")
    @classmethod
    def normalize_capability(cls, value: object) -> object:
        return value.strip().lower() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_date_range(self) -> "AuditLogFilters":
        if self.start_date is not None and self.end_date is not None:
            if self.start_date > self.end_date:
                raise ValueError("start_date must be before or equal to end_date")
        return self


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    request_id: str
    user_id: UUID
    agent_id: UUID | None
    agent_identifier: str
    permission_id: UUID | None
    action: str
    resource: str
    amount: Decimal | None
    currency: str | None
    decision: AuditDecision
    reason: str
    requested_at: datetime
    created_at: datetime
    risk_score: int | None = None
    risk_level: str | None = None
    risk_recommendation: str | None = None


class PaginatedAuditLogs(BaseModel):
    items: list[AuditLogResponse]
    page: int
    page_size: int
    total: int
    total_pages: int
