"""Validated permission requests and public permission responses."""

from datetime import datetime, timezone
from decimal import Decimal
from typing import Annotated
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator, field_validator

from app.models.permission import PermissionStatus

PermissionDateTime = Annotated[datetime, AwareDatetime]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class PermissionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    agent_id: UUID
    action: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9:_-]*$")
    resource: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9:_-]*$")
    maximum_amount: Decimal | None = Field(
        default=None,
        gt=0,
        max_digits=19,
        decimal_places=4,
    )
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    valid_from: PermissionDateTime = Field(default_factory=utc_now)
    expires_at: PermissionDateTime
    requires_approval: bool = False
    allow_delegation: bool = False

    @field_validator("action", "resource", mode="before")
    @classmethod
    def normalize_capability(cls, value: object) -> object:
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("currency", mode="before")
    @classmethod
    def normalize_currency(cls, value: object) -> object:
        return value.strip().upper() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_constraints(self) -> "PermissionCreate":
        if (self.maximum_amount is None) != (self.currency is None):
            raise ValueError("maximum_amount and currency must be provided together")
        if self.expires_at <= self.valid_from:
            raise ValueError("expires_at must be after valid_from")
        if self.expires_at <= utc_now():
            raise ValueError("expires_at must be in the future")
        return self


class PermissionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    owner_id: UUID
    agent_id: UUID
    action: str
    resource: str
    maximum_amount: Decimal | None
    currency: str | None
    requires_approval: bool
    allow_delegation: bool = False
    valid_from: datetime
    expires_at: datetime
    status: PermissionStatus
    created_at: datetime
    updated_at: datetime
