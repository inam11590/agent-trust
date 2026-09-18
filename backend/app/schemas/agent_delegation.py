"""Pydantic schemas for Agent-to-Agent Delegation (Step 19)."""

from datetime import datetime, timezone
from decimal import Decimal
from typing import Annotated
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.agent_delegation import DelegationStatus

DelegationDateTime = Annotated[datetime, AwareDatetime]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AgentDelegationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    parent_agent_id: UUID
    child_agent_id: UUID
    parent_permission_id: UUID
    parent_delegation_id: UUID | None = None

    action: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9:_-]*$")
    resource: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9:_-]*$")
    maximum_amount: Decimal | None = Field(default=None, gt=0, max_digits=19, decimal_places=4)
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")

    requires_approval: bool = False
    allow_further_delegation: bool = False
    max_delegation_depth: int = Field(default=3, ge=1, le=5)

    valid_from: DelegationDateTime = Field(default_factory=utc_now)
    expires_at: DelegationDateTime

    @field_validator("action", "resource", mode="before")
    @classmethod
    def normalize_capability(cls, value: object) -> object:
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("currency", mode="before")
    @classmethod
    def normalize_currency(cls, value: object) -> object:
        return value.strip().upper() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_constraints(self) -> "AgentDelegationCreate":
        if self.parent_agent_id == self.child_agent_id:
            raise ValueError("parent_agent_id and child_agent_id cannot be the same agent (no self-delegation)")
        if (self.maximum_amount is None) != (self.currency is None):
            raise ValueError("maximum_amount and currency must be provided together")
        if self.expires_at <= self.valid_from:
            raise ValueError("expires_at must be after valid_from")
        if self.expires_at <= utc_now():
            raise ValueError("expires_at must be in the future")
        return self


class AgentDelegationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    delegation_id: str
    parent_agent_id: UUID
    child_agent_id: UUID
    parent_permission_id: UUID
    parent_delegation_id: UUID | None
    organization_id: UUID

    action: str
    resource: str
    maximum_amount: Decimal | None
    currency: str | None
    requires_approval: bool
    allow_further_delegation: bool

    current_depth: int
    max_delegation_depth: int

    valid_from: datetime
    expires_at: datetime
    status: DelegationStatus

    revoked_at: datetime | None = None
    revocation_reason: str | None = None
    created_at: datetime

    parent_agent_name: str | None = None
    child_agent_name: str | None = None


class DelegationRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    reason: str | None = Field(default=None, max_length=255)


class DelegationChainNode(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    depth: int
    delegation_id: str | None
    parent_agent_id: UUID | None
    parent_agent_name: str | None
    child_agent_id: UUID | None
    child_agent_name: str | None
    action: str
    resource: str
    maximum_amount: Decimal | None
    currency: str | None
    requires_approval: bool
    status: str
    valid_from: datetime
    expires_at: datetime


class DelegationChainResponse(BaseModel):
    delegation_id: str
    root_permission_id: UUID
    is_valid: bool
    validation_error: str | None = None
    effective_action: str
    effective_resource: str
    effective_maximum_amount: Decimal | None
    effective_currency: str | None
    effective_requires_approval: bool
    effective_expires_at: datetime
    chain: list[DelegationChainNode]
