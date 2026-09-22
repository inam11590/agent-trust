"""Validated agent requests and public agent responses."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator, field_validator

from app.models.agent import AgentStatus


class AgentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    organization_id: UUID | None = None

    @field_validator("name", mode="before")
    @classmethod
    def trim_name(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @field_validator("description", mode="before")
    @classmethod
    def trim_description(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        trimmed = value.strip()
        return trimmed or None


class AgentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: str | None
    agent_identifier: str
    owner_id: UUID
    organization_id: UUID | None
    status: AgentStatus
    created_at: datetime
    updated_at: datetime

    # Step 28: Governance Attributes
    owner_type: str = "USER"
    team: str | None = None
    purpose: str | None = None
    business_function: str | None = None
    expected_actions: list[str] = Field(default_factory=list)
    data_access_description: str | None = None
    risk_classification: str = "LOW"
    classification_reasons: list[str] = Field(default_factory=list)
    business_criticality: str = "LOW"
    data_classification: str = "INTERNAL"
    source: str = "MANUAL"
    external_reference: str | None = None
    tags: list[str] = Field(default_factory=list)
    last_activity_at: datetime | None = None
    last_reviewed_at: datetime | None = None
    next_review_due_at: datetime | None = None
    certified_until: datetime | None = None
    certification_status: str = "UNREVIEWED"


class AgentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    status: AgentStatus | None = None
    purpose: str | None = None
    business_function: str | None = None
    risk_classification: str | None = None
    business_criticality: str | None = None
    data_classification: str | None = None
    team: str | None = None
    tags: list[str] | None = None
    expected_actions: list[str] | None = None
    data_access_description: str | None = None

    @field_validator("name", mode="before")
    @classmethod
    def trim_name(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @field_validator("description", mode="before")
    @classmethod
    def trim_description(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        return value.strip() or None

    @model_validator(mode="after")
    def require_change(self) -> "AgentUpdate":
        if not self.model_fields_set:
            raise ValueError("At least one field must be provided")
        return self

