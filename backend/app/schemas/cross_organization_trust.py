"""Pydantic schemas for Step 20 Cross-Organization Agent-to-Agent Trust."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Annotated
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.cross_organization_trust import ApprovalStage, ApprovalStatus, CrossOrgRequestStatus, TrustStatus

TrustDateTime = Annotated[datetime, AwareDatetime]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class TrustRequestCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    target_organization_id: UUID
    expires_at: TrustDateTime | None = None

    @model_validator(mode="after")
    def validate_expiry(self) -> "TrustRequestCreate":
        if self.expires_at is not None and self.expires_at <= utc_now():
            raise ValueError("expires_at must be in the future")
        return self


class TrustRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    reason: str = Field(min_length=1, max_length=255)


class TrustPolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    allowed_actions: list[str] = Field(default_factory=list)
    allowed_resources: list[str] = Field(default_factory=list)
    max_amount: Decimal | None = Field(default=None, gt=0, max_digits=19, decimal_places=4)
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")

    require_human_approval: bool = False
    approval_threshold: Decimal | None = Field(default=None, gt=0, max_digits=19, decimal_places=4)
    approval_type: str = Field(default="TARGET_APPROVAL", pattern=r"^(SOURCE_APPROVAL|TARGET_APPROVAL|BOTH_APPROVAL)$")

    allow_agent_delegation: bool = False
    max_delegation_depth: int = Field(default=1, ge=1, le=5)
    risk_threshold: int | None = Field(default=None, ge=0, le=100)

    @field_validator("currency", mode="before")
    @classmethod
    def normalize_currency(cls, value: object) -> object:
        return value.strip().upper() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_constraints(self) -> "TrustPolicyUpdate":
        if (self.max_amount is None) != (self.currency is None):
            raise ValueError("max_amount and currency must be provided together")
        return self


class TrustPolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    trust_relationship_id: UUID
    allowed_actions: list[str]
    allowed_resources: list[str]
    max_amount: Decimal | None
    currency: str | None
    require_human_approval: bool
    approval_threshold: Decimal | None
    approval_type: str
    allow_agent_delegation: bool
    max_delegation_depth: int
    risk_threshold: int | None
    created_at: datetime
    updated_at: datetime


class TrustRelationshipResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    trust_id: str
    source_organization_id: UUID
    source_organization_name: str | None = None
    target_organization_id: UUID
    target_organization_name: str | None = None
    status: TrustStatus
    created_by_user_id: UUID
    accepted_by_user_id: UUID | None
    created_at: datetime
    accepted_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None
    revocation_reason: str | None
    updated_at: datetime
    policy: TrustPolicyResponse | None = None


class OrganizationPublicProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    public_name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=1000)
    website_domain: str | None = Field(default=None, max_length=255)
    discoverable: bool = True
    supported_capabilities: list[str] = Field(default_factory=list)


class OrganizationPublicProfileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    public_name: str
    description: str
    website_domain: str | None
    discoverable: bool
    supported_capabilities: list[str]
    verification_status: str
    created_at: datetime
    updated_at: datetime


class TargetOrganizationPolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    allowed_actions: list[str] = Field(default_factory=list)
    allowed_resources: list[str] = Field(default_factory=list)
    max_amount: Decimal | None = Field(default=None, gt=0, max_digits=19, decimal_places=4)
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    require_human_approval: bool = False
    approval_threshold: Decimal | None = Field(default=None, gt=0, max_digits=19, decimal_places=4)

    @field_validator("currency", mode="before")
    @classmethod
    def normalize_currency(cls, value: object) -> object:
        return value.strip().upper() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_currency(self) -> "TargetOrganizationPolicyUpdate":
        if (self.max_amount is None) != (self.currency is None):
            raise ValueError("max_amount and currency must be provided together")
        return self


class TargetOrganizationPolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    allowed_actions: list[str]
    allowed_resources: list[str]
    max_amount: Decimal | None
    currency: str | None
    require_human_approval: bool
    approval_threshold: Decimal | None
    created_at: datetime
    updated_at: datetime


class ExternalAgentConnectionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    source_agent_id: UUID
    target_agent_id: UUID
    expires_at: TrustDateTime | None = None

    @model_validator(mode="after")
    def validate_different_agents(self) -> "ExternalAgentConnectionCreate":
        if self.source_agent_id == self.target_agent_id:
            raise ValueError("source_agent_id and target_agent_id cannot be the same")
        if self.expires_at is not None and self.expires_at <= utc_now():
            raise ValueError("expires_at must be in the future")
        return self


class ExternalAgentConnectionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    connection_id: str
    trust_relationship_id: UUID
    source_agent_id: UUID
    source_agent_name: str | None = None
    target_agent_id: UUID
    target_agent_name: str | None = None
    status: str
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    revocation_reason: str | None


class CrossOrgAuthorizePayload(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    source_organization_id: UUID | None = None
    target_organization_id: UUID
    source_agent_id: str = Field(min_length=1, max_length=255)
    target_agent_id: str = Field(min_length=1, max_length=255)
    action: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9:_-]*$")
    resource: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9:_-]*$")
    amount: Decimal | None = Field(default=None, gt=0, max_digits=19, decimal_places=4)
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    delegation_id: str | None = Field(default=None, pattern=r"^dlg_[0-9a-f]{24}$")

    @field_validator("action", "resource", mode="before")
    @classmethod
    def normalize_str(cls, value: object) -> object:
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("currency", mode="before")
    @classmethod
    def normalize_currency(cls, value: object) -> object:
        return value.strip().upper() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_amount(self) -> "CrossOrgAuthorizePayload":
        if (self.amount is None) != (self.currency is None):
            raise ValueError("amount and currency must be provided together")
        return self


class CrossOrgAuthorizeResponse(BaseModel):
    request_id: str
    status: str
    reason: str
    risk_level: str | None = None
    risk_score: int | None = None
    pending_approvals: list[str] = Field(default_factory=list)


class CrossOrgApprovalResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    cross_org_request_id: UUID
    organization_id: UUID
    approval_stage: ApprovalStage
    required_role: str
    status: ApprovalStatus
    decided_by_user_id: UUID | None
    decided_at: datetime | None
    reason: str | None
    created_at: datetime


class CrossOrgRequestDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    request_id: str
    trust_relationship_id: UUID
    connection_id: UUID | None
    source_organization_id: UUID
    source_organization_name: str | None = None
    target_organization_id: UUID
    target_organization_name: str | None = None
    source_agent_id: UUID
    source_agent_identifier: str | None = None
    source_agent_name: str | None = None
    target_agent_id: UUID
    target_agent_identifier: str | None = None
    target_agent_name: str | None = None
    action: str
    resource: str
    amount: Decimal | None
    currency: str | None
    status: CrossOrgRequestStatus
    decision_reason: str | None
    risk_level: str | None
    risk_score: int | None
    created_at: datetime
    expires_at: datetime | None
    completed_at: datetime | None
    approvals: list[CrossOrgApprovalResponse] = Field(default_factory=list)


class CrossOrgDecisionPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    reason: str | None = Field(default=None, max_length=255)
