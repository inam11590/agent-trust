"""Public organization security settings; secrets are never serialized."""

from datetime import datetime
from decimal import Decimal
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator


class SecurityPolicyUpdate(BaseModel):
    require_mfa: bool = False
    require_sso: bool = False
    session_timeout_minutes: int = Field(default=15, ge=5, le=60)
    max_session_lifetime_minutes: int = Field(default=1440, ge=15, le=1440)
    allowed_email_domains: list[str] = Field(default_factory=list, max_length=20)
    require_manual_approval_above_amount: Decimal | None = Field(default=None, gt=0, max_digits=19, decimal_places=4)
    approval_threshold_currency: str = Field(default="USD", pattern=r"^[A-Z]{3}$")
    block_critical_risk: bool = True
    require_approval_for_high_risk: bool = True

    @field_validator("allowed_email_domains")
    @classmethod
    def domains(cls, values: list[str]) -> list[str]:
        import re
        cleaned = [value.strip().lower() for value in values]
        if any(not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", value) for value in cleaned):
            raise ValueError("Use valid domain names")
        return sorted(set(cleaned))

    @model_validator(mode="after")
    def lifetime(self):
        if self.max_session_lifetime_minutes < self.session_timeout_minutes:
            raise ValueError("Maximum session lifetime must exceed inactivity timeout")
        return self


class SecurityPolicyResponse(SecurityPolicyUpdate):
    organization_id: UUID
    created_at: datetime | None = None
    updated_at: datetime | None = None


class SSOConnectionCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    issuer: str = Field(max_length=512)
    client_id: str = Field(min_length=1, max_length=255)
    client_secret: str = Field(min_length=1, max_length=512)
    discovery_url: str = Field(max_length=1024)
    allowed_domains: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("allowed_domains")
    @classmethod
    def domains(cls, values: list[str]) -> list[str]:
        return SecurityPolicyUpdate.domains(values)


class SSOConnectionResponse(BaseModel):
    id: UUID
    organization_id: UUID
    provider_type: Literal["OIDC"] = "OIDC"
    name: str
    issuer: str
    client_id: str
    discovery_url: str
    allowed_domains: list[str]
    status: str
    verified_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class SSOTicketExchange(BaseModel):
    ticket: str = Field(min_length=32, max_length=200)
