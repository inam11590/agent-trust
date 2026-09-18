"""Public account-security API contracts; no secret persistence fields."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class MFACodeInput(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    code: SecretStr = Field(min_length=6, max_length=64)


class MFADisableInput(MFACodeInput):
    password: SecretStr = Field(min_length=1, max_length=128)


class StepUpInput(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    password: SecretStr = Field(min_length=1, max_length=128)
    code: SecretStr | None = Field(default=None, min_length=6, max_length=64)


class PasswordChangeInput(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    current_password: SecretStr = Field(min_length=1, max_length=128)
    new_password: SecretStr = Field(min_length=15, max_length=128)
    code: SecretStr | None = Field(default=None, min_length=6, max_length=64)


class MFACredentialStatus(BaseModel):
    enabled: bool
    pending: bool
    recovery_codes_remaining: int


class MFASetupResponse(BaseModel):
    secret: str
    otpauth_uri: str
    qr_svg_data_url: str


class RecoveryCodesResponse(BaseModel):
    recovery_codes: list[str]


class SessionResponse(BaseModel):
    id: UUID
    device_type: str
    user_agent_summary: str
    auth_method: str
    created_at: datetime
    last_active_at: datetime
    expires_at: datetime
    current: bool


class SecurityEventItem(BaseModel):
    id: UUID
    actor_user_id: UUID | None
    actor_name: str | None = None
    organization_id: UUID | None
    event_type: str
    severity: str
    description: str | None
    created_at: datetime


class PaginatedSecurityEvents(BaseModel):
    items: list[SecurityEventItem]
    page: int
    page_size: int
    total: int
