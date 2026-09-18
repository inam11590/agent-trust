"""Validated developer key, versioned API, sandbox, webhook, and log contracts."""

from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, AnyHttpUrl, BaseModel, ConfigDict, Field, field_validator

from app.models import APIKeyStatus, WebhookStatus


class APIKeyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    organization_id: UUID | None = None
    environment: Literal["sandbox", "production"] = "production"
    expires_at: AwareDatetime | None = None

    @field_validator("name", mode="before")
    @classmethod
    def trim_name(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @field_validator("expires_at")
    @classmethod
    def future_expiry(cls, value: datetime | None) -> datetime | None:
        if value is not None and value <= datetime.now(timezone.utc):
            raise ValueError("expires_at must be in the future")
        return value


class APIKeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    organization_id: UUID | None
    name: str
    environment: str = "sandbox"
    prefix: str
    status: APIKeyStatus
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None


class APIKeyCreated(APIKeyResponse):
    api_key: str


class DeveloperAuthorizationResponse(BaseModel):
    request_id: str
    status: str = Field(pattern=r"^(APPROVED|REJECTED|PENDING|EXPIRED)$")
    reason: str
    risk: dict[str, str] | None = None


class DeveloperLogResponse(DeveloperAuthorizationResponse):
    agent_id: str
    action: str
    api_key_prefix: str
    environment: str = "sandbox"
    created_at: datetime


class DeveloperLogDetailResponse(DeveloperAuthorizationResponse):
    agent_id: str
    action: str
    resource: str
    amount: str | None = None
    currency: str | None = None
    environment: str = "sandbox"
    api_key_prefix: str
    risk_score: int | None = None
    signature_verified: bool = False
    signing_key_id: str | None = None
    response_time_ms: float | None = None
    created_at: datetime


class WebhookCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    organization_id: UUID
    url: AnyHttpUrl
    environment: Literal["sandbox", "production"] = "production"


class WebhookResponse(BaseModel):
    id: UUID
    organization_id: UUID
    url: str
    environment: str = "production"
    status: WebhookStatus
    created_at: datetime


class WebhookCreated(WebhookResponse):
    signing_secret: str


class TestAgentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(default="Travel Assistant Test", min_length=1, max_length=200)
    organization_id: UUID | None = None


class TestAgentResponse(BaseModel):
    id: UUID
    agent_identifier: str
    name: str
    environment: str = "sandbox"
    status: str
    instructions: str


class PermissionTemplateCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: UUID
    template: Literal["flight_purchase", "document_access"] = "flight_purchase"


class SandboxScenarioResult(BaseModel):
    scenario_id: str
    name: str
    expected_status: str
    actual_status: str
    passed: bool
    request_id: str | None = None
    reason: str
    details: str


class WebhookTestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_type: Literal["authorization.approved", "authorization.rejected", "authorization.pending"] = "authorization.approved"


class WebhookDeliveryDetail(BaseModel):
    id: UUID
    webhook_endpoint_id: UUID
    request_id: str
    event_type: str
    is_test: bool
    status: str
    attempt_count: int
    response_status: int | None = None
    response_body: str | None = None
    last_error: str | None = None
    delivered_at: datetime | None = None
    created_at: datetime


class ProductionChecklistResponse(BaseModel):
    mfa_enabled: bool
    organization_info_complete: bool
    agent_signing_key_registered: bool
    webhook_configured: bool
    sdk_integration_tested: bool
    sandbox_authorization_successful: bool
    security_contact_configured: bool
    billing_plan_appropriate: bool
    all_passed: bool
    status: str


class OnboardingProgressResponse(BaseModel):
    step_1_create_sandbox_key: bool
    step_2_create_agent: bool
    step_3_register_signing_key: bool
    step_4_create_permission: bool
    step_5_send_first_request: bool
    step_6_configure_webhook: bool
    step_7_test_approval: bool
    step_8_ready_for_production: bool
    completed_count: int
    total_count: int = 8


class DeveloperOverviewResponse(BaseModel):
    organization_id: UUID | None
    organization_name: str | None
    environment: str
    api_status: str
    sandbox_api_keys_count: int
    production_api_keys_count: int
    sandbox_agents_count: int
    production_agents_count: int
    authorization_requests_this_month: int
    webhook_status: str
    production_access_status: str
    onboarding: OnboardingProgressResponse
    checklist: ProductionChecklistResponse
    recent_activity: list[DeveloperLogResponse]
