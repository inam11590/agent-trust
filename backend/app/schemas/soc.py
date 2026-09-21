"""Pydantic schemas for Enterprise SOC: Events, Alerts, Rules, SIEM Exports."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class SecurityOverviewResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    security_status: str
    total_events: int
    critical_alerts: int
    high_alerts: int
    denied_actions: int
    replay_attempts: int
    invalid_signatures: int
    revoked_credential_usage: int
    trust_violations: int
    gateway_problems: int
    high_risk_actions: int
    admin_security_changes: int
    window_hours: int


class UnifiedSecurityEventItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    event_id: str | None = None
    organization_id: UUID | None = None
    event_type: str
    category: str | None = None
    severity: str
    description: str | None = None
    source_type: str | None = None
    source_id: str | None = None
    agent_id: UUID | None = None
    gateway_id: UUID | None = None
    credential_id: UUID | None = None
    request_id: str | None = None
    trace_id: str | None = None
    correlation_id: str | None = None
    actor_type: str | None = None
    actor_id: str | None = None
    target_type: str | None = None
    target_id: str | None = None
    action: str | None = None
    decision: str | None = None
    risk_level: str | None = None
    region: str | None = None
    environment: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class PaginatedUnifiedSecurityEvents(BaseModel):
    items: list[UnifiedSecurityEventItem]
    total: int
    next_cursor: str | None = None


class SecurityAlertItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    alert_id: str
    organization_id: UUID
    rule_id: str
    fingerprint: str
    severity: str
    status: str
    title: str
    description: str
    first_seen_at: datetime
    last_seen_at: datetime
    event_count: int
    assigned_to: UUID | None = None
    acknowledged_at: datetime | None = None
    acknowledged_by: UUID | None = None
    resolved_at: datetime | None = None
    resolved_by: UUID | None = None
    resolution_note: str | None = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class PaginatedSecurityAlerts(BaseModel):
    items: list[SecurityAlertItem]
    total: int


class AcknowledgeAlertRequest(BaseModel):
    note: str | None = None


class ResolveAlertRequest(BaseModel):
    resolution_note: str | None = None


class DetectionRuleItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    rule_id: str
    organization_id: UUID | None = None
    name: str
    description: str
    event_type: str | None = None
    category: str | None = None
    conditions: dict[str, Any] = Field(default_factory=dict)
    threshold: int
    window_seconds: int
    severity: str
    enabled: bool
    created_at: datetime
    updated_at: datetime


class CreateDetectionRuleRequest(BaseModel):
    rule_id: str = Field(min_length=3, max_length=64)
    name: str = Field(min_length=3, max_length=128)
    description: str = Field(min_length=5, max_length=512)
    event_type: str | None = None
    category: str | None = None
    conditions: dict[str, Any] = Field(default_factory=dict)
    threshold: int = Field(ge=1, le=10000, default=1)
    window_seconds: int = Field(ge=10, le=86400, default=300)
    severity: str = Field(default="HIGH")
    enabled: bool = True


class UpdateDetectionRuleRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    threshold: int | None = Field(None, ge=1, le=10000)
    window_seconds: int | None = Field(None, ge=10, le=86400)
    severity: str | None = None
    enabled: bool | None = None


class SecurityExportDestinationItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    destination_id: str
    organization_id: UUID
    name: str
    destination_type: str
    endpoint_url: str | None = None
    secret_ref: str | None = None
    min_severity: str
    categories: list[str] = Field(default_factory=list)
    enabled: bool
    status: str
    last_export_at: datetime | None = None
    consecutive_failures: int = 0
    last_error: str | None = None
    created_at: datetime
    updated_at: datetime


class CreateExportDestinationRequest(BaseModel):
    name: str = Field(min_length=3, max_length=128)
    destination_type: str = Field(pattern="^(WEBHOOK|SYSLOG|JSON_STREAM|CEF|SPLUNK|SENTINEL|ELASTIC)$")
    endpoint_url: str | None = None
    secret_ref: str | None = None
    min_severity: str = Field(default="INFO")
    categories: list[str] = Field(default_factory=list)
    enabled: bool = True


class TestExportResponse(BaseModel):
    success: bool
    error: str | None = None
    exported_sample_event_id: str


class RelatedEventsResponse(BaseModel):
    primary_event_id: str
    related_events: list[UnifiedSecurityEventItem]
    total_found: int
