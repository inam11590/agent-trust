"""Validated notification, device, and preference API data."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models import DevicePlatform, DeviceStatus, NotificationPriority, NotificationStatus, NotificationType


class NotificationFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")
    unread: bool | None = None
    type: NotificationType | None = None
    priority: NotificationPriority | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


class NotificationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    organization_id: UUID | None
    type: NotificationType
    title: str
    message: str
    status: NotificationStatus
    priority: NotificationPriority
    related_request_id: UUID | None
    related_agent_id: UUID | None
    related_permission_id: UUID | None
    metadata: dict | None = Field(default=None, validation_alias="metadata_json")
    created_at: datetime
    read_at: datetime | None


class PaginatedNotifications(BaseModel):
    items: list[NotificationResponse]
    page: int
    page_size: int
    total: int
    total_pages: int


class UnreadCountResponse(BaseModel):
    count: int


class NotificationPreferenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    push_enabled: bool
    email_enabled: bool
    in_app_enabled: bool
    security_email_enabled: bool
    approval_push_enabled: bool
    approval_email_enabled: bool
    permission_expiry_enabled: bool
    general_activity_enabled: bool
    updated_at: datetime


class NotificationPreferenceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    push_enabled: bool | None = None
    email_enabled: bool | None = None
    in_app_enabled: bool | None = None
    security_email_enabled: bool | None = None
    approval_push_enabled: bool | None = None
    approval_email_enabled: bool | None = None
    permission_expiry_enabled: bool | None = None
    general_activity_enabled: bool | None = None


class DeviceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    push_token: str = Field(min_length=20, max_length=4096)
    platform: DevicePlatform
    device_name: str | None = Field(default=None, min_length=1, max_length=120)

    @field_validator("push_token")
    @classmethod
    def clean_token(cls, value: str) -> str:
        value = value.strip()
        if any(char.isspace() for char in value):
            raise ValueError("Push token must not contain whitespace")
        return value


class DeviceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    platform: DevicePlatform
    device_name: str | None
    status: DeviceStatus
    created_at: datetime
    updated_at: datetime
    last_seen_at: datetime
