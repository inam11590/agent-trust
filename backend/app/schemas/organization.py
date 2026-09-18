"""Validated organization, membership, invitation, and security-event contracts."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.models import InvitationStatus, MemberStatus, OrganizationRole


class OrganizationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    name: str = Field(min_length=1, max_length=200)

    @field_validator("name", mode="before")
    @classmethod
    def trim_name(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value


class OrganizationSummary(BaseModel):
    id: UUID
    name: str
    role: OrganizationRole
    status: MemberStatus
    created_at: datetime


class MemberResponse(BaseModel):
    id: UUID
    organization_id: UUID
    user_id: UUID
    full_name: str
    email: EmailStr
    role: OrganizationRole
    status: MemberStatus
    joined_at: datetime
    created_at: datetime


class InvitationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    email: EmailStr
    role: OrganizationRole

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: object) -> object:
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("role")
    @classmethod
    def no_owner_invites(cls, value: OrganizationRole) -> OrganizationRole:
        if value == OrganizationRole.OWNER:
            raise ValueError("Owner transfer is not available")
        return value


class InvitationResponse(BaseModel):
    id: UUID
    organization_id: UUID
    email: EmailStr
    role: OrganizationRole
    status: InvitationStatus
    expires_at: datetime
    created_at: datetime
    accepted_at: datetime | None
    invitation_url: str | None = None


class InvitationAccept(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    token: str = Field(min_length=32, max_length=500)


class MemberRoleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: OrganizationRole

    @field_validator("role")
    @classmethod
    def no_owner_assignment(cls, value: OrganizationRole) -> OrganizationRole:
        if value == OrganizationRole.OWNER:
            raise ValueError("Owner transfer is not available")
        return value


class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    organization_id: UUID | None
    actor_user_id: UUID | None
    target_user_id: UUID | None
    event_type: str
    severity: str
    description: str | None
    details: dict
    created_at: datetime
