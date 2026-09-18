"""Public signing-key API shapes. Private keys are never accepted."""

from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SigningKeyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key: str = Field(min_length=44, max_length=44)
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def valid_expiry(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value <= datetime.now(timezone.utc)):
            raise ValueError("Expiry must be a future time with a timezone")
        return value


class SigningKeyResponse(BaseModel):
    id: UUID
    key_id: str
    agent_id: UUID
    organization_id: UUID | None
    algorithm: str
    public_key: str
    fingerprint: str
    status: str
    created_at: datetime
    activated_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    rotated_from_key_id: str | None
    last_used_at: datetime | None

    model_config = {"from_attributes": True}
