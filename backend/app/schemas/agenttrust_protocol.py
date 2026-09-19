"""Pydantic schemas for ATP/1.0 and AgentTrust Gateway (Step 21)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ATPSourceTarget(BaseModel):
    organization_id: Optional[str] = None
    agent_id: Optional[str] = None
    address: Optional[str] = None


class ATPSignature(BaseModel):
    version: str = Field(default="ATP-SIG/1")
    key_id: str
    value: str


class ATPMessageEnvelope(BaseModel):
    protocol: str = Field(default="ATP/1.0", description="Protocol version, must be ATP/1.0")
    message_id: str = Field(..., description="Unique message ID e.g. msg_...")
    message_type: str = Field(default="request", description="'request' or 'query'")
    source: ATPSourceTarget
    target: ATPSourceTarget
    capability: str = Field(..., description="e.g. hotel.reserve@1.0")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp e.g. 2026-09-19T10:00:00Z")
    nonce: str = Field(..., description="Unique nonce e.g. nonce_...")
    payload: Any = Field(default_factory=dict, description="Arbitrary JSON payload")
    payload_sha256: Optional[str] = Field(default=None, description="SHA-256 hex digest of deterministic payload")
    signature: ATPSignature


class ATPGatewayDispatchResponse(BaseModel):
    protocol: str = "ATP/1.0"
    message_id: str
    status: str
    target: Optional[str] = None
    capability: Optional[str] = None
    attestation_id: Optional[str] = None
    response: Optional[Any] = None
    approval_required: Optional[bool] = None
    reason: Optional[str] = None
    notice: Optional[str] = None
    idempotent: Optional[bool] = None
    completed_at: Optional[str] = None


class AgentEndpointCreate(BaseModel):
    agent_id: UUID
    endpoint_url: str


class AgentEndpointUpdate(BaseModel):
    endpoint_url: Optional[str] = None
    status: Optional[str] = None


class AgentEndpointResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    agent_id: UUID
    endpoint_url: str
    status: str
    verification_token: str
    verified_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class AgentCapabilityCreate(BaseModel):
    name: str = Field(..., max_length=128)
    version: str = Field(default="1.0", max_length=32)
    description: Optional[str] = Field(default=None, max_length=512)
    input_schema: Optional[Dict[str, Any]] = None
    output_schema: Optional[Dict[str, Any]] = None


class AgentCapabilityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    agent_id: UUID
    name: str
    version: str
    description: Optional[str] = None
    input_schema: Optional[Dict[str, Any]] = None
    output_schema: Optional[Dict[str, Any]] = None
    is_active: bool
    created_at: datetime
    updated_at: datetime


class ATPMessageRecordSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    message_id: str
    atp_version: str
    message_type: str
    source_organization_id: UUID
    source_agent_id: UUID
    target_organization_id: Optional[UUID] = None
    target_agent_id: Optional[UUID] = None
    capability: str
    status: str
    decision_reason: Optional[str] = None
    attestation_id: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None


class GatewayIdentityResponse(BaseModel):
    issuer: str
    key_id: str
    algorithm: str = "Ed25519"
    public_key_base64: str
    public_key_pem: str
    attestation_ttl_seconds: int = 60
