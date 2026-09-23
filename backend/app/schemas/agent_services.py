"""Pydantic schemas for Step 30: Agent Service Registry & Communication."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# --------------------------------------------------------------------------
# Service Schemas
# --------------------------------------------------------------------------

class ServiceCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    agent_id: UUID
    description: Optional[str] = None
    version: str = Field(default="1.0.0", max_length=32)
    status: str = Field(default="ACTIVE")
    visibility: str = Field(default="ORGANIZATION")
    environment: str = Field(default="production")
    metadata_json: Optional[Dict[str, Any]] = None


class ServiceUpdate(BaseModel):
    description: Optional[str] = None
    version: Optional[str] = None
    status: Optional[str] = None
    visibility: Optional[str] = None
    environment: Optional[str] = None
    metadata_json: Optional[Dict[str, Any]] = None


class ServiceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    service_id: str
    organization_id: UUID
    agent_id: UUID
    name: str
    description: Optional[str] = None
    version: str
    status: str
    visibility: str
    environment: str
    metadata_json: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime
    capabilities_count: int = 0
    endpoints_count: int = 0


class ServiceListResponse(BaseModel):
    items: List[ServiceResponse]
    total: int


# --------------------------------------------------------------------------
# Capability Schemas
# --------------------------------------------------------------------------

class CapabilityRegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    agent_id: UUID
    service_id: Optional[UUID] = None
    version: str = Field(default="1.0", max_length=32)
    description: Optional[str] = None
    input_schema: Optional[Dict[str, Any]] = None
    output_schema: Optional[Dict[str, Any]] = None
    risk_classification: str = Field(default="LOW")
    requires_approval: bool = False
    approval_threshold_amount: Optional[float] = None
    rate_limit_per_minute: Optional[int] = None


class CapabilityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    capability_id: str
    organization_id: UUID
    agent_id: UUID
    service_id: Optional[UUID] = None
    name: str
    version: str
    description: Optional[str] = None
    input_schema: Optional[Dict[str, Any]] = None
    output_schema: Optional[Dict[str, Any]] = None
    risk_classification: str
    requires_approval: bool
    approval_threshold_amount: Optional[float] = None
    rate_limit_per_minute: Optional[int] = None
    is_active: bool
    created_at: datetime
    updated_at: datetime


class CapabilityListResponse(BaseModel):
    items: List[CapabilityResponse]
    total: int


# --------------------------------------------------------------------------
# Endpoint Schemas
# --------------------------------------------------------------------------

class EndpointCreateRequest(BaseModel):
    protocol: str = Field(default="HTTPS")
    url: str = Field(..., max_length=1024)
    priority: int = Field(default=1, ge=1, le=100)
    weight: int = Field(default=100, ge=1, le=1000)
    environment: str = Field(default="production")


class EndpointResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    endpoint_id: str
    organization_id: UUID
    service_id: UUID
    agent_id: UUID
    protocol: str
    url: str
    priority: int
    weight: int
    environment: str
    health_status: str
    consecutive_failures: int
    verified_at: Optional[datetime] = None
    is_active: bool
    created_at: datetime


class ChallengeInitiateResponse(BaseModel):
    challenge_id: str
    challenge_token: str
    expires_at: datetime


class EndpointVerifyRequest(BaseModel):
    challenge_token: str
    signature: Optional[str] = None
    key_id: Optional[str] = None


class EndpointVerifyResponse(BaseModel):
    verified: bool
    endpoint_id: str
    health_status: str
    verified_at: str


# --------------------------------------------------------------------------
# Resolution Schemas
# --------------------------------------------------------------------------

class ServiceResolveRequest(BaseModel):
    caller_agent_id: str
    service_id: str
    capability: Optional[str] = None


class CapabilityResolveRequest(BaseModel):
    caller_agent_id: str
    capability: str


class ServiceResolveResponse(BaseModel):
    status: str
    service_id: str
    service_name: str
    service_status: str
    service_version: str
    visibility: str
    target_agent: Dict[str, Any]
    target_organization_id: str
    primary_endpoint: Dict[str, Any]
    failover_endpoints: List[Dict[str, Any]]
    capability: Optional[Dict[str, Any]] = None
    discovery_advisory: str
    notice: str


# --------------------------------------------------------------------------
# Agent-to-Agent Call Schemas
# --------------------------------------------------------------------------

class AgentCallRequest(BaseModel):
    caller_agent_id: str
    service_id: str
    capability: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    call_chain: List[str] = Field(default_factory=list)
    depth: int = Field(default=1, ge=1)
    idempotency_key: Optional[str] = None
    caller_signature: Optional[str] = None
    caller_key_id: Optional[str] = None
    caller_timestamp: Optional[str] = None
    caller_nonce: Optional[str] = None
    credential_jwt: Optional[str] = None


class AgentCallResponse(BaseModel):
    call_id: str
    message_id: str
    status: str
    service_id: Optional[str] = None
    target_agent: Optional[str] = None
    capability: Optional[str] = None
    routed_endpoint_id: Optional[str] = None
    duration_ms: float
    response_digest: Optional[str] = None
    response: Optional[Dict[str, Any]] = None
    call_chain: List[str] = Field(default_factory=list)
    depth: int = 1
    approval_required: bool = False
    reason: Optional[str] = None
    notice: Optional[str] = None
    idempotent_replay: Optional[bool] = None


class AgentCallRecordSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    call_id: str
    message_id: str
    source_agent_id: UUID
    target_agent_id: Optional[UUID] = None
    service_id: Optional[UUID] = None
    capability_name: str
    call_chain: List[str]
    depth: int
    status: str
    decision_reason: Optional[str] = None
    duration_ms: float
    created_at: datetime
