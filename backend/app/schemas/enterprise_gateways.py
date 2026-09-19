"""Pydantic schemas for Enterprise Gateways, Sidecars, and Configuration Bundles (Step 23)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class GatewayRegistrationRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=128, description="Human-readable name for the gateway")
    deployment_type: str = Field("SELF_HOSTED_GATEWAY", description="SELF_HOSTED_GATEWAY, SIDECAR, or CLOUD_GATEWAY")
    environment: str = Field("PRODUCTION", description="PRODUCTION or SANDBOX")
    offline_policy: str = Field("FAIL_CLOSED", description="FAIL_CLOSED or LIMITED_OFFLINE")
    labels: Dict[str, Any] = Field(default_factory=dict, description="Metadata labels (region, cluster, service)")


class GatewayRegistrationResponse(BaseModel):
    id: str
    gateway_id: str
    name: str
    deployment_type: str
    environment: str
    status: str
    enrollment_token: str
    enrollment_command: str
    enrollment_token_expires_at: datetime
    created_at: datetime


class GatewayEnrollRequest(BaseModel):
    enrollment_token: str = Field(..., description="One-time enrollment token issued by Control Plane")
    public_key: str = Field(..., description="Base64-encoded Ed25519 public key generated locally by the gateway")
    version: Optional[str] = Field("1.0.0", description="Gateway software version")
    labels: Optional[Dict[str, Any]] = Field(default=None, description="Optional extra labels")


class GatewayEnrollResponse(BaseModel):
    status: str
    gateway_id: str
    organization_id: str
    environment: str
    control_plane_public_key: str
    control_plane_signing_key_id: str
    initial_config_version: int


class GatewayHeartbeatRequest(BaseModel):
    version: str = Field(..., description="Software version")
    config_version: int = Field(..., description="Currently applied configuration version")
    health: Dict[str, Any] = Field(..., description="Safe health metrics: cpu_percent, memory_percent, error_count, etc.")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp")
    signature: str = Field(..., description="Ed25519 signature over gateway_id + config_version + timestamp")


class GatewayHeartbeatResponse(BaseModel):
    status: str
    latest_config_version: int
    sync_required: bool
    control_plane_time: str


class GatewayConfigBundleResponse(BaseModel):
    config_version: int
    organization_id: str
    environment: str
    issued_at: str
    expires_at: str
    bundle: Dict[str, Any]
    bundle_sha256: str
    signature: str
    signing_key_id: str


class GatewayPublishConfigRequest(BaseModel):
    environment: str = Field("production", description="Target environment")
    policies: Optional[List[Dict[str, Any]]] = Field(None, description="Compiled policies")
    trusted_issuers: Optional[List[Dict[str, Any]]] = Field(None, description="Trusted credential issuers")
    credential_requirements: Optional[List[Dict[str, Any]]] = Field(None, description="Required credentials")
    revocations: Optional[List[Dict[str, Any]]] = Field(None, description="Revoked keys and credentials")
    routing: Optional[Dict[str, Any]] = Field(None, description="Routing rules (e.g. allowed direct peers)")
    validity_hours: Optional[int] = Field(24, ge=1, le=720, description="Config expiration hours")


class GatewayRollbackRequest(BaseModel):
    target_version: int = Field(..., description="Historical configuration version to restore under a new monotonic version")


class EnterpriseGatewayResponse(BaseModel):
    id: str
    gateway_id: str
    organization_id: str
    name: str
    deployment_type: str
    environment: str
    status: str
    version: str
    public_key: Optional[str] = None
    fingerprint: Optional[str] = None
    config_version: int
    labels: Dict[str, Any]
    offline_policy: str
    last_seen_at: Optional[datetime] = None
    last_heartbeat_data: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime
    suspended_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class GatewayConfigHistoryItem(BaseModel):
    id: str
    config_version: int
    organization_id: str
    environment: str
    bundle_sha256: str
    signing_key_id: str
    published_by_user_id: Optional[str] = None
    created_at: datetime
    expires_at: datetime
