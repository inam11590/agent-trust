"""Pydantic Schemas for Trust Registry and Verifiable Credentials (Step 22)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class IssuerSigningKeySchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    key_id: str
    algorithm: str = "Ed25519"
    public_key: str
    fingerprint: str
    status: str
    created_at: datetime
    activated_at: datetime
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    rotated_from_key_id: Optional[str] = None


class CredentialIssuerCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=200)


class CredentialIssuerResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    issuer_id: str
    organization_id: UUID
    name: str
    status: str
    created_at: datetime
    updated_at: datetime
    suspended_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    signing_keys: List[IssuerSigningKeySchema] = Field(default_factory=list)


class CredentialIssueRequest(BaseModel):
    agent_id: str = Field(..., description="Subject agent identifier or UUID")
    credential_type: str = Field(..., description="AgentIdentityCredential or AgentCapabilityCredential")
    claims: Optional[Dict[str, Any]] = None
    validity_days: Optional[int] = Field(default=None, ge=1, le=90)
    environment: str = Field(default="production", pattern="^(production|sandbox)$")


class CredentialVerifyRequest(BaseModel):
    credential: Dict[str, Any]
    expected_environment: str = Field(default="production", pattern="^(production|sandbox)$")


class CredentialVerifyResponse(BaseModel):
    verified: bool
    credential_id: str
    credential_type: str
    issuer: str
    subject_organization_id: str
    subject_agent_id: str
    environment: str
    expires_at: str
    claims: Dict[str, Any]


class CredentialStatusResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    credential_id: str
    status: str
    credential_type: str
    environment: str
    issued_at: datetime
    expires_at: datetime
    revoked_at: Optional[datetime] = None
    revocation_reason_code: Optional[str] = None


class CredentialRevokeRequest(BaseModel):
    reason_code: str = Field(default="ISSUER_ACTION", pattern="^(AGENT_REVOKED|KEY_COMPROMISED|CLAIMS_CHANGED|ISSUER_ACTION|SECURITY_EVENT)$")


class RotateKeyRequest(BaseModel):
    revoke_old_key: bool = False
