"""Security Hardening and Cryptographic Key Lifecycle Administration API."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional

from app.core.config import Settings
from app.core.crypto_keys import (
    KeyCompromisedError,
    KeyMetadata,
    KeyPurpose,
    KeySecurityError,
    KeyStatus,
    get_key_provider,
)
from app.core.secrets import get_secret_provider

router = APIRouter(prefix="/v1/security", tags=["Security Hardening"])


class KeyStatusResponse(BaseModel):
    key_id: str
    purpose: str
    status: str
    algorithm: str
    public_key: str
    created_at: str
    rotated_at: Optional[str] = None
    revoked_at: Optional[str] = None
    revocation_reason: Optional[str] = None


class CompromiseKeyRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=256)


class HardeningStatusResponse(BaseModel):
    environment: str
    debug_mode: bool
    secret_provider: Dict[str, Any]
    key_provider_mode: str
    compliance_label: str
    hsts_enabled: bool
    insecure_tls_allowed: bool
    cors_wildcard_prohibited: bool
    active_keys_count: int


@router.get("/hardening/status", response_model=HardeningStatusResponse)
def get_hardening_status() -> HardeningStatusResponse:
    from app.main import app
    settings: Settings = app.state.settings
    secret_prov = get_secret_provider()
    key_prov = get_key_provider()

    keys = key_prov.list_keys()
    active_keys = [k for k in keys if k.status == KeyStatus.ACTIVE]
    compliance_label = getattr(key_prov, "compliance_label", "TEST / MOCK ONLY (Local Software Keystore)")

    return HardeningStatusResponse(
        environment=settings.app_env,
        debug_mode=settings.debug,
        secret_provider=secret_prov.health(),
        key_provider_mode=type(key_prov).__name__,
        compliance_label=compliance_label,
        hsts_enabled=(settings.app_env == "production"),
        insecure_tls_allowed=settings.allow_insecure_tls,
        cors_wildcard_prohibited=("*" not in settings.cors_allowed_origins),
        active_keys_count=len(active_keys),
    )


@router.get("/keys", response_model=List[KeyStatusResponse])
def list_keys(purpose: Optional[str] = None) -> List[KeyStatusResponse]:
    """List cryptographic keys. CRITICAL INVARIANT: Private keys are NEVER exposed."""
    key_prov = get_key_provider()
    filter_purpose = None
    if purpose:
        try:
            filter_purpose = KeyPurpose(purpose)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid key purpose '{purpose}'")
    
    keys = key_prov.list_keys(purpose=filter_purpose)
    return [
        KeyStatusResponse(
            key_id=k.key_id,
            purpose=k.purpose.value,
            status=k.status.value,
            algorithm=k.algorithm,
            public_key=k.public_key,
            created_at=k.created_at.isoformat(),
            rotated_at=k.rotated_at.isoformat() if k.rotated_at else None,
            revoked_at=k.revoked_at.isoformat() if k.revoked_at else None,
            revocation_reason=k.revocation_reason,
        )
        for k in keys
    ]


@router.post("/keys/{key_id}/rotate", response_model=KeyStatusResponse)
def rotate_key(key_id: str) -> KeyStatusResponse:
    key_prov = get_key_provider()
    try:
        new_key = key_prov.rotate(key_id)
        return KeyStatusResponse(
            key_id=new_key.key_id,
            purpose=new_key.purpose.value,
            status=new_key.status.value,
            algorithm=new_key.algorithm,
            public_key=new_key.public_key,
            created_at=new_key.created_at.isoformat(),
        )
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Key '{key_id}' not found")


@router.post("/keys/{key_id}/compromise", status_code=status.HTTP_200_OK)
def mark_key_compromised(key_id: str, request: CompromiseKeyRequest) -> Dict[str, Any]:
    key_prov = get_key_provider()
    try:
        key_prov.revoke(key_id, reason=request.reason, compromised=True)
        return {
            "status": "COMPROMISED",
            "key_id": key_id,
            "message": "Key has been permanently marked COMPROMISED. Signing operations halted immediately.",
        }
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Key '{key_id}' not found")


@router.get("/secrets/health")
def get_secret_health() -> Dict[str, Any]:
    return get_secret_provider().health()
