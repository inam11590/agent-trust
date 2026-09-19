"""AgentTrust Trust Registry and Verifiable Credentials API Endpoints (Step 22)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.models.agent import Agent
from app.models.organization import OrganizationMember, OrganizationRole, SecurityEvent
from app.models.trust_registry import (
    AgentCredential,
    CredentialIssuer,
    CredentialStatus,
    IssuerKeyStatus,
    IssuerSigningKey,
    IssuerStatus,
)
from app.schemas.trust_registry import (
    CredentialIssueRequest,
    CredentialIssuerCreate,
    CredentialIssuerResponse,
    CredentialRevokeRequest,
    CredentialStatusResponse,
    CredentialVerifyRequest,
    CredentialVerifyResponse,
    IssuerSigningKeySchema,
    RotateKeyRequest,
)
from app.services.credential_service import (
    CredentialVerificationError,
    create_credential_issuer,
    issue_agent_credential,
    revoke_agent_credential,
    rotate_issuer_signing_key,
    verify_agent_credential,
)
from app.services.organization_context import CurrentWorkspace

router = APIRouter(tags=["Trust Registry & Verifiable Credentials"])


# ----------------------------------------------------------------------
# 1. Credentials Endpoints (POST /v1/credentials, verify, status, revoke)
# ----------------------------------------------------------------------

@router.post("/v1/credentials", status_code=status.HTTP_201_CREATED)
def issue_credential(
    payload: CredentialIssueRequest,
    workspace: CurrentWorkspace,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Issue a cryptographically signed ATC/1.0 credential for an active agent."""
    # Find active issuer for this organization
    issuer = db.execute(
        select(CredentialIssuer).where(
            CredentialIssuer.organization_id == workspace.organization.id,
            CredentialIssuer.status == IssuerStatus.ACTIVE.value,
        )
    ).scalars().first()

    if not issuer:
        # Automatically provision initial issuer if not present
        issuer, _ = create_credential_issuer(
            db=db,
            organization_id=workspace.organization.id,
            name=f"{workspace.organization.name} Agent Issuer",
        )

    try:
        cred = issue_agent_credential(
            db=db,
            issuer_id_str=issuer.issuer_id,
            subject_agent_id_str=payload.agent_id,
            credential_type=payload.credential_type,
            claims=payload.claims,
            validity_days=payload.validity_days,
            environment=payload.environment,
        )
        return cred
    except CredentialVerificationError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"message": exc.message, "code": exc.code})


@router.post("/v1/credentials/verify", status_code=status.HTTP_200_OK, response_model=CredentialVerifyResponse)
def verify_credential(
    payload: CredentialVerifyRequest,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Cryptographically verify an ATC/1.0 credential against the Trust Registry and Status Registry."""
    try:
        result = verify_agent_credential(
            db=db,
            credential=payload.credential,
            expected_environment=payload.expected_environment,
            check_agent_active=True,
        )
        return result
    except CredentialVerificationError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"message": exc.message, "code": exc.code, "details": exc.details},
        )


@router.get("/v1/credentials/{credential_id}/status", response_model=CredentialStatusResponse)
def get_credential_status(
    credential_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Public credential status registry lookup (ACTIVE, REVOKED, EXPIRED)."""
    cred = db.execute(
        select(AgentCredential).where(AgentCredential.credential_id == credential_id)
    ).scalar_one_or_none()

    if not cred:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"message": f"Credential '{credential_id}' not found.", "code": "CREDENTIAL_NOT_FOUND"},
        )

    # Check temporal expiration
    now = datetime.now(timezone.utc)
    current_status = cred.status
    if current_status == CredentialStatus.ACTIVE.value and now > cred.expires_at:
        current_status = CredentialStatus.EXPIRED.value

    return {
        "credential_id": cred.credential_id,
        "status": current_status,
        "credential_type": cred.credential_type,
        "environment": cred.environment,
        "issued_at": cred.issued_at,
        "expires_at": cred.expires_at,
        "revoked_at": cred.revoked_at,
        "revocation_reason_code": cred.revocation_reason_code,
    }


@router.post("/v1/credentials/{credential_id}/revoke", status_code=status.HTTP_200_OK)
def revoke_credential(
    credential_id: str,
    payload: CredentialRevokeRequest,
    workspace: CurrentWorkspace,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Revoke an issued credential immediately. Only authorized organization admins/owners can revoke."""
    cred = db.execute(
        select(AgentCredential).where(
            AgentCredential.credential_id == credential_id,
            AgentCredential.organization_id == workspace.organization.id,
        )
    ).scalar_one_or_none()

    if not cred:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"message": "Credential not found in this organization.", "code": "CREDENTIAL_NOT_FOUND"},
        )

    revoked = revoke_agent_credential(db=db, credential_id=credential_id, reason_code=payload.reason_code)
    return {
        "credential_id": revoked.credential_id,
        "status": revoked.status,
        "revoked_at": revoked.revoked_at.isoformat() if revoked.revoked_at else None,
        "reason_code": revoked.revocation_reason_code,
    }


@router.get("/v1/credentials")
def list_credentials(
    workspace: CurrentWorkspace,
    user: CurrentUser,
    db: Session = Depends(get_db),
    agent_id: Optional[str] = None,
    credential_type: Optional[str] = None,
    status_filter: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List verifiable credentials belonging to the current organization."""
    query = select(AgentCredential).where(AgentCredential.organization_id == workspace.organization.id)
    if status_filter:
        query = query.where(AgentCredential.status == status_filter.upper())
    if credential_type:
        query = query.where(AgentCredential.credential_type == credential_type)

    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    records = db.scalars(query.order_by(desc(AgentCredential.created_at)).offset(offset).limit(limit)).all()

    items = []
    for r in records:
        items.append({
            "id": str(r.id),
            "credential_id": r.credential_id,
            "credential_type": r.credential_type,
            "environment": r.environment,
            "subject_agent_id": str(r.subject_agent_id),
            "status": r.status,
            "issued_at": r.issued_at.isoformat(),
            "expires_at": r.expires_at.isoformat(),
            "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
            "claims": r.claims_json,
            "signing_key_id": r.signing_key_id,
        })

    return {"items": items, "total": total, "limit": limit, "offset": offset}


# ----------------------------------------------------------------------
# 2. Trust Registry Issuer Management Endpoints
# ----------------------------------------------------------------------

@router.get("/v1/trust-registry/issuers", response_model=List[CredentialIssuerResponse])
def list_issuers(
    workspace: CurrentWorkspace,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> List[CredentialIssuer]:
    """List credential issuers configured for the current organization."""
    issuers = db.scalars(
        select(CredentialIssuer).where(CredentialIssuer.organization_id == workspace.organization.id)
    ).all()
    return list(issuers)


@router.post("/v1/trust-registry/issuers", status_code=status.HTTP_201_CREATED, response_model=CredentialIssuerResponse)
def create_issuer(
    payload: CredentialIssuerCreate,
    workspace: CurrentWorkspace,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> CredentialIssuer:
    """Create a new Credential Issuer for the organization."""
    issuer, _ = create_credential_issuer(
        db=db,
        organization_id=workspace.organization.id,
        name=payload.name,
    )
    return issuer


@router.get("/v1/trust-registry/issuers/{issuer_id}")
def get_issuer_public_info(
    issuer_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Public Trust Registry endpoint: return issuer metadata, status, and public verification keys."""
    issuer = db.execute(
        select(CredentialIssuer).where(CredentialIssuer.issuer_id == issuer_id)
    ).scalar_one_or_none()

    if not issuer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"message": f"Issuer '{issuer_id}' not found.", "code": "CREDENTIAL_ISSUER_UNKNOWN"},
        )

    keys = db.scalars(
        select(IssuerSigningKey).where(IssuerSigningKey.issuer_id == issuer.id)
    ).all()

    keys_data = [
        {
            "key_id": k.key_id,
            "algorithm": k.algorithm,
            "public_key": k.public_key,
            "fingerprint": k.fingerprint,
            "status": k.status,
            "created_at": k.created_at.isoformat(),
            "activated_at": k.activated_at.isoformat(),
            "expires_at": k.expires_at.isoformat() if k.expires_at else None,
            "revoked_at": k.revoked_at.isoformat() if k.revoked_at else None,
            "rotated_from_key_id": k.rotated_from_key_id,
        }
        for k in keys
    ]

    return {
        "issuer_id": issuer.issuer_id,
        "name": issuer.name,
        "status": issuer.status,
        "supported_versions": ["ATC/1.0"],
        "supported_types": ["AgentIdentityCredential", "AgentCapabilityCredential"],
        "signing_keys": keys_data,
        "created_at": issuer.created_at.isoformat(),
    }


@router.post("/v1/trust-registry/issuers/{issuer_id}/rotate-key", response_model=IssuerSigningKeySchema)
def rotate_key(
    issuer_id: str,
    payload: RotateKeyRequest,
    workspace: CurrentWorkspace,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> IssuerSigningKey:
    """Rotate an issuer's active signing key."""
    issuer = db.execute(
        select(CredentialIssuer).where(
            CredentialIssuer.issuer_id == issuer_id,
            CredentialIssuer.organization_id == workspace.organization.id,
        )
    ).scalar_one_or_none()

    if not issuer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Issuer not found.")

    try:
        new_key = rotate_issuer_signing_key(db=db, issuer_id=issuer_id, revoke_old_key=payload.revoke_old_key)
        return new_key
    except CredentialVerificationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)


@router.post("/v1/trust-registry/issuers/{issuer_id}/suspend")
def suspend_issuer(
    issuer_id: str,
    workspace: CurrentWorkspace,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Suspend an issuer."""
    issuer = db.execute(
        select(CredentialIssuer).where(
            CredentialIssuer.issuer_id == issuer_id,
            CredentialIssuer.organization_id == workspace.organization.id,
        )
    ).scalar_one_or_none()

    if not issuer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Issuer not found.")

    now = datetime.now(timezone.utc)
    issuer.status = IssuerStatus.SUSPENDED.value
    issuer.suspended_at = now
    db.commit()
    return {"issuer_id": issuer.issuer_id, "status": issuer.status, "suspended_at": now.isoformat()}


@router.post("/v1/trust-registry/issuers/{issuer_id}/revoke")
def revoke_issuer(
    issuer_id: str,
    workspace: CurrentWorkspace,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Revoke an issuer."""
    issuer = db.execute(
        select(CredentialIssuer).where(
            CredentialIssuer.issuer_id == issuer_id,
            CredentialIssuer.organization_id == workspace.organization.id,
        )
    ).scalar_one_or_none()

    if not issuer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Issuer not found.")

    now = datetime.now(timezone.utc)
    issuer.status = IssuerStatus.REVOKED.value
    issuer.revoked_at = now
    db.commit()
    return {"issuer_id": issuer.issuer_id, "status": issuer.status, "revoked_at": now.isoformat()}
