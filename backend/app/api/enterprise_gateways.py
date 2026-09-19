"""Enterprise Gateway, Sidecar, and Configuration Synchronization API (Step 23)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.models.enterprise_gateway import EnterpriseGateway, GatewayConfigBundle
from app.schemas.enterprise_gateways import (
    EnterpriseGatewayResponse,
    GatewayConfigBundleResponse,
    GatewayConfigHistoryItem,
    GatewayEnrollRequest,
    GatewayEnrollResponse,
    GatewayHeartbeatRequest,
    GatewayHeartbeatResponse,
    GatewayPublishConfigRequest,
    GatewayRegistrationRequest,
    GatewayRegistrationResponse,
    GatewayRollbackRequest,
)
from app.services.gateway_control_service import (
    GatewayControlError,
    build_and_publish_config,
    enroll_enterprise_gateway,
    get_signed_config_bundle,
    register_enterprise_gateway,
    revoke_enterprise_gateway,
    rollback_gateway_config,
    suspend_enterprise_gateway,
    verify_gateway_heartbeat,
)
from app.services.organization_context import CurrentWorkspace

router = APIRouter(tags=["Enterprise Gateways & Sidecars"])


# ----------------------------------------------------------------------
# 1. Organization Gateway Management Endpoints
# ----------------------------------------------------------------------

@router.post("/gateways", response_model=GatewayRegistrationResponse, status_code=status.HTTP_201_CREATED)
def register_gateway(
    payload: GatewayRegistrationRequest,
    workspace: CurrentWorkspace,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> GatewayRegistrationResponse:
    """Register a new self-hosted gateway or sidecar and generate a one-time enrollment token."""
    try:
        gw, raw_token, cmd = register_enterprise_gateway(db, workspace.organization.id, payload)
        return GatewayRegistrationResponse(
            id=str(gw.id),
            gateway_id=gw.gateway_id,
            name=gw.name,
            deployment_type=gw.deployment_type,
            environment=gw.environment,
            status=gw.status,
            enrollment_token=raw_token,
            enrollment_command=cmd,
            enrollment_token_expires_at=gw.enrollment_token_expires_at or datetime.now(timezone.utc),
            created_at=gw.created_at,
        )
    except GatewayControlError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"message": exc.message, "code": exc.code})


@router.get("/gateways", response_model=List[EnterpriseGatewayResponse])
def list_gateways(
    workspace: CurrentWorkspace,
    user: CurrentUser,
    environment: Optional[str] = Query(None, description="Filter by environment"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status"),
    db: Session = Depends(get_db),
) -> List[EnterpriseGatewayResponse]:
    """List all enterprise gateways for the organization."""
    query = select(EnterpriseGateway).where(EnterpriseGateway.organization_id == workspace.organization.id)
    if environment:
        query = query.where(EnterpriseGateway.environment == environment.upper())
    if status_filter:
        query = query.where(EnterpriseGateway.status == status_filter.upper())
    query = query.order_by(desc(EnterpriseGateway.created_at))

    gateways = db.scalars(query).all()
    return [
        EnterpriseGatewayResponse(
            id=str(g.id),
            gateway_id=g.gateway_id,
            organization_id=str(g.organization_id),
            name=g.name,
            deployment_type=g.deployment_type,
            environment=g.environment,
            status=g.status,
            version=g.version,
            public_key=g.public_key,
            fingerprint=g.fingerprint,
            config_version=g.config_version,
            labels=g.labels,
            offline_policy=g.offline_policy,
            last_seen_at=g.last_seen_at,
            last_heartbeat_data=g.last_heartbeat_data,
            created_at=g.created_at,
            updated_at=g.updated_at,
            suspended_at=g.suspended_at,
            revoked_at=g.revoked_at,
        )
        for g in gateways
    ]


@router.get("/gateways/{gateway_id}", response_model=EnterpriseGatewayResponse)
def get_gateway(
    gateway_id: str,
    workspace: CurrentWorkspace,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> EnterpriseGatewayResponse:
    """Retrieve detailed enterprise gateway record."""
    gw = db.execute(
        select(EnterpriseGateway).where(
            EnterpriseGateway.gateway_id == gateway_id,
            EnterpriseGateway.organization_id == workspace.organization.id,
        )
    ).scalar_one_or_none()
    if not gw:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Gateway not found.")

    return EnterpriseGatewayResponse(
        id=str(gw.id),
        gateway_id=gw.gateway_id,
        organization_id=str(gw.organization_id),
        name=gw.name,
        deployment_type=gw.deployment_type,
        environment=gw.environment,
        status=gw.status,
        version=gw.version,
        public_key=gw.public_key,
        fingerprint=gw.fingerprint,
        config_version=gw.config_version,
        labels=gw.labels,
        offline_policy=gw.offline_policy,
        last_seen_at=gw.last_seen_at,
        last_heartbeat_data=gw.last_heartbeat_data,
        created_at=gw.created_at,
        updated_at=gw.updated_at,
        suspended_at=gw.suspended_at,
        revoked_at=gw.revoked_at,
    )


@router.post("/gateways/{gateway_id}/suspend")
def suspend_gateway(
    gateway_id: str,
    workspace: CurrentWorkspace,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Temporarily suspend gateway operations."""
    try:
        gw = suspend_enterprise_gateway(db, gateway_id, workspace.organization.id)
        return {"status": gw.status, "gateway_id": gw.gateway_id, "suspended_at": gw.suspended_at}
    except GatewayControlError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"message": exc.message, "code": exc.code})


@router.post("/gateways/{gateway_id}/revoke")
def revoke_gateway(
    gateway_id: str,
    workspace: CurrentWorkspace,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Permanently revoke gateway identity."""
    try:
        gw = revoke_enterprise_gateway(db, gateway_id, workspace.organization.id)
        return {"status": gw.status, "gateway_id": gw.gateway_id, "revoked_at": gw.revoked_at}
    except GatewayControlError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"message": exc.message, "code": exc.code})


# ----------------------------------------------------------------------
# 2. Configuration Management Endpoints
# ----------------------------------------------------------------------

@router.post("/gateways/config/publish", response_model=GatewayConfigBundleResponse, status_code=status.HTTP_201_CREATED)
def publish_config(
    payload: GatewayPublishConfigRequest,
    workspace: CurrentWorkspace,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> GatewayConfigBundleResponse:
    """Compile and publish a new signed, monotonically ordered configuration bundle."""
    try:
        bundle = build_and_publish_config(db, workspace.organization.id, payload, user_id=user.id)
        return GatewayConfigBundleResponse(
            config_version=bundle.config_version,
            organization_id=str(bundle.organization_id),
            environment=bundle.environment,
            issued_at=bundle.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            expires_at=bundle.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            bundle=bundle.bundle_json,
            bundle_sha256=bundle.bundle_sha256,
            signature=bundle.signature,
            signing_key_id=bundle.signing_key_id,
        )
    except GatewayControlError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"message": exc.message, "code": exc.code})


@router.post("/gateways/config/rollback", response_model=GatewayConfigBundleResponse)
def rollback_config(
    payload: GatewayRollbackRequest,
    workspace: CurrentWorkspace,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> GatewayConfigBundleResponse:
    """
    Roll back configuration by restoring historical content under a strictly
    higher monotonic version number, preserving anti-rollback invariants.
    """
    try:
        bundle = rollback_gateway_config(db, workspace.organization.id, payload, user_id=user.id)
        return GatewayConfigBundleResponse(
            config_version=bundle.config_version,
            organization_id=str(bundle.organization_id),
            environment=bundle.environment,
            issued_at=bundle.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            expires_at=bundle.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            bundle=bundle.bundle_json,
            bundle_sha256=bundle.bundle_sha256,
            signature=bundle.signature,
            signing_key_id=bundle.signing_key_id,
        )
    except GatewayControlError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"message": exc.message, "code": exc.code})


@router.get("/gateways/config/history", response_model=List[GatewayConfigHistoryItem])
def get_config_history(
    workspace: CurrentWorkspace,
    user: CurrentUser,
    environment: Optional[str] = Query("production"),
    db: Session = Depends(get_db),
) -> List[GatewayConfigHistoryItem]:
    """Retrieve published configuration bundle version history."""
    bundles = db.scalars(
        select(GatewayConfigBundle)
        .where(
            GatewayConfigBundle.organization_id == workspace.organization.id,
            GatewayConfigBundle.environment == environment.lower(),
        )
        .order_by(desc(GatewayConfigBundle.config_version))
        .limit(50)
    ).all()
    return [
        GatewayConfigHistoryItem(
            id=str(b.id),
            config_version=b.config_version,
            organization_id=str(b.organization_id),
            environment=b.environment,
            bundle_sha256=b.bundle_sha256,
            signing_key_id=b.signing_key_id,
            published_by_user_id=str(b.published_by_user_id) if b.published_by_user_id else None,
            created_at=b.created_at,
            expires_at=b.expires_at,
        )
        for b in bundles
    ]


# ----------------------------------------------------------------------
# 3. Direct Gateway / Data Plane Interaction Endpoints
# ----------------------------------------------------------------------

@router.post("/gateways/{gateway_id}/enroll", response_model=GatewayEnrollResponse)
def enroll_gateway_endpoint(
    gateway_id: str,
    payload: GatewayEnrollRequest,
    db: Session = Depends(get_db),
) -> GatewayEnrollResponse:
    """Public enrollment endpoint: establishes gateway identity with local public key and one-time token."""
    try:
        res = enroll_enterprise_gateway(db, gateway_id, payload)
        return GatewayEnrollResponse(**res)
    except GatewayControlError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"message": exc.message, "code": exc.code})


@router.post("/gateways/{gateway_id}/heartbeat", response_model=GatewayHeartbeatResponse)
def heartbeat_endpoint(
    gateway_id: str,
    payload: GatewayHeartbeatRequest,
    db: Session = Depends(get_db),
) -> GatewayHeartbeatResponse:
    """Signed heartbeat endpoint: verifies gateway signature and returns sync status."""
    try:
        res = verify_gateway_heartbeat(db, gateway_id, payload)
        return GatewayHeartbeatResponse(**res)
    except GatewayControlError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"message": exc.message, "code": exc.code})


@router.get("/gateways/{gateway_id}/config")
def download_config_endpoint(
    gateway_id: str,
    client_version: Optional[int] = Query(None, description="Current config version applied on gateway"),
    response: Response = None,
    db: Session = Depends(get_db),
) -> Any:
    """
    Download latest signed configuration bundle.
    Returns 304 Not Modified if client_version is already current.
    """
    try:
        bundle_data = get_signed_config_bundle(db, gateway_id, client_version=client_version)
        if bundle_data is None:
            if response:
                response.status_code = status.HTTP_304_NOT_MODIFIED
            return Response(status_code=status.HTTP_304_NOT_MODIFIED)
        return bundle_data
    except GatewayControlError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"message": exc.message, "code": exc.code})
