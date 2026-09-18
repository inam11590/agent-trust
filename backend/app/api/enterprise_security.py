"""Owner-only organization security policy and SSO administration."""

from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.account_security import require_recent_step_up
from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.models import NotificationPriority, NotificationType, OrganizationSecurityPolicy, SSOConnection
from app.schemas.enterprise_security import SecurityPolicyResponse, SecurityPolicyUpdate, SSOConnectionCreate, SSOConnectionResponse
from app.services.organization_context import resolve_workspace
from app.services.security_events import record_security_event
from app.services.notification_service import create_notification
from app.services.sso import SSOError, check_provider_url, encrypt_provider_secret, fetch_discovery

router = APIRouter(prefix="/organizations/{organization_id}", tags=["enterprise-security"])


def _owner(db: Session, user_id: UUID, organization_id: UUID) -> None:
    context = resolve_workspace(db, user_id, organization_id)
    if context is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    context.require("manage_security_policy")


def _policy(db: Session, organization_id: UUID) -> SecurityPolicyResponse:
    policy = db.get(OrganizationSecurityPolicy, organization_id)
    if policy is None:
        return SecurityPolicyResponse(organization_id=organization_id)
    return SecurityPolicyResponse.model_validate(policy, from_attributes=True)


@router.get("/security-policy", response_model=SecurityPolicyResponse)
def get_policy(organization_id: UUID, user: CurrentUser, db: Annotated[Session, Depends(get_db)], response: Response):
    _owner(db, user.id, organization_id)
    response.headers["Cache-Control"] = "no-store"
    return _policy(db, organization_id)


@router.put("/security-policy", response_model=SecurityPolicyResponse)
def set_policy(organization_id: UUID, payload: SecurityPolicyUpdate, user: CurrentUser, request: Request,
               db: Annotated[Session, Depends(get_db)], response: Response):
    _owner(db, user.id, organization_id)
    require_recent_step_up(request)
    merged = SecurityPolicyUpdate.model_validate({
        **_policy(db, organization_id).model_dump(exclude={"organization_id", "created_at", "updated_at"}),
        **payload.model_dump(exclude_unset=True),
    })
    if merged.require_sso and db.scalar(select(SSOConnection.id).where(
        SSOConnection.organization_id == organization_id, SSOConnection.status == "active",
    )) is None:
        raise HTTPException(status_code=409, detail="Enable and test an SSO connection before requiring SSO")
    policy = db.get(OrganizationSecurityPolicy, organization_id)
    if policy is None:
        policy = OrganizationSecurityPolicy(organization_id=organization_id)
        db.add(policy)
    for key, value in merged.model_dump().items():
        setattr(policy, key, value)
    record_security_event(db, user.id, "security_policy_changed", organization_id=organization_id,
        description="Organization security policy updated", severity="warning", commit=False)
    create_notification(db, user_id=user.id, organization_id=organization_id,
        notification_type=NotificationType.SECURITY_ALERT, title="Organization Security Policy Changed",
        message="Your organization security policy was updated.", priority=NotificationPriority.HIGH)
    db.commit()
    db.refresh(policy)
    response.headers["Cache-Control"] = "no-store"
    return _policy(db, organization_id)


@router.get("/sso/connections", response_model=list[SSOConnectionResponse])
def list_connections(organization_id: UUID, user: CurrentUser, db: Annotated[Session, Depends(get_db)], response: Response):
    _owner(db, user.id, organization_id)
    response.headers["Cache-Control"] = "no-store"
    return list(db.scalars(select(SSOConnection).where(SSOConnection.organization_id == organization_id).order_by(SSOConnection.created_at.desc())))


@router.post("/sso/connections", response_model=SSOConnectionResponse, status_code=201)
def create_connection(organization_id: UUID, payload: SSOConnectionCreate, user: CurrentUser, request: Request,
                      db: Annotated[Session, Depends(get_db)], response: Response):
    _owner(db, user.id, organization_id)
    require_recent_step_up(request)
    try:
        check_provider_url(payload.issuer, request.app.state.settings)
        check_provider_url(payload.discovery_url, request.app.state.settings)
        encrypted = encrypt_provider_secret(request.app.state.settings, payload.client_secret)
    except SSOError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    connection = SSOConnection(organization_id=organization_id, name=payload.name,
        issuer=payload.issuer.rstrip("/"), client_id=payload.client_id,
        encrypted_client_secret=encrypted, discovery_url=payload.discovery_url,
        allowed_domains=SecurityPolicyUpdate.domains(payload.allowed_domains), status="draft")
    db.add(connection)
    db.commit()
    db.refresh(connection)
    response.headers["Cache-Control"] = "no-store"
    return connection


def _connection(db: Session, organization_id: UUID, connection_id: UUID) -> SSOConnection:
    connection = db.scalar(select(SSOConnection).where(
        SSOConnection.id == connection_id, SSOConnection.organization_id == organization_id))
    if connection is None:
        raise HTTPException(status_code=404, detail="SSO connection not found")
    return connection


@router.post("/sso/connections/{connection_id}/test", response_model=SSOConnectionResponse)
def test_connection(organization_id: UUID, connection_id: UUID, user: CurrentUser, request: Request,
                    db: Annotated[Session, Depends(get_db)]):
    _owner(db, user.id, organization_id)
    require_recent_step_up(request)
    connection = _connection(db, organization_id, connection_id)
    try:
        fetch_discovery(connection, request.app.state.settings)
    except SSOError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from None
    connection.verified_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(connection)
    return connection


@router.post("/sso/connections/{connection_id}/enable", response_model=SSOConnectionResponse)
def enable_connection(organization_id: UUID, connection_id: UUID, user: CurrentUser, request: Request,
                      db: Annotated[Session, Depends(get_db)]):
    _owner(db, user.id, organization_id)
    require_recent_step_up(request)
    connection = _connection(db, organization_id, connection_id)
    if connection.verified_at is None:
        raise HTTPException(status_code=409, detail="Test this SSO connection first")
    connection.status = "active"
    record_security_event(db, user.id, "sso_enabled", organization_id=organization_id,
        description="SSO connection enabled", severity="warning", commit=False)
    create_notification(db, user_id=user.id, organization_id=organization_id,
        notification_type=NotificationType.SECURITY_ALERT, title="Company SSO Enabled",
        message="A company SSO connection was enabled.", priority=NotificationPriority.HIGH)
    db.commit()
    db.refresh(connection)
    return connection


@router.post("/sso/connections/{connection_id}/disable", response_model=SSOConnectionResponse)
def disable_connection(organization_id: UUID, connection_id: UUID, user: CurrentUser, request: Request,
                       db: Annotated[Session, Depends(get_db)]):
    _owner(db, user.id, organization_id)
    require_recent_step_up(request)
    policy = db.get(OrganizationSecurityPolicy, organization_id)
    if policy is not None and policy.require_sso:
        raise HTTPException(status_code=409, detail="Disable the SSO requirement before disabling this connection")
    connection = _connection(db, organization_id, connection_id)
    connection.status = "disabled"
    record_security_event(db, user.id, "sso_disabled", organization_id=organization_id,
        description="SSO connection disabled", severity="warning", commit=False)
    create_notification(db, user_id=user.id, organization_id=organization_id,
        notification_type=NotificationType.SECURITY_ALERT, title="Company SSO Disabled",
        message="A company SSO connection was disabled.", priority=NotificationPriority.HIGH)
    db.commit()
    db.refresh(connection)
    return connection
