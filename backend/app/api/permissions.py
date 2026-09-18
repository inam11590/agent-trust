"""Protected permission creation, owner-scoped reads, and revocation."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.schemas.permission import PermissionCreate, PermissionResponse
from app.services.permissions import (
    AgentNotFound,
    create_permission,
    get_owned_permission,
    list_owned_permissions,
    revoke_owned_permission,
)
from app.services.organization_context import CurrentWorkspace
from app.services.organization_context import resolve_workspace
from app.services.security_events import record_security_event
from app.models import Agent

router = APIRouter(prefix="/permissions", tags=["permissions"])


@router.post("", response_model=PermissionResponse, status_code=201)
def grant_permission(
    payload: PermissionCreate,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> PermissionResponse:
    target = workspace
    if workspace.is_personal:
        agent = db.scalar(select(Agent).where(Agent.id == payload.agent_id))
        if agent is not None and agent.organization_id is not None:
            target = resolve_workspace(db, user.id, agent.organization_id)
            if target is None:
                raise HTTPException(status_code=404, detail="Agent not found")
    target.require("manage_permissions")
    try:
        permission = create_permission(db, user.id, payload, target.organization_id)
    except AgentNotFound:
        raise HTTPException(status_code=404, detail="Agent not found") from None
    response.headers["Location"] = f"/permissions/{permission.id}"
    response.headers["Cache-Control"] = "no-store"
    return PermissionResponse.model_validate(permission)


@router.get("", response_model=list[PermissionResponse])
def get_permissions(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> list[PermissionResponse]:
    response.headers["Cache-Control"] = "no-store"
    return [
        PermissionResponse.model_validate(permission)
        for permission in list_owned_permissions(db, user.id, workspace.organization_id)
    ]


@router.get("/{permission_id}", response_model=PermissionResponse)
def get_permission(
    permission_id: UUID,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> PermissionResponse:
    workspace.require("read")
    permission = get_owned_permission(db, user.id, permission_id, workspace.organization_id)
    if permission is None:
        raise HTTPException(status_code=404, detail="Permission not found")
    response.headers["Cache-Control"] = "no-store"
    return PermissionResponse.model_validate(permission)


@router.post("/{permission_id}/revoke", response_model=PermissionResponse)
def revoke_permission(
    permission_id: UUID,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> PermissionResponse:
    workspace.require("manage_permissions")
    permission = revoke_owned_permission(db, user.id, permission_id, workspace.organization_id)
    if permission is None:
        raise HTTPException(status_code=404, detail="Permission not found")
    record_security_event(
        db, user.id, "permission.revoked", organization_id=workspace.organization_id,
        description=f"Permission: {permission.id}",
    )
    response.headers["Cache-Control"] = "no-store"
    return PermissionResponse.model_validate(permission)
