"""JWT-authenticated management of agent public signing keys."""

from typing import Annotated
from uuid import UUID
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.account_security import require_recent_step_up
from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.models import Agent, AgentSigningKey, AgentSigningKeyStatus, OrganizationRole
from app.schemas.agent_signing import SigningKeyCreate, SigningKeyResponse
from app.services.agent_signing import SigningError, register_key, revoke_key
from app.services.organization_context import CurrentWorkspace
from app.services.security_events import record_security_event

router = APIRouter(prefix="/agents/{agent_id}/signing-keys", tags=["agent signing keys"])


def _agent(db: Session, agent_id: UUID, user_id: UUID, workspace: CurrentWorkspace,
           *, write: bool) -> Agent:
    workspace.require("manage_keys" if write else "read")
    conditions = [Agent.id == agent_id, Agent.organization_id == workspace.organization_id]
    if workspace.organization_id is None or (write and workspace.role == OrganizationRole.DEVELOPER):
        conditions.append(Agent.owner_id == user_id)
    agent = db.scalar(select(Agent).where(*conditions))
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


def _key(db: Session, agent: Agent, key_id: str) -> AgentSigningKey:
    key = db.scalar(select(AgentSigningKey).where(
        AgentSigningKey.key_id == key_id, AgentSigningKey.agent_id == agent.id,
        AgentSigningKey.organization_id == agent.organization_id,
    ))
    if key is None:
        raise HTTPException(status_code=404, detail="Signing key not found")
    return key


@router.get("", response_model=list[SigningKeyResponse])
def list_keys(agent_id: UUID, user: CurrentUser, workspace: CurrentWorkspace, response: Response,
              db: Annotated[Session, Depends(get_db)]):
    agent = _agent(db, agent_id, user.id, workspace, write=False)
    now = datetime.now(timezone.utc)
    keys = list(db.scalars(select(AgentSigningKey).where(AgentSigningKey.agent_id == agent.id)
                           .order_by(AgentSigningKey.created_at.desc())))
    changed = False
    for key in keys:
        if key.status in {AgentSigningKeyStatus.ACTIVE, AgentSigningKeyStatus.ROTATING} and key.expires_at is not None and key.expires_at <= now:
            key.status = AgentSigningKeyStatus.EXPIRED
            changed = True
    if changed:
        db.commit()
    response.headers["Cache-Control"] = "no-store"
    return keys


@router.post("", response_model=SigningKeyResponse, status_code=201)
def add_key(agent_id: UUID, payload: SigningKeyCreate, user: CurrentUser, workspace: CurrentWorkspace,
            request: Request, response: Response, db: Annotated[Session, Depends(get_db)]):
    agent = _agent(db, agent_id, user.id, workspace, write=True)
    require_recent_step_up(request)
    try:
        key = register_key(db, agent, payload, request.app.state.settings)
    except SigningError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.code) from None
    record_security_event(db, user.id, "agent_signing_key_added", organization_id=agent.organization_id,
        description=f"Public signing key registered for {agent.name}", details={"key_id": key.key_id})
    response.headers["Cache-Control"] = "no-store"
    return key


@router.post("/{key_id}/rotate", response_model=SigningKeyResponse, status_code=201)
def rotate(agent_id: UUID, key_id: str, payload: SigningKeyCreate, user: CurrentUser,
           workspace: CurrentWorkspace, request: Request, response: Response,
           db: Annotated[Session, Depends(get_db)]):
    agent = _agent(db, agent_id, user.id, workspace, write=True)
    require_recent_step_up(request)
    old = _key(db, agent, key_id)
    if old.status not in {AgentSigningKeyStatus.ACTIVE, AgentSigningKeyStatus.ROTATING}:
        raise HTTPException(status_code=409, detail="Signing key is not active")
    try:
        key = register_key(db, agent, payload, request.app.state.settings, rotated_from=old)
    except SigningError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.code) from None
    record_security_event(db, user.id, "agent_signing_key_rotated", organization_id=agent.organization_id,
        description=f"Signing key rotated for {agent.name}", details={"old_key_id": old.key_id, "new_key_id": key.key_id})
    response.headers["Cache-Control"] = "no-store"
    return key


@router.post("/{key_id}/revoke", response_model=SigningKeyResponse)
def revoke(agent_id: UUID, key_id: str, user: CurrentUser, workspace: CurrentWorkspace,
           request: Request, response: Response, db: Annotated[Session, Depends(get_db)]):
    agent = _agent(db, agent_id, user.id, workspace, write=True)
    require_recent_step_up(request)
    key = _key(db, agent, key_id)
    changed = key.status != AgentSigningKeyStatus.REVOKED
    key = revoke_key(db, key)
    if changed:
        record_security_event(db, user.id, "agent_signing_key_revoked", organization_id=agent.organization_id,
            description=f"Signing key revoked for {agent.name}", severity="warning", details={"key_id": key.key_id})
    response.headers["Cache-Control"] = "no-store"
    return key
