"""Protected agent-to-agent delegation endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.models.agent import Agent
from app.models.agent_delegation import AgentDelegation, DelegationStatus
from app.schemas.agent_delegation import (
    AgentDelegationCreate,
    AgentDelegationResponse,
    DelegationChainResponse,
    DelegationRevokeRequest,
)
from app.services.agent_delegation import (
    create_delegation,
    get_delegation_chain,
    list_delegations,
    revoke_delegation,
)
from app.services.organization_context import CurrentWorkspace, resolve_workspace
from app.services.security_events import record_security_event

router = APIRouter(prefix="/agent-delegations", tags=["agent-delegations"])


def _populate_names(db: Session, delegation: AgentDelegation) -> AgentDelegationResponse:
    parent_agent = db.get(Agent, delegation.parent_agent_id)
    child_agent = db.get(Agent, delegation.child_agent_id)
    resp = AgentDelegationResponse.model_validate(delegation)
    resp.parent_agent_name = parent_agent.name if parent_agent else None
    resp.child_agent_name = child_agent.name if child_agent else None
    return resp


@router.post("", response_model=AgentDelegationResponse, status_code=201)
def create_agent_delegation(
    payload: AgentDelegationCreate,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> AgentDelegationResponse:
    target = workspace
    if workspace.is_personal:
        parent_agent = db.get(Agent, payload.parent_agent_id)
        if parent_agent is not None and parent_agent.organization_id is not None:
            target = resolve_workspace(db, user.id, parent_agent.organization_id)
            if target is None:
                raise HTTPException(status_code=404, detail="Parent agent organization not found")
    target.require("manage_permissions")

    delegation = create_delegation(db, payload, current_user=user)
    record_security_event(
        db,
        actor_user_id=user.id,
        event_type="agent_delegation_created",
        organization_id=delegation.organization_id,
        severity="low",
        description=f"Delegated {delegation.action} on {delegation.resource} from agent {delegation.parent_agent_id} to {delegation.child_agent_id}",
        details={"delegation_id": delegation.delegation_id, "depth": delegation.current_depth},
    )

    response.headers["Location"] = f"/agent-delegations/{delegation.delegation_id}"
    response.headers["Cache-Control"] = "no-store"
    return _populate_names(db, delegation)


@router.get("", response_model=list[AgentDelegationResponse])
def get_agent_delegations(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    status: DelegationStatus | None = None,
    agent_id: UUID | None = None,
) -> list[AgentDelegationResponse]:
    response.headers["Cache-Control"] = "no-store"
    if not workspace.organization_id:
        return []
    workspace.require("view_organization")

    delegations = list_delegations(
        db,
        organization_id=workspace.organization_id,
        status_filter=status,
        agent_id=agent_id,
    )
    return [_populate_names(db, dlg) for dlg in delegations]


@router.get("/{delegation_id}", response_model=AgentDelegationResponse)
def get_agent_delegation(
    delegation_id: str,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> AgentDelegationResponse:
    response.headers["Cache-Control"] = "no-store"
    delegation = db.scalar(
        select(AgentDelegation).where(AgentDelegation.delegation_id == delegation_id)
    )
    if not delegation:
        raise HTTPException(status_code=404, detail="Delegation not found")

    if workspace.organization_id and delegation.organization_id != workspace.organization_id:
        raise HTTPException(status_code=404, detail="Delegation not found")

    return _populate_names(db, delegation)


@router.get("/{delegation_id}/chain", response_model=DelegationChainResponse)
def get_delegation_chain_route(
    delegation_id: str,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> DelegationChainResponse:
    response.headers["Cache-Control"] = "no-store"
    delegation = db.scalar(
        select(AgentDelegation).where(AgentDelegation.delegation_id == delegation_id)
    )
    if not delegation:
        raise HTTPException(status_code=404, detail="Delegation not found")

    if workspace.organization_id and delegation.organization_id != workspace.organization_id:
        raise HTTPException(status_code=404, detail="Delegation not found")

    return get_delegation_chain(db, delegation_id)


@router.post("/{delegation_id}/revoke", response_model=AgentDelegationResponse)
def revoke_agent_delegation(
    delegation_id: str,
    payload: DelegationRevokeRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> AgentDelegationResponse:
    response.headers["Cache-Control"] = "no-store"
    delegation = db.scalar(
        select(AgentDelegation).where(AgentDelegation.delegation_id == delegation_id)
    )
    if not delegation:
        raise HTTPException(status_code=404, detail="Delegation not found")

    if workspace.organization_id and delegation.organization_id != workspace.organization_id:
        raise HTTPException(status_code=404, detail="Delegation not found")

    workspace.require("manage_permissions")

    revoked = revoke_delegation(
        db,
        delegation_id=delegation_id,
        revoked_by_user_id=user.id,
        reason=payload.reason,
        cascade=True,
    )
    record_security_event(
        db,
        actor_user_id=user.id,
        event_type="agent_delegation_revoked",
        organization_id=delegation.organization_id,
        severity="medium",
        description=f"Revoked delegation {delegation_id} and cascaded to descendants",
        details={"delegation_id": delegation_id, "reason": payload.reason},
    )

    return _populate_names(db, revoked)

