"""Protected agent registration and owner-scoped read routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.schemas.agent import AgentCreate, AgentResponse, AgentUpdate
from app.services.agents import (
    AgentIdentifierGenerationError,
    InvalidAgentTransition,
    OrganizationNotFound,
    create_agent,
    get_owned_agent,
    list_owned_agents,
    update_owned_agent,
)
from app.services.organization_context import CurrentWorkspace, resolve_workspace
from app.services.security_events import record_security_event
from app.models import AgentStatus

router = APIRouter(prefix="/agents", tags=["agents"])


@router.post("", response_model=AgentResponse, status_code=201)
def register_agent(
    payload: AgentCreate,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> AgentResponse:
    target = workspace
    if payload.organization_id is not None and payload.organization_id != workspace.organization_id:
        target = resolve_workspace(db, user.id, payload.organization_id)
        if target is None:
            raise HTTPException(status_code=404, detail="Organization not found")
    target.require("manage_agents")
    try:
        agent = create_agent(db, user.id, payload, target.organization_id)
    except OrganizationNotFound:
        raise HTTPException(status_code=404, detail="Organization not found") from None
    except AgentIdentifierGenerationError:
        raise HTTPException(status_code=503, detail="Could not create agent identifier") from None

    response.headers["Location"] = f"/agents/{agent.agent_identifier}"
    response.headers["Cache-Control"] = "no-store"
    return AgentResponse.model_validate(agent)


@router.get("", response_model=list[AgentResponse])
def get_agents(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> list[AgentResponse]:
    response.headers["Cache-Control"] = "no-store"
    workspace.require("read")
    return [AgentResponse.model_validate(agent) for agent in list_owned_agents(db, user.id, workspace.organization_id)]


@router.get("/{agent_identifier}", response_model=AgentResponse)
def get_agent(
    agent_identifier: str,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> AgentResponse:
    workspace.require("read")
    agent = get_owned_agent(db, user.id, agent_identifier, workspace.organization_id)
    if agent is None:
        # The same response is used for missing agents and agents owned by others.
        raise HTTPException(status_code=404, detail="Agent not found")
    response.headers["Cache-Control"] = "no-store"
    return AgentResponse.model_validate(agent)


@router.patch("/{agent_identifier}", response_model=AgentResponse)
def update_agent(
    agent_identifier: str,
    payload: AgentUpdate,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> AgentResponse:
    workspace.require("manage_agents")
    try:
        agent = update_owned_agent(db, user.id, agent_identifier, payload, workspace.organization_id)
    except InvalidAgentTransition:
        raise HTTPException(status_code=409, detail="A revoked agent cannot be reactivated") from None
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if payload.status == AgentStatus.REVOKED:
        record_security_event(
            db, user.id, "agent.revoked", organization_id=workspace.organization_id,
            description=f"Agent: {agent.agent_identifier}",
        )
    response.headers["Cache-Control"] = "no-store"
    return AgentResponse.model_validate(agent)
