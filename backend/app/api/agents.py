from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.models import AgentStatus
from app.models.agent import Agent
from app.models.agent_governance import AgentOwnershipHistory
from app.schemas.agent import AgentCreate, AgentResponse, AgentUpdate
from app.schemas.agent_governance import (
    AgentLifecycleTransitionRequest,
    AgentOwnershipHistoryResponse,
    AgentOwnershipTransferRequest,
    DependencyGraphResponse,
    EmergencySuspendRequest,
    ReactivateAgentRequest,
    RetireAgentRequest,
    RetirementCheckResponse,
)
from app.services.agent_governance import (
    calculate_blast_radius_graph,
    transfer_agent_ownership,
)
from app.services.agent_lifecycle import (
    LifecycleTransitionError,
    check_retirement_dependencies,
    transition_lifecycle,
)
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
    status: Optional[str] = Query(None, description="Filter by status (e.g. active, draft, suspended)"),
    risk: Optional[str] = Query(None, description="Filter by risk classification (LOW, MEDIUM, HIGH, CRITICAL)"),
    search: Optional[str] = Query(None, description="Search by name or identifier"),
) -> list[AgentResponse]:
    response.headers["Cache-Control"] = "no-store"
    workspace.require("read")

    agents = list_owned_agents(db, user.id, workspace.organization_id)

    # In-memory filter for flexible query compatibility
    filtered = []
    for ag in agents:
        if status and ag.status.value.lower() != status.lower():
            continue
        if risk and (ag.risk_classification or "LOW").upper() != risk.upper():
            continue
        if search:
            s = search.lower()
            if s not in ag.name.lower() and s not in ag.agent_identifier.lower():
                continue
        filtered.append(ag)

    return [AgentResponse.model_validate(agent) for agent in filtered]


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


# ---------------------------------------------------------------------------
# Step 28: Lifecycle and Governance Sub-routes
# ---------------------------------------------------------------------------

@router.post("/{agent_identifier}/lifecycle/transition", response_model=AgentResponse)
def transition_agent(
    agent_identifier: str,
    payload: AgentLifecycleTransitionRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> AgentResponse:
    """Transition agent lifecycle state through the authoritative state machine."""
    workspace.require("manage_agents")
    agent = get_owned_agent(db, user.id, agent_identifier, workspace.organization_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    try:
        updated = transition_lifecycle(
            db,
            agent,
            target_status=payload.target_status,
            acting_user_id=user.id,
            reason=payload.reason,
            bypass_checklist=payload.bypass_checklist,
        )
        return AgentResponse.model_validate(updated)
    except LifecycleTransitionError as err:
        raise HTTPException(status_code=err.status_code, detail=err.message)


@router.post("/{agent_identifier}/ownership/transfer", response_model=AgentOwnershipHistoryResponse)
def transfer_ownership(
    agent_identifier: str,
    payload: AgentOwnershipTransferRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> AgentOwnershipHistoryResponse:
    """Transfer agent ownership to another user, team, or service principal."""
    workspace.require("manage_agents")
    agent = get_owned_agent(db, user.id, agent_identifier, workspace.organization_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    history = transfer_agent_ownership(
        db,
        agent,
        new_owner_id=payload.new_owner_id,
        new_owner_type=payload.new_owner_type,
        reason=payload.reason,
        changed_by_user_id=user.id,
        new_team=payload.new_team,
    )
    return AgentOwnershipHistoryResponse.model_validate(history)


@router.get("/{agent_identifier}/ownership/history", response_model=list[AgentOwnershipHistoryResponse])
def get_ownership_history(
    agent_identifier: str,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> list[AgentOwnershipHistoryResponse]:
    """Retrieve the immutable ownership transfer audit trail for an agent."""
    workspace.require("read")
    agent = get_owned_agent(db, user.id, agent_identifier, workspace.organization_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    history = db.scalars(
        select(AgentOwnershipHistory)
        .where(AgentOwnershipHistory.agent_id == agent.id)
        .order_by(AgentOwnershipHistory.changed_at.desc())
    ).all()
    return [AgentOwnershipHistoryResponse.model_validate(h) for h in history]


@router.get("/{agent_identifier}/relationships", response_model=DependencyGraphResponse)
def get_relationships(
    agent_identifier: str,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> DependencyGraphResponse:
    """Retrieve full dependency graph and blast-radius analysis for an agent."""
    workspace.require("read")
    agent = get_owned_agent(db, user.id, agent_identifier, workspace.organization_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    graph = calculate_blast_radius_graph(db, agent.id)
    return DependencyGraphResponse(**graph)


@router.post("/{agent_identifier}/retirement/check", response_model=RetirementCheckResponse)
def check_retirement(
    agent_identifier: str,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> RetirementCheckResponse:
    """Inspect dependent delegations and active credentials before retirement."""
    workspace.require("manage_agents")
    agent = get_owned_agent(db, user.id, agent_identifier, workspace.organization_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    deps = check_retirement_dependencies(db, agent)
    return RetirementCheckResponse(**deps)


@router.post("/{agent_identifier}/retirement/execute", response_model=AgentResponse)
def execute_retirement(
    agent_identifier: str,
    payload: RetireAgentRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> AgentResponse:
    """Safely decommission an agent, revoking credentials and terminating delegations."""
    workspace.require("manage_agents")
    agent = get_owned_agent(db, user.id, agent_identifier, workspace.organization_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    deps = check_retirement_dependencies(db, agent)
    if deps["has_active_dependencies"] and not payload.force:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot retire agent: {deps['summary']}. Use force=True to automatically revoke dependencies.",
        )

    try:
        updated = transition_lifecycle(
            db,
            agent,
            target_status=AgentStatus.RETIRED,
            acting_user_id=user.id,
            reason=payload.reason,
            bypass_checklist=True,
        )
        return AgentResponse.model_validate(updated)
    except LifecycleTransitionError as err:
        raise HTTPException(status_code=err.status_code, detail=err.message)


@router.post("/{agent_identifier}/suspend", response_model=AgentResponse)
def suspend_agent(
    agent_identifier: str,
    payload: EmergencySuspendRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> AgentResponse:
    """Instantly suspend an agent across Control Plane and Gateway data planes."""
    workspace.require("manage_agents")
    agent = get_owned_agent(db, user.id, agent_identifier, workspace.organization_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    try:
        updated = transition_lifecycle(
            db,
            agent,
            target_status=AgentStatus.SUSPENDED,
            acting_user_id=user.id,
            reason=payload.reason,
            bypass_checklist=True,
        )
        return AgentResponse.model_validate(updated)
    except LifecycleTransitionError as err:
        raise HTTPException(status_code=err.status_code, detail=err.message)


@router.post("/{agent_identifier}/reactivate", response_model=AgentResponse)
def reactivate_agent(
    agent_identifier: str,
    payload: ReactivateAgentRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> AgentResponse:
    """Reactivate a previously suspended agent."""
    workspace.require("manage_agents")
    agent = get_owned_agent(db, user.id, agent_identifier, workspace.organization_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    try:
        updated = transition_lifecycle(
            db,
            agent,
            target_status=AgentStatus.ACTIVE,
            acting_user_id=user.id,
            reason=payload.reason or "Reactivated from suspension",
        )
        return AgentResponse.model_validate(updated)
    except LifecycleTransitionError as err:
        raise HTTPException(status_code=err.status_code, detail=err.message)

