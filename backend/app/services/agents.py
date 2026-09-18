"""Agent registration and owner-scoped queries, independent of HTTP."""

import secrets
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Agent, AgentStatus, NotificationPriority, NotificationType, Organization
from app.services.notification_service import create_notification
from app.schemas.agent import AgentCreate, AgentUpdate
from app.services.plan_limits import enforce_resource_limit

AGENT_IDENTIFIER_PREFIX = "agt_"
AGENT_IDENTIFIER_BYTES = 12
MAX_IDENTIFIER_ATTEMPTS = 5


class OrganizationNotFound(Exception):
    pass


class AgentIdentifierGenerationError(Exception):
    pass


class InvalidAgentTransition(Exception):
    pass


def generate_agent_identifier() -> str:
    return f"{AGENT_IDENTIFIER_PREFIX}{secrets.token_hex(AGENT_IDENTIFIER_BYTES)}"


def create_agent(
    db: Session, owner_id: UUID, payload: AgentCreate, organization_id: UUID | None = None,
) -> Agent:
    enforce_resource_limit(db, organization_id, "agents")
    target_organization_id = organization_id if organization_id is not None else payload.organization_id
    if target_organization_id is not None:
        organization = db.scalar(
            select(Organization).where(
                Organization.id == target_organization_id,
                Organization.is_active.is_(True),
            )
        )
        if organization is None:
            # This also prevents assigning an agent to another user's organization.
            raise OrganizationNotFound

    for _ in range(MAX_IDENTIFIER_ATTEMPTS):
        agent = Agent(
            name=payload.name,
            description=payload.description,
            agent_identifier=generate_agent_identifier(),
            owner_id=owner_id,
            organization_id=target_organization_id,
        )
        db.add(agent)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            constraint = getattr(getattr(exc.orig, "diag", None), "constraint_name", None)
            if constraint == "uq_agents_agent_identifier":
                continue
            raise
        db.refresh(agent)
        return agent

    raise AgentIdentifierGenerationError


def list_owned_agents(db: Session, owner_id: UUID, organization_id: UUID | None = None) -> list[Agent]:
    condition = (
        Agent.organization_id == organization_id
        if organization_id is not None
        else (Agent.owner_id == owner_id) & Agent.organization_id.is_(None)
    )
    return list(db.scalars(
        select(Agent)
        .where(condition)
        .order_by(Agent.created_at.desc(), Agent.id.desc())
    ))


def get_owned_agent(
    db: Session, owner_id: UUID, agent_identifier: str, organization_id: UUID | None = None,
) -> Agent | None:
    condition = (
        Agent.organization_id == organization_id
        if organization_id is not None
        else (Agent.owner_id == owner_id) & Agent.organization_id.is_(None)
    )
    return db.scalar(
        select(Agent).where(
            condition,
            Agent.agent_identifier == agent_identifier,
        )
    )


def update_owned_agent(
    db: Session,
    owner_id: UUID,
    agent_identifier: str,
    payload: AgentUpdate,
    organization_id: UUID | None = None,
) -> Agent | None:
    agent = get_owned_agent(db, owner_id, agent_identifier, organization_id)
    if agent is None:
        return None
    if agent.status == AgentStatus.REVOKED and payload.status not in (None, AgentStatus.REVOKED):
        raise InvalidAgentTransition
    previous_status = agent.status
    for field in payload.model_fields_set:
        setattr(agent, field, getattr(payload, field))
    if agent.status != previous_status and agent.status in {AgentStatus.SUSPENDED, AgentStatus.REVOKED}:
        create_notification(
            db, user_id=agent.owner_id, organization_id=agent.organization_id,
            notification_type=(
                NotificationType.AGENT_SUSPENDED if agent.status == AgentStatus.SUSPENDED
                else NotificationType.AGENT_REVOKED
            ),
            title="Agent Suspended" if agent.status == AgentStatus.SUSPENDED else "Agent Revoked",
            message=f"{agent.name} is now {agent.status.value}.", priority=NotificationPriority.HIGH,
            related_agent_id=agent.id,
            deduplication_key=f"agent-status:{agent.id}:{agent.status.value}",
        )
    db.commit()
    db.refresh(agent)
    return agent
