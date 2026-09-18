"""Permission lifecycle and owner-scoped persistence operations."""

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models import Agent, Permission, PermissionStatus
from app.schemas.permission import PermissionCreate


class AgentNotFound(Exception):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def create_permission(
    db: Session, owner_id: UUID, payload: PermissionCreate, organization_id: UUID | None = None,
) -> Permission:
    scope = (
        Agent.organization_id == organization_id
        if organization_id is not None
        else (Agent.owner_id == owner_id) & Agent.organization_id.is_(None)
    )
    agent_exists = db.scalar(
        select(Agent.id).where(Agent.id == payload.agent_id, scope)
    )
    if agent_exists is None:
        # This also prevents granting access to another user's agent.
        raise AgentNotFound

    permission = Permission(
        owner_id=owner_id,
        agent_id=payload.agent_id,
        action=payload.action,
        resource=payload.resource,
        maximum_amount=payload.maximum_amount,
        currency=payload.currency,
        requires_approval=payload.requires_approval,
        allow_delegation=payload.allow_delegation,
        valid_from=payload.valid_from,
        expires_at=payload.expires_at,
    )
    db.add(permission)
    db.commit()
    db.refresh(permission)
    return permission


def expire_owned_permissions(
    db: Session, owner_id: UUID, at: datetime | None = None,
    organization_id: UUID | None | object = ..., 
) -> None:
    checked_at = at or utc_now()
    conditions = [Permission.status == PermissionStatus.ACTIVE, Permission.expires_at <= checked_at]
    if organization_id is ...:
        conditions.append(Permission.owner_id == owner_id)
    elif organization_id is None:
        conditions.append(Permission.agent_id.in_(select(Agent.id).where(
            Agent.owner_id == owner_id, Agent.organization_id.is_(None),
        )))
    else:
        conditions.append(Permission.agent_id.in_(select(Agent.id).where(Agent.organization_id == organization_id)))
    result = db.execute(
        update(Permission)
        .where(*conditions)
        .values(status=PermissionStatus.EXPIRED)
    )
    if result.rowcount:
        db.commit()


def list_owned_permissions(db: Session, owner_id: UUID, organization_id: UUID | None = None) -> list[Permission]:
    expire_owned_permissions(db, owner_id, organization_id=organization_id)
    agent_scope = select(Agent.id).where(
        Agent.organization_id == organization_id
        if organization_id is not None
        else (Agent.owner_id == owner_id) & Agent.organization_id.is_(None)
    )
    return list(db.scalars(
        select(Permission)
        .where(Permission.agent_id.in_(agent_scope))
        .order_by(Permission.created_at.desc(), Permission.id.desc())
    ))


def get_owned_permission(
    db: Session, owner_id: UUID, permission_id: UUID, organization_id: UUID | None = None,
) -> Permission | None:
    agent_scope = select(Agent.id).where(
        Agent.organization_id == organization_id
        if organization_id is not None
        else (Agent.owner_id == owner_id) & Agent.organization_id.is_(None)
    )
    permission = db.scalar(
        select(Permission).where(
            Permission.id == permission_id,
            Permission.agent_id.in_(agent_scope),
        )
    )
    if (
        permission is not None
        and permission.status == PermissionStatus.ACTIVE
        and permission.expires_at <= utc_now()
    ):
        permission.status = PermissionStatus.EXPIRED
        db.commit()
        db.refresh(permission)
    return permission


def revoke_owned_permission(
    db: Session, owner_id: UUID, permission_id: UUID, organization_id: UUID | None = None,
) -> Permission | None:
    permission = get_owned_permission(db, owner_id, permission_id, organization_id)
    if permission is None:
        return None
    if permission.status == PermissionStatus.ACTIVE:
        permission.status = PermissionStatus.REVOKED
        db.commit()
        db.refresh(permission)
    return permission
