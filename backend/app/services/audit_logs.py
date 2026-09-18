"""Owner-scoped, read-only audit history queries."""

from math import ceil
from uuid import UUID

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.models import Agent, AuditLog
from app.schemas.audit_log import AuditLogFilters


class AgentNotFound(Exception):
    pass


def _apply_filters(
    query: Select, owner_id: UUID, filters: AuditLogFilters,
    organization_id: UUID | None,
) -> Select:
    if organization_id is None:
        query = query.where(
            AuditLog.user_id == owner_id,
            AuditLog.organization_id.is_(None),
        )
    else:
        query = query.where(AuditLog.organization_id == organization_id)
    if filters.decision is not None:
        query = query.where(AuditLog.decision == filters.decision)
    if filters.agent_id is not None:
        query = query.where(AuditLog.agent_identifier == filters.agent_id)
    if filters.action is not None:
        query = query.where(AuditLog.action == filters.action)
    if filters.resource is not None:
        query = query.where(AuditLog.resource == filters.resource)
    if filters.start_date is not None:
        query = query.where(AuditLog.requested_at >= filters.start_date)
    if filters.end_date is not None:
        query = query.where(AuditLog.requested_at <= filters.end_date)
    return query


def list_audit_logs(
    db: Session,
    owner_id: UUID,
    filters: AuditLogFilters,
    organization_id: UUID | None = None,
) -> tuple[list[AuditLog], int, int]:
    total = db.scalar(
        _apply_filters(select(func.count()).select_from(AuditLog), owner_id, filters, organization_id)
    ) or 0
    items = list(db.scalars(
        _apply_filters(select(AuditLog), owner_id, filters, organization_id)
        .order_by(AuditLog.requested_at.desc(), AuditLog.id.desc())
        .offset((filters.page - 1) * filters.page_size)
        .limit(filters.page_size)
    ))
    total_pages = ceil(total / filters.page_size) if total else 0
    return items, total, total_pages


def get_owned_audit_log(
    db: Session, owner_id: UUID, audit_log_id: UUID, organization_id: UUID | None = None,
) -> AuditLog | None:
    scope = (
        AuditLog.organization_id == organization_id
        if organization_id is not None
        else (AuditLog.user_id == owner_id) & AuditLog.organization_id.is_(None)
    )
    return db.scalar(
        select(AuditLog).where(AuditLog.id == audit_log_id, scope)
    )


def list_agent_audit_logs(
    db: Session,
    owner_id: UUID,
    agent_identifier: str,
    filters: AuditLogFilters,
    organization_id: UUID | None = None,
) -> tuple[list[AuditLog], int, int]:
    agent = db.scalar(
        select(Agent).where(
            Agent.agent_identifier == agent_identifier,
            Agent.organization_id == organization_id if organization_id is not None else (
                (Agent.owner_id == owner_id) & Agent.organization_id.is_(None)
            ),
        )
    )
    if agent is None:
        raise AgentNotFound
    agent_filters = filters.model_copy(update={"agent_id": agent_identifier})
    return list_audit_logs(db, owner_id, agent_filters, organization_id)
