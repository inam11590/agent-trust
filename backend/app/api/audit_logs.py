"""Secure, read-only audit log endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.models.audit_log import AuditDecision, AuditLog
from app.schemas.audit_log import AuditDateTime, AuditLogFilters, AuditLogResponse, PaginatedAuditLogs
from app.services.audit_logs import AgentNotFound, get_owned_audit_log, list_agent_audit_logs, list_audit_logs
from app.services.organization_context import CurrentWorkspace

router = APIRouter(tags=["audit logs"])


def get_filters(
    decision: Annotated[AuditDecision | None, Query()] = None,
    agent_id: Annotated[str | None, Query(min_length=1, max_length=255, pattern=r"^agt_[0-9a-f]{24}$")] = None,
    action: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    resource: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    start_date: Annotated[AuditDateTime | None, Query()] = None,
    end_date: Annotated[AuditDateTime | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> AuditLogFilters:
    return AuditLogFilters(
        decision=decision,
        agent_id=agent_id,
        action=action,
        resource=resource,
        start_date=start_date,
        end_date=end_date,
        page=page,
        page_size=page_size,
    )


def paginated_response(
    items: list[AuditLog],
    filters: AuditLogFilters,
    total: int,
    total_pages: int,
) -> PaginatedAuditLogs:
    return PaginatedAuditLogs(
        items=[AuditLogResponse.model_validate(item) for item in items],
        page=filters.page,
        page_size=filters.page_size,
        total=total,
        total_pages=total_pages,
    )


@router.get("/audit-logs", response_model=PaginatedAuditLogs)
def get_audit_logs(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    filters: Annotated[AuditLogFilters, Depends(get_filters)],
    db: Annotated[Session, Depends(get_db)],
) -> PaginatedAuditLogs:
    workspace.require("read_audit")
    items, total, total_pages = list_audit_logs(db, user.id, filters, workspace.organization_id)
    response.headers["Cache-Control"] = "no-store"
    return paginated_response(items, filters, total, total_pages)


@router.get("/audit-logs/{audit_log_id}", response_model=AuditLogResponse)
def get_audit_log(
    audit_log_id: UUID,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> AuditLogResponse:
    workspace.require("read_audit")
    audit_log = get_owned_audit_log(db, user.id, audit_log_id, workspace.organization_id)
    if audit_log is None:
        raise HTTPException(status_code=404, detail="Audit log not found")
    response.headers["Cache-Control"] = "no-store"
    return AuditLogResponse.model_validate(audit_log)


@router.get("/agents/{agent_identifier}/audit-logs", response_model=PaginatedAuditLogs)
def get_agent_audit_logs(
    agent_identifier: str,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    filters: Annotated[AuditLogFilters, Depends(get_filters)],
    db: Annotated[Session, Depends(get_db)],
) -> PaginatedAuditLogs:
    try:
        items, total, total_pages = list_agent_audit_logs(
            db, user.id, agent_identifier, filters, workspace.organization_id,
        )
    except AgentNotFound:
        raise HTTPException(status_code=404, detail="Agent not found") from None
    response.headers["Cache-Control"] = "no-store"
    return paginated_response(items, filters, total, total_pages)
