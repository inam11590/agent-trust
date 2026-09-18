"""Secure APIs for viewing and deciding manual authorization requests."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.models import AuthorizationRequestRecord, AuthorizationRequestStatus, RiskAssessment
from sqlalchemy import select
from app.schemas.authorization_request import (
    AuthorizationRequestFilters,
    AuthorizationRequestResponse,
    PaginatedAuthorizationRequests,
)
from app.services.authorization_requests import (
    RequestAlreadyDecided,
    RequestExpired,
    RequestNotFound,
    decide_owned_request,
    get_owned_request,
    list_owned_requests,
)
from app.services.webhooks import deliver_authorization_webhook
from app.services.organization_context import CurrentWorkspace, WorkspaceContext

router = APIRouter(prefix="/authorization-requests", tags=["authorization requests"])


def _response(record: AuthorizationRequestRecord, db: Session) -> AuthorizationRequestResponse:
    assessment = db.scalar(select(RiskAssessment).where(RiskAssessment.request_id == record.request_id))
    return AuthorizationRequestResponse(
        id=record.id,
        request_id=record.request_id,
        user_id=record.user_id,
        agent_id=record.agent_id,
        agent_identifier=record.agent.agent_identifier,
        agent_name=record.agent.name,
        permission_id=record.permission_id,
        action=record.action,
        resource=record.resource,
        amount=record.amount,
        currency=record.currency,
        status=record.status,
        reason=record.reason,
        policy_reason=record.policy_reason,
        created_at=record.created_at,
        expires_at=record.expires_at,
        decided_at=record.decided_at,
        risk_score=record.risk_score,
        risk_level=record.risk_level,
        risk_recommendation=record.risk_recommendation,
        risk_reasons=list(assessment.reasons) if assessment else [],
    )


def _filters(
    status: Annotated[AuthorizationRequestStatus | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> AuthorizationRequestFilters:
    return AuthorizationRequestFilters(status=status, page=page, page_size=page_size)


@router.get("", response_model=PaginatedAuthorizationRequests)
def get_requests(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    filters: Annotated[AuthorizationRequestFilters, Depends(_filters)],
    db: Annotated[Session, Depends(get_db)],
) -> PaginatedAuthorizationRequests:
    workspace.require("read")
    items, total, total_pages = list_owned_requests(db, user.id, filters, workspace.organization_id)
    response.headers["Cache-Control"] = "no-store"
    return PaginatedAuthorizationRequests(
        items=[_response(item, db) for item in items],
        page=filters.page,
        page_size=filters.page_size,
        total=total,
        total_pages=total_pages,
    )


@router.get("/{request_id}", response_model=AuthorizationRequestResponse)
def get_request(
    request_id: UUID,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> AuthorizationRequestResponse:
    workspace.require("read")
    record = get_owned_request(db, user.id, request_id, workspace.organization_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Authorization request not found")
    response.headers["Cache-Control"] = "no-store"
    return _response(record, db)


def _decide(
    request_id: UUID,
    user: CurrentUser,
    response: Response,
    db: Session,
    approve: bool,
    settings,
    workspace: WorkspaceContext,
) -> AuthorizationRequestResponse:
    workspace.require("decide_requests")
    try:
        record = decide_owned_request(
            db, user.id, request_id, approve, organization_id=workspace.organization_id,
        )
    except RequestNotFound:
        raise HTTPException(status_code=404, detail="Authorization request not found") from None
    except RequestExpired:
        raise HTTPException(status_code=409, detail="Authorization request has expired") from None
    except RequestAlreadyDecided:
        raise HTTPException(status_code=409, detail="Authorization request has already been decided") from None
    response.headers["Cache-Control"] = "no-store"
    deliver_authorization_webhook(db, record, settings)
    return _response(record, db)


@router.post("/{request_id}/approve", response_model=AuthorizationRequestResponse)
def approve_request(
    request_id: UUID,
    user: CurrentUser,
    response: Response,
    request: Request,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> AuthorizationRequestResponse:
    return _decide(request_id, user, response, db, True, request.app.state.settings, workspace)


@router.post("/{request_id}/reject", response_model=AuthorizationRequestResponse)
def reject_request(
    request_id: UUID,
    user: CurrentUser,
    response: Response,
    request: Request,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> AuthorizationRequestResponse:
    return _decide(request_id, user, response, db, False, request.app.state.settings, workspace)
