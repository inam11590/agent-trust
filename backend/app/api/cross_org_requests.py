"""REST API endpoints for Cross-Organization Authorizations and multi-party approvals."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser
from app.core.config import Settings
from app.database.session import get_db
from app.models.cross_organization_trust import (
    CrossOrgRequestStatus,
    CrossOrganizationApproval,
    CrossOrganizationRequest,
)
from app.schemas.cross_organization_trust import (
    CrossOrgApprovalResponse,
    CrossOrgAuthorizePayload,
    CrossOrgAuthorizeResponse,
    CrossOrgDecisionPayload,
    CrossOrgRequestDetailResponse,
)
from app.services.api_keys import DeveloperPrincipal, authenticate_api_key
from app.services.cross_org_authorization import (
    authorize_cross_organization_action,
    decide_cross_org_approval,
)
from app.services.organization_context import CurrentWorkspace

router = APIRouter(tags=["cross-org-authorization"])


def _populate_detail(req: CrossOrganizationRequest) -> CrossOrgRequestDetailResponse:
    resp = CrossOrgRequestDetailResponse.model_validate(req)
    if req.source_organization:
        resp.source_organization_name = req.source_organization.name
    if req.target_organization:
        resp.target_organization_name = req.target_organization.name
    if req.source_agent:
        resp.source_agent_identifier = req.source_agent.agent_identifier
        resp.source_agent_name = req.source_agent.name
    if req.target_agent:
        resp.target_agent_identifier = req.target_agent.agent_identifier
        resp.target_agent_name = req.target_agent.name
    resp.approvals = [CrossOrgApprovalResponse.model_validate(a) for a in req.approvals]
    return resp


@router.post("/api/v1/cross-org/authorize", response_model=CrossOrgAuthorizeResponse)
async def cross_org_authorize(
    request: Request,
    payload: CrossOrgAuthorizePayload,
    db: Session = Depends(get_db),
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> CrossOrgAuthorizeResponse:
    """Authorize a signed cross-organization action from a source agent to a target agent."""
    raw_body = await request.body()
    redis_client = getattr(request.app.state, "redis", None)
    settings = request.app.state.settings

    # Allow authorization via Developer API Key or Signed Headers
    caller_org_id = None
    api_key_header = request.headers.get("x-api-key")
    if api_key_header:
        principal = authenticate_api_key(db, api_key_header)
        if principal.api_key.organization_id:
            caller_org_id = principal.api_key.organization_id

    result = authorize_cross_organization_action(
        db,
        settings,
        redis_client,
        payload=payload,
        headers=request.headers,
        raw_body=raw_body,
        caller_org_id=caller_org_id,
        idempotency_key=idempotency_key,
    )
    return result


@router.get("/v1/cross-org/requests", response_model=list[CrossOrgRequestDetailResponse])
def list_requests(
    workspace: CurrentWorkspace,
    direction: Annotated[str, Query(pattern=r"^(inbound|outbound|all)$")] = "all",
    status_filter: Annotated[CrossOrgRequestStatus | None, Query(alias="status")] = None,
    db: Session = Depends(get_db),
) -> list[CrossOrgRequestDetailResponse]:
    """List cross-organization requests for the current organization."""
    if not workspace.organization_id:
        raise HTTPException(status_code=400, detail="Organization context required")
    workspace.require("read")

    stmt = select(CrossOrganizationRequest)
    if direction == "inbound":
        stmt = stmt.where(CrossOrganizationRequest.target_organization_id == workspace.organization_id)
    elif direction == "outbound":
        stmt = stmt.where(CrossOrganizationRequest.source_organization_id == workspace.organization_id)
    else:
        stmt = stmt.where(
            or_(
                CrossOrganizationRequest.source_organization_id == workspace.organization_id,
                CrossOrganizationRequest.target_organization_id == workspace.organization_id,
            )
        )

    if status_filter:
        stmt = stmt.where(CrossOrganizationRequest.status == status_filter)

    stmt = stmt.order_by(CrossOrganizationRequest.created_at.desc()).limit(100)
    requests = list(db.scalars(stmt).all())
    return [_populate_detail(r) for r in requests]


@router.get("/v1/cross-org/requests/{request_id}", response_model=CrossOrgRequestDetailResponse)
def get_request_detail(
    request_id: str,
    workspace: CurrentWorkspace,
    db: Session = Depends(get_db),
) -> CrossOrgRequestDetailResponse:
    """Get detail of a cross-organization request."""
    if not workspace.organization_id:
        raise HTTPException(status_code=400, detail="Organization context required")
    workspace.require("read")

    req = db.scalar(
        select(CrossOrganizationRequest).where(CrossOrganizationRequest.request_id == request_id)
    )
    if not req:
        raise HTTPException(status_code=404, detail="Cross-organization request not found")

    if req.source_organization_id != workspace.organization_id and req.target_organization_id != workspace.organization_id:
        raise HTTPException(status_code=404, detail="Cross-organization request not found")

    return _populate_detail(req)


@router.post("/v1/cross-org/requests/{request_id}/approve", response_model=CrossOrgRequestDetailResponse)
def approve_request(
    request_id: str,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    payload: CrossOrgDecisionPayload | None = None,
    db: Session = Depends(get_db),
) -> CrossOrgRequestDetailResponse:
    """Approve a pending multi-party cross-organization request."""
    if not workspace.organization_id:
        raise HTTPException(status_code=400, detail="Organization context required")
    workspace.require("manage_permissions")

    reason = payload.reason if payload else None
    req = decide_cross_org_approval(
        db,
        request_id=request_id,
        user_id=user.id,
        caller_org_id=workspace.organization_id,
        decision="APPROVED",
        reason=reason,
    )
    return _populate_detail(req)


@router.post("/v1/cross-org/requests/{request_id}/reject", response_model=CrossOrgRequestDetailResponse)
def reject_request(
    request_id: str,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    payload: CrossOrgDecisionPayload | None = None,
    db: Session = Depends(get_db),
) -> CrossOrgRequestDetailResponse:
    """Reject a pending cross-organization request."""
    if not workspace.organization_id:
        raise HTTPException(status_code=400, detail="Organization context required")
    workspace.require("manage_permissions")

    reason = payload.reason if payload else None
    req = decide_cross_org_approval(
        db,
        request_id=request_id,
        user_id=user.id,
        caller_org_id=workspace.organization_id,
        decision="REJECTED",
        reason=reason,
    )
    return _populate_detail(req)
