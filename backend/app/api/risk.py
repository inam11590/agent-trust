"""Private workspace risk history and policy endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.models import RiskLevel
from app.schemas.risk import (
    PaginatedRiskAssessments, RiskAssessmentResponse, RiskFilters,
    RiskOverview, RiskPolicyResponse, RiskPolicyUpdate,
)
from app.services.organization_context import CurrentWorkspace
from app.services.risk_assessments import get_assessment, list_assessments, overview, update_policy
from app.services.risk_engine import get_or_create_policy
from app.services.security_events import record_security_event

router = APIRouter(prefix="/risk", tags=["risk"])


def _filters(
    level: Annotated[RiskLevel | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> RiskFilters:
    return RiskFilters(level=level, page=page, page_size=page_size)


@router.get("/overview", response_model=RiskOverview)
def risk_overview(user: CurrentUser, workspace: CurrentWorkspace, response: Response,
                  db: Annotated[Session, Depends(get_db)]) -> RiskOverview:
    workspace.require("read_audit")
    counts = overview(db, user.id, workspace.organization_id)
    response.headers["Cache-Control"] = "no-store"
    return RiskOverview(low=counts[RiskLevel.LOW], medium=counts[RiskLevel.MEDIUM],
                        high=counts[RiskLevel.HIGH], critical=counts[RiskLevel.CRITICAL])


@router.get("/assessments", response_model=PaginatedRiskAssessments)
def risk_assessments(user: CurrentUser, workspace: CurrentWorkspace, response: Response,
                     filters: Annotated[RiskFilters, Depends(_filters)],
                     db: Annotated[Session, Depends(get_db)]) -> PaginatedRiskAssessments:
    workspace.require("read_audit")
    items, total, pages = list_assessments(db, user.id, workspace.organization_id, filters)
    response.headers["Cache-Control"] = "no-store"
    return PaginatedRiskAssessments(items=items, page=filters.page, page_size=filters.page_size,
                                    total=total, total_pages=pages)


@router.get("/assessments/{assessment_id}", response_model=RiskAssessmentResponse)
def risk_assessment(assessment_id: UUID, user: CurrentUser, workspace: CurrentWorkspace,
                    response: Response, db: Annotated[Session, Depends(get_db)]) -> RiskAssessmentResponse:
    workspace.require("read_audit")
    item = get_assessment(db, user.id, workspace.organization_id, assessment_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Risk assessment not found")
    response.headers["Cache-Control"] = "no-store"
    return item


@router.get("/policy", response_model=RiskPolicyResponse)
def risk_policy(user: CurrentUser, workspace: CurrentWorkspace, response: Response,
                db: Annotated[Session, Depends(get_db)]) -> RiskPolicyResponse:
    workspace.require("read")
    policy = get_or_create_policy(db, user.id, workspace.organization_id)
    db.commit()
    db.refresh(policy)
    response.headers["Cache-Control"] = "no-store"
    return RiskPolicyResponse.model_validate(policy)


@router.patch("/policy", response_model=RiskPolicyResponse)
def change_risk_policy(payload: RiskPolicyUpdate, user: CurrentUser, workspace: CurrentWorkspace,
                       response: Response, db: Annotated[Session, Depends(get_db)]) -> RiskPolicyResponse:
    workspace.require("manage_risk_policy")
    policy = update_policy(db, user.id, workspace.organization_id, payload)
    record_security_event(
        db, user.id, "risk_policy.updated", organization_id=workspace.organization_id,
        description=f"Risk policy: {policy.id}",
    )
    response.headers["Cache-Control"] = "no-store"
    return RiskPolicyResponse.model_validate(policy)
