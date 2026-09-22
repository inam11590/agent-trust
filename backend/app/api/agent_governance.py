"""Enterprise Agent Lifecycle Governance API routes (Step 28)."""

from typing import Annotated, Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.models.agent import Agent
from app.models.agent_governance import (
    AgentCertification,
    AgentGovernancePolicy,
    CertificationStatus,
    ExpiryBehavior,
)
from app.schemas.agent_governance import (
    AgentCertificationResponse,
    BulkGovernanceRequest,
    CreateCertificationRequest,
    DecideCertificationRequest,
    GovernancePolicyResponse,
    ImportInventoryRequest,
    UpdateGovernancePolicyRequest,
)
from app.services.agent_governance import (
    check_and_apply_certification_expiries,
    complete_certification_review,
    create_certification_review,
    detect_orphaned_agents,
    evaluate_governance_signals,
    execute_bulk_governance,
    export_agent_inventory,
    get_executive_governance_kpis,
    import_agent_inventory,
)
from app.services.agent_lifecycle import get_governance_policy
from app.services.organization_context import CurrentWorkspace

router = APIRouter(prefix="/governance", tags=["governance"])


@router.get("/dashboard")
def get_dashboard_kpis(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Get high-level executive KPIs and posture overview for the organization."""
    workspace.require("read")
    return get_executive_governance_kpis(db, workspace.organization_id)


@router.get("/signals")
def get_signals(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
    agent_id: Optional[UUID] = None,
) -> List[Dict[str, Any]]:
    """Retrieve active governance alerts and signals (dormant, overdue, broad permissions)."""
    workspace.require("read")
    return evaluate_governance_signals(db, workspace.organization_id, agent_id=agent_id)


@router.get("/orphaned")
def get_orphaned(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> List[Dict[str, Any]]:
    """Identify orphaned agents whose owner is missing or inactive."""
    workspace.require("read")
    return detect_orphaned_agents(db, workspace.organization_id)


@router.get("/certifications", response_model=List[AgentCertificationResponse])
def list_certifications(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
    status: Optional[str] = Query(None, description="Filter by status: PENDING, APPROVED, REJECTED, EXPIRED"),
    agent_id: Optional[UUID] = None,
) -> List[AgentCertificationResponse]:
    """List agent access certification reviews."""
    workspace.require("read")
    query = select(AgentCertification)
    if workspace.organization_id:
        query = query.where(AgentCertification.organization_id == workspace.organization_id)
    if status:
        query = query.where(AgentCertification.status == status.upper())
    if agent_id:
        query = query.where(AgentCertification.agent_id == agent_id)

    certs = db.scalars(query.order_by(AgentCertification.created_at.desc())).all()
    return [AgentCertificationResponse.model_validate(c) for c in certs]


@router.post("/certifications", response_model=AgentCertificationResponse, status_code=201)
def request_certification(
    payload: CreateCertificationRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> AgentCertificationResponse:
    """Initiate a formal access posture review for an agent."""
    workspace.require("manage_agents")
    if not payload.agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required")

    agent = db.scalar(select(Agent).where(Agent.id == payload.agent_id))
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if workspace.organization_id and agent.organization_id != workspace.organization_id:
        raise HTTPException(status_code=403, detail="Agent does not belong to current organization")

    cert = create_certification_review(
        db, agent, reviewer_id=payload.reviewer_id or user.id, due_days=payload.due_days, notes=payload.notes
    )
    return AgentCertificationResponse.model_validate(cert)


@router.post("/certifications/{certification_id}/decide", response_model=AgentCertificationResponse)
def decide_certification(
    certification_id: str,
    payload: DecideCertificationRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> AgentCertificationResponse:
    """Submit approval or rejection decision for an agent certification review."""
    workspace.require("manage_agents")
    cert = db.scalar(select(AgentCertification).where(AgentCertification.certification_id == certification_id))
    if not cert:
        raise HTTPException(status_code=404, detail="Certification review not found")
    if workspace.organization_id and cert.organization_id != workspace.organization_id:
        raise HTTPException(status_code=403, detail="Certification review belongs to different organization")

    # Separation of duties check if user is the agent owner
    policy = get_governance_policy(db, workspace.organization_id)
    agent = db.scalar(select(Agent).where(Agent.id == cert.agent_id))
    if policy.enforce_separation_of_duties and agent and agent.owner_id == user.id:
        raise HTTPException(
            status_code=403,
            detail="Separation of duties: Agent owner cannot approve their own agent's certification review.",
        )

    updated_cert = complete_certification_review(
        db, cert, decision=payload.decision, reviewer_id=user.id, notes=payload.notes
    )
    return AgentCertificationResponse.model_validate(updated_cert)


@router.post("/certifications/evaluate-expiries")
def trigger_expiry_evaluations(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Manually trigger background expiration checks against certified agents."""
    workspace.require("manage_agents")
    results = check_and_apply_certification_expiries(db, workspace.organization_id)
    return {"status": "completed", "expired_actions": results}


@router.post("/bulk")
def execute_bulk(
    payload: BulkGovernanceRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Execute bulk governance operation across multiple agents."""
    workspace.require("manage_agents")
    return execute_bulk_governance(
        db,
        organization_id=workspace.organization_id,
        action=payload.action,
        agent_ids=payload.agent_ids,
        params=payload.params,
        acting_user_id=user.id,
    )


@router.post("/import")
def import_inventory(
    payload: ImportInventoryRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Import agent records into authoritative inventory."""
    workspace.require("manage_agents")
    return import_agent_inventory(
        db,
        organization_id=workspace.organization_id,
        records=payload.records,
        default_owner_id=user.id,
        source=payload.source,
    )


@router.get("/export")
def export_inventory(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
    format: str = Query("json", description="json or csv"),
) -> Response:
    """Export authoritative agent inventory in JSON or CSV format."""
    workspace.require("read")
    content = export_agent_inventory(db, workspace.organization_id, format=format)
    if format.lower() == "csv":
        return PlainTextResponse(content, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=agents.csv"})
    return PlainTextResponse(content, media_type="application/json")


@router.get("/policy", response_model=GovernancePolicyResponse)
def get_policy(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> GovernancePolicyResponse:
    """Get organization agent governance policy."""
    workspace.require("read")
    policy = get_governance_policy(db, workspace.organization_id)
    return GovernancePolicyResponse(
        organization_id=policy.organization_id,
        periodic_review_days=policy.periodic_review_days,
        expiry_behavior=policy.expiry_behavior.value if hasattr(policy.expiry_behavior, "value") else str(policy.expiry_behavior),
        dormancy_days=policy.dormancy_days,
        enforce_separation_of_duties=policy.enforce_separation_of_duties,
        require_classification_on_promotion=policy.require_classification_on_promotion,
        require_purpose_on_promotion=policy.require_purpose_on_promotion,
    )


@router.put("/policy", response_model=GovernancePolicyResponse)
def update_policy(
    payload: UpdateGovernancePolicyRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> GovernancePolicyResponse:
    """Update organization agent governance policy."""
    workspace.require("admin")
    policy = get_governance_policy(db, workspace.organization_id)

    if payload.periodic_review_days is not None:
        policy.periodic_review_days = payload.periodic_review_days
    if payload.expiry_behavior is not None:
        policy.expiry_behavior = ExpiryBehavior(payload.expiry_behavior.upper())
    if payload.dormancy_days is not None:
        policy.dormancy_days = payload.dormancy_days
    if payload.enforce_separation_of_duties is not None:
        policy.enforce_separation_of_duties = payload.enforce_separation_of_duties
    if payload.require_classification_on_promotion is not None:
        policy.require_classification_on_promotion = payload.require_classification_on_promotion
    if payload.require_purpose_on_promotion is not None:
        policy.require_purpose_on_promotion = payload.require_purpose_on_promotion

    db.commit()
    db.refresh(policy)
    return GovernancePolicyResponse(
        organization_id=policy.organization_id,
        periodic_review_days=policy.periodic_review_days,
        expiry_behavior=policy.expiry_behavior.value if hasattr(policy.expiry_behavior, "value") else str(policy.expiry_behavior),
        dormancy_days=policy.dormancy_days,
        enforce_separation_of_duties=policy.enforce_separation_of_duties,
        require_classification_on_promotion=policy.require_classification_on_promotion,
        require_purpose_on_promotion=policy.require_purpose_on_promotion,
    )
