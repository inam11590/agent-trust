"""Agent Discovery API routes (Step 29).

Enforces:
- Tenant isolation across all queries
- RBAC capability checks (discovery.read, discovery.sources.manage, discovery.scan, discovery.onboard, etc.)
- Strict privacy: never returns connector secrets, raw prompts, model responses, or customer documents
- Bounded pagination
"""

from typing import Annotated, Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import PlainTextResponse
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.models.discovery import (
    DiscoveryCandidate,
    DiscoveryEvidence,
    DiscoveryRun,
    DiscoverySource,
)
from app.schemas.agent import AgentResponse
from app.schemas.discovery import (
    DiscoveryCandidateResponse,
    DiscoveryDashboardResponse,
    DiscoveryEvidenceResponse,
    DiscoveryRunResponse,
    DiscoverySourceCreate,
    DiscoverySourceResponse,
    FalsePositiveCandidateRequest,
    IgnoreCandidateRequest,
    MatchCandidateRequest,
    OnboardCandidateRequest,
)
from app.services.discovery.engine import (
    create_discovery_source,
    execute_discovery_run,
    export_discovery_candidates,
    get_discovery_dashboard_metrics,
    get_discovery_governance_signals,
    ignore_candidate,
    mark_candidate_false_positive,
    match_candidate_to_agent,
    onboard_candidate_to_inventory,
)
from app.services.organization_context import CurrentWorkspace

router = APIRouter(prefix="/discovery", tags=["discovery"])


@router.get("/dashboard", response_model=DiscoveryDashboardResponse)
def get_dashboard_summary(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> DiscoveryDashboardResponse:
    """Get high-level discovery metrics and review queue counts."""
    workspace.require("discovery.read")
    return get_discovery_dashboard_metrics(db, workspace.organization_id)


@router.get("/signals")
def get_discovery_signals(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> List[Dict[str, Any]]:
    """Retrieve governance signals related to unmanaged agents and shadow AI."""
    workspace.require("discovery.read")
    return get_discovery_governance_signals(db, workspace.organization_id)


# ---------------------------------------------------------------------------
# Discovery Sources
# ---------------------------------------------------------------------------

@router.get("/sources", response_model=List[DiscoverySourceResponse])
def list_discovery_sources(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> List[DiscoverySource]:
    """List configured discovery sources for the organization."""
    workspace.require("discovery.sources.read")
    sources = db.scalars(
        select(DiscoverySource)
        .where(DiscoverySource.organization_id == workspace.organization_id)
        .order_by(DiscoverySource.created_at.desc())
    ).all()
    return sources


@router.post("/sources", response_model=DiscoverySourceResponse, status_code=201)
def create_source(
    payload: DiscoverySourceCreate,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> DiscoverySource:
    """Create a new discovery source connector."""
    workspace.require("discovery.sources.manage")
    return create_discovery_source(
        db=db,
        organization_id=workspace.organization_id,
        name=payload.name,
        source_type=payload.source_type,
        configuration=payload.configuration,
        credential_reference=payload.credential_reference,
        created_by=user.id,
    )


@router.get("/sources/{source_id}", response_model=DiscoverySourceResponse)
def get_source_details(
    source_id: str,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> DiscoverySource:
    """Get details of a specific discovery source."""
    workspace.require("discovery.sources.read")
    source = db.scalar(
        select(DiscoverySource).where(
            DiscoverySource.organization_id == workspace.organization_id,
            or_(DiscoverySource.source_id == source_id, DiscoverySource.id == source_id),
        )
    )
    if not source:
        raise HTTPException(status_code=404, detail="DiscoverySource not found.")
    return source


@router.post("/sources/{source_id}/scan", response_model=DiscoveryRunResponse)
def trigger_manual_scan(
    source_id: str,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> DiscoveryRun:
    """Trigger a manual discovery scan against a source."""
    workspace.require("discovery.scan")
    source = db.scalar(
        select(DiscoverySource).where(
            DiscoverySource.organization_id == workspace.organization_id,
            or_(DiscoverySource.source_id == source_id, DiscoverySource.id == source_id),
        )
    )
    if not source:
        raise HTTPException(status_code=404, detail="DiscoverySource not found.")

    return execute_discovery_run(db=db, source_id=source.id, trigger_type="MANUAL")


# ---------------------------------------------------------------------------
# Discovery Runs
# ---------------------------------------------------------------------------

@router.get("/runs", response_model=List[DiscoveryRunResponse])
def list_discovery_runs(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
    source_id: Optional[str] = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> List[DiscoveryRun]:
    """List discovery runs with bounded pagination."""
    workspace.require("discovery.read")
    query = select(DiscoveryRun).where(DiscoveryRun.organization_id == workspace.organization_id)
    if source_id:
        query = query.join(DiscoverySource).where(
            or_(DiscoverySource.source_id == source_id, DiscoverySource.id == source_id)
        )
    query = query.order_by(DiscoveryRun.started_at.desc()).offset(offset).limit(limit)
    return db.scalars(query).all()


# ---------------------------------------------------------------------------
# Discovery Candidates
# ---------------------------------------------------------------------------

@router.get("/candidates", response_model=List[DiscoveryCandidateResponse])
def list_candidates(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
    status: Optional[str] = None,
    environment: Optional[str] = None,
    confidence_level: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> List[DiscoveryCandidate]:
    """List discovery candidates with filters and bounded pagination."""
    workspace.require("discovery.read")
    query = select(DiscoveryCandidate).where(
        DiscoveryCandidate.organization_id == workspace.organization_id
    )
    if status:
        query = query.where(DiscoveryCandidate.status == status.upper())
    if environment:
        query = query.where(DiscoveryCandidate.environment == environment.lower())
    if confidence_level:
        query = query.where(DiscoveryCandidate.confidence_level == confidence_level.upper())
    if search:
        pattern = f"%{search.strip()}%"
        query = query.where(
            or_(
                DiscoveryCandidate.display_name.ilike(pattern),
                DiscoveryCandidate.external_resource_reference.ilike(pattern),
                DiscoveryCandidate.location_reference.ilike(pattern),
            )
        )

    query = query.order_by(DiscoveryCandidate.last_seen_at.desc()).offset(offset).limit(limit)
    return db.scalars(query).all()


@router.get("/candidates/{candidate_id}", response_model=DiscoveryCandidateResponse)
def get_candidate_details(
    candidate_id: str,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> DiscoveryCandidate:
    """Get full details of a specific discovery candidate."""
    workspace.require("discovery.read")
    cand = db.scalar(
        select(DiscoveryCandidate).where(
            DiscoveryCandidate.organization_id == workspace.organization_id,
            or_(DiscoveryCandidate.candidate_id == candidate_id, DiscoveryCandidate.id == candidate_id),
        )
    )
    if not cand:
        raise HTTPException(status_code=404, detail="DiscoveryCandidate not found.")
    return cand


@router.get("/candidates/{candidate_id}/evidence", response_model=List[DiscoveryEvidenceResponse])
def list_candidate_evidence(
    candidate_id: str,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> List[DiscoveryEvidence]:
    """List all evidence items observed for a discovery candidate."""
    workspace.require("discovery.read")
    cand = db.scalar(
        select(DiscoveryCandidate).where(
            DiscoveryCandidate.organization_id == workspace.organization_id,
            or_(DiscoveryCandidate.candidate_id == candidate_id, DiscoveryCandidate.id == candidate_id),
        )
    )
    if not cand:
        raise HTTPException(status_code=404, detail="DiscoveryCandidate not found.")

    evidence = db.scalars(
        select(DiscoveryEvidence)
        .where(DiscoveryEvidence.candidate_id == cand.id)
        .order_by(DiscoveryEvidence.observed_at.desc())
    ).all()
    return evidence


@router.post("/candidates/{candidate_id}/match", response_model=DiscoveryCandidateResponse)
def match_candidate(
    candidate_id: str,
    payload: MatchCandidateRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> DiscoveryCandidate:
    """Manually link candidate to an existing registered Agent."""
    workspace.require("discovery.match")
    try:
        return match_candidate_to_agent(
            db=db,
            candidate_id=candidate_id,
            agent_id=payload.agent_id,
            user_id=user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/candidates/{candidate_id}/onboard", response_model=AgentResponse, status_code=201)
def onboard_candidate(
    candidate_id: str,
    payload: OnboardCandidateRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> Any:
    """Safe onboarding of candidate into Step 28 lifecycle (REGISTERED / DRAFT)."""
    workspace.require("discovery.onboard")
    try:
        agent = onboard_candidate_to_inventory(
            db=db,
            candidate_id=candidate_id,
            owner_id=payload.owner_id,
            owner_type=payload.owner_type,
            purpose=payload.purpose,
            risk_classification=payload.risk_classification,
            team=payload.team,
            business_function=payload.business_function,
            user_id=user.id,
        )
        return agent
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/candidates/{candidate_id}/ignore", response_model=DiscoveryCandidateResponse)
def ignore_review_candidate(
    candidate_id: str,
    payload: IgnoreCandidateRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> DiscoveryCandidate:
    """Suppress candidate from review queue for a configured duration."""
    workspace.require("discovery.ignore")
    try:
        return ignore_candidate(
            db=db,
            candidate_id=candidate_id,
            reason=payload.reason,
            days=payload.days,
            user_id=user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/candidates/{candidate_id}/false-positive", response_model=DiscoveryCandidateResponse)
def mark_false_positive(
    candidate_id: str,
    payload: FalsePositiveCandidateRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> DiscoveryCandidate:
    """Record that candidate is not an AI agent."""
    workspace.require("discovery.review")
    try:
        return mark_candidate_false_positive(
            db=db,
            candidate_id=candidate_id,
            reason=payload.reason,
            user_id=user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/export")
def export_candidates(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
    format: str = Query("json", pattern="^(json|csv)$"),
) -> Response:
    """Sanitized export of discovery candidates (CSV or JSON). Excludes secrets and prompts."""
    workspace.require("discovery.export")
    exported = export_discovery_candidates(db, workspace.organization_id, format=format)
    media_type = "text/csv" if format == "csv" else "application/json"
    filename = f"agent_discovery_export_{workspace.organization_id}.{format}"
    return Response(
        content=exported,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
