"""Agent Service Registry and Trusted Communication API routes (Step 30).

Implements:
- Service Registry lifecycle (CRUD, status, visibility)
- Capability catalog management
- Endpoint registration, cryptographic challenge initiation, and verification
- Trusted zero-trust resolution (with zero-trust discovery advisory)
- Loop-protected, depth-bounded agent-to-agent capability call execution
"""

from __future__ import annotations

from typing import Annotated, Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.models.agent_service import AgentCallRecord, AgentService, AgentServiceEndpoint
from app.models.agenttrust_protocol import AgentCapability
from app.schemas.agent_services import (
    AgentCallRecordSummary,
    AgentCallRequest,
    AgentCallResponse,
    CapabilityListResponse,
    CapabilityRegisterRequest,
    CapabilityResponse,
    ChallengeInitiateResponse,
    EndpointCreateRequest,
    EndpointResponse,
    EndpointVerifyRequest,
    EndpointVerifyResponse,
    ServiceCreate,
    ServiceListResponse,
    ServiceResolveRequest,
    ServiceResolveResponse,
    ServiceResponse,
    ServiceUpdate,
)
from app.services.agent_call_pipeline import AgentCallPipelineError, execute_agent_to_agent_call
from app.services.agent_service_registry import (
    ServiceRegistryError,
    create_service,
    delete_service,
    get_capability,
    get_service,
    initiate_endpoint_verification,
    list_capabilities,
    list_endpoints,
    list_services,
    register_capability,
    register_endpoint,
    update_service,
    verify_endpoint_challenge,
)
from app.services.agent_service_router import ResolutionError, resolve_capability, resolve_service
from app.services.organization_context import CurrentWorkspace

router = APIRouter(tags=["Agent Services & Communication"])


# --------------------------------------------------------------------------
# 1. Services Management
# --------------------------------------------------------------------------

@router.post("/services", response_model=ServiceResponse, status_code=status.HTTP_201_CREATED)
def create_new_service(
    payload: ServiceCreate,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> ServiceResponse:
    """Create a new service in the registry bound to an active Agent."""
    workspace.require("services.manage")
    org_id = workspace.organization_id
    if not org_id:
        raise HTTPException(status_code=400, detail="Personal workspace cannot own organization services.")

    try:
        service = create_service(
            db,
            organization_id=org_id,
            agent_id=payload.agent_id,
            name=payload.name,
            description=payload.description,
            version=payload.version,
            status=payload.status,
            visibility=payload.visibility,
            environment=payload.environment,
            metadata_json=payload.metadata_json,
        )
        return _format_service_response(db, service)
    except ServiceRegistryError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"error": exc.code, "message": exc.message}) from exc


@router.get("/services", response_model=ServiceListResponse)
def get_services(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
    agent_id: Optional[UUID] = None,
    status: Optional[str] = None,
    visibility: Optional[str] = None,
    environment: Optional[str] = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> ServiceListResponse:
    """List services accessible to the caller's organization."""
    workspace.require("services.read")
    items, total = list_services(
        db,
        organization_id=workspace.organization_id,
        agent_id=agent_id,
        status=status,
        visibility=visibility,
        environment=environment,
        limit=limit,
        offset=offset,
    )
    formatted = [_format_service_response(db, s) for s in items]
    return ServiceListResponse(items=formatted, total=total)


@router.get("/services/{service_id}", response_model=ServiceResponse)
def get_service_details(
    service_id: str,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> ServiceResponse:
    """Retrieve service details by ID."""
    workspace.require("services.read")
    try:
        service = get_service(db, service_id, workspace.organization_id)
        return _format_service_response(db, service)
    except ServiceRegistryError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"error": exc.code, "message": exc.message}) from exc


@router.patch("/services/{service_id}", response_model=ServiceResponse)
def update_service_details(
    service_id: str,
    payload: ServiceUpdate,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> ServiceResponse:
    """Update service metadata and status."""
    workspace.require("services.manage")
    try:
        service = update_service(
            db,
            service_id_or_uuid=service_id,
            updates=payload.model_dump(exclude_unset=True),
            organization_id=workspace.organization_id,
        )
        return _format_service_response(db, service)
    except ServiceRegistryError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"error": exc.code, "message": exc.message}) from exc


@router.delete("/services/{service_id}", status_code=status.HTTP_204_NO_CONTENT)
def retire_service(
    service_id: str,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> None:
    """Retire or deactivate a service."""
    workspace.require("services.manage")
    try:
        delete_service(db, service_id, workspace.organization_id)
    except ServiceRegistryError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"error": exc.code, "message": exc.message}) from exc


# --------------------------------------------------------------------------
# 2. Capabilities Management
# --------------------------------------------------------------------------

@router.post("/services/{service_id}/capabilities", response_model=CapabilityResponse, status_code=status.HTTP_201_CREATED)
def add_capability_to_service(
    service_id: str,
    payload: CapabilityRegisterRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> CapabilityResponse:
    """Register a new capability under a service."""
    workspace.require("capabilities.manage")
    org_id = workspace.organization_id
    if not org_id:
        raise HTTPException(status_code=400, detail="Personal workspace cannot manage capabilities.")

    service = get_service(db, service_id, org_id)

    try:
        cap = register_capability(
            db,
            organization_id=org_id,
            agent_id=payload.agent_id,
            service_id=service.id,
            name=payload.name,
            version=payload.version,
            description=payload.description,
            input_schema=payload.input_schema,
            output_schema=payload.output_schema,
            risk_classification=payload.risk_classification,
            requires_approval=payload.requires_approval,
            approval_threshold_amount=payload.approval_threshold_amount,
            rate_limit_per_minute=payload.rate_limit_per_minute,
        )
        return CapabilityResponse.model_validate(cap)
    except ServiceRegistryError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"error": exc.code, "message": exc.message}) from exc


@router.get("/services/{service_id}/capabilities", response_model=CapabilityListResponse)
def get_service_capabilities(
    service_id: str,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> CapabilityListResponse:
    """List capabilities bound to a service."""
    workspace.require("services.read")
    service = get_service(db, service_id, workspace.organization_id)
    items, total = list_capabilities(db, service_id=service.id, limit=limit, offset=offset)
    return CapabilityListResponse(items=[CapabilityResponse.model_validate(c) for c in items], total=total)


@router.get("/capabilities", response_model=CapabilityListResponse)
def get_capabilities_catalog(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
    agent_id: Optional[UUID] = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> CapabilityListResponse:
    """List all published capabilities in the organization."""
    workspace.require("services.read")
    items, total = list_capabilities(
        db,
        organization_id=workspace.organization_id,
        agent_id=agent_id,
        limit=limit,
        offset=offset,
    )
    return CapabilityListResponse(items=[CapabilityResponse.model_validate(c) for c in items], total=total)


# --------------------------------------------------------------------------
# 3. Endpoints Management & Verification
# --------------------------------------------------------------------------

@router.post("/services/{service_id}/endpoints", response_model=EndpointResponse, status_code=status.HTTP_201_CREATED)
def add_service_endpoint(
    service_id: str,
    payload: EndpointCreateRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> EndpointResponse:
    """Add a network endpoint destination to a service."""
    workspace.require("services.manage")
    org_id = workspace.organization_id
    if not org_id:
        raise HTTPException(status_code=400, detail="Personal workspace cannot manage endpoints.")

    service = get_service(db, service_id, org_id)

    try:
        ep = register_endpoint(
            db,
            organization_id=org_id,
            service_id=service.id,
            protocol=payload.protocol,
            url=payload.url,
            priority=payload.priority,
            weight=payload.weight,
            environment=payload.environment,
            allow_private_ips=False,
            enforce_https=(payload.protocol == "HTTPS"),
        )
        return EndpointResponse.model_validate(ep)
    except ServiceRegistryError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"error": exc.code, "message": exc.message}) from exc


@router.get("/services/{service_id}/endpoints", response_model=List[EndpointResponse])
def get_service_endpoints(
    service_id: str,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> List[EndpointResponse]:
    """List registered endpoints for a service."""
    workspace.require("services.read")
    service = get_service(db, service_id, workspace.organization_id)
    endpoints = list_endpoints(db, service.id, workspace.organization_id)
    return [EndpointResponse.model_validate(ep) for ep in endpoints]


@router.post("/services/{service_id}/endpoints/{endpoint_id}/challenges", response_model=ChallengeInitiateResponse)
def initiate_verification(
    service_id: str,
    endpoint_id: str,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> ChallengeInitiateResponse:
    """Generate cryptographic ownership verification challenge for an endpoint."""
    workspace.require("services.manage")
    service = get_service(db, service_id, workspace.organization_id)

    ep = _find_endpoint(db, endpoint_id, service.id)
    challenge = initiate_endpoint_verification(db, ep.id)
    return ChallengeInitiateResponse(
        challenge_id=challenge.challenge_id,
        challenge_token=challenge.challenge_token,
        expires_at=challenge.expires_at,
    )


@router.post("/services/{service_id}/endpoints/{endpoint_id}/verify", response_model=EndpointVerifyResponse)
def verify_endpoint(
    service_id: str,
    endpoint_id: str,
    payload: EndpointVerifyRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> EndpointVerifyResponse:
    """Verify cryptographic challenge signature and mark endpoint HEALTHY."""
    workspace.require("services.manage")
    service = get_service(db, service_id, workspace.organization_id)
    ep = _find_endpoint(db, endpoint_id, service.id)

    try:
        res = verify_endpoint_challenge(
            db,
            endpoint_id=ep.id,
            challenge_token=payload.challenge_token,
            signature=payload.signature,
            key_id=payload.key_id,
        )
        return EndpointVerifyResponse(**res)
    except ServiceRegistryError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"error": exc.code, "message": exc.message}) from exc


# --------------------------------------------------------------------------
# 4. Trusted Resolution & Discovery
# --------------------------------------------------------------------------

@router.post("/services/resolve", response_model=ServiceResolveResponse)
def resolve_service_endpoint(
    payload: ServiceResolveRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> ServiceResolveResponse:
    """
    Resolve routable endpoints for an AgentService.
    Zero-Trust Invariant: Discovery is NOT trust; resolution does NOT authorize action.
    """
    workspace.require("services.resolve")
    try:
        res = resolve_service(
            db,
            caller_agent_id=payload.caller_agent_id,
            service_id_or_name=payload.service_id,
            capability_name=payload.capability,
        )
        return ServiceResolveResponse(**res)
    except ResolutionError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"error": exc.code, "message": exc.message, "details": exc.details},
        ) from exc


# --------------------------------------------------------------------------
# 5. Agent-to-Agent Execution Pipeline
# --------------------------------------------------------------------------

@router.post("/services/call", response_model=AgentCallResponse)
def call_agent_service(
    payload: AgentCallRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> AgentCallResponse:
    """
    Execute authenticated agent-to-agent invocation with loop and depth protection.
    """
    workspace.require("services.call")
    try:
        res = execute_agent_to_agent_call(
            db,
            caller_agent_id=payload.caller_agent_id,
            service_id_or_name=payload.service_id,
            capability_name=payload.capability,
            payload=payload.payload,
            call_chain=payload.call_chain,
            depth=payload.depth,
            idempotency_key=payload.idempotency_key,
            caller_signature=payload.caller_signature,
            caller_key_id=payload.caller_key_id,
            caller_timestamp=payload.caller_timestamp,
            caller_nonce=payload.caller_nonce,
            credential_jwt=payload.credential_jwt,
        )
        return AgentCallResponse(**res)
    except AgentCallPipelineError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"error": exc.code, "message": exc.message, "details": exc.details},
        ) from exc


@router.get("/services/calls", response_model=List[AgentCallRecordSummary])
def list_call_traces(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
    limit: int = Query(50, ge=1, le=200),
) -> List[AgentCallRecordSummary]:
    """List recent agent-to-agent call traces and audit logs."""
    workspace.require("services.read")
    org_id = workspace.organization_id
    query = select(AgentCallRecord)
    if org_id:
        query = query.where(
            (AgentCallRecord.source_organization_id == org_id) |
            (AgentCallRecord.target_organization_id == org_id)
        )
    records = db.scalars(query.order_by(desc(AgentCallRecord.created_at)).limit(limit)).all()
    return [AgentCallRecordSummary.model_validate(r) for r in records]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _format_service_response(db: Session, service: AgentService) -> ServiceResponse:
    caps_count = len(db.scalars(select(AgentCapability.id).where(AgentCapability.service_id == service.id)).all())
    eps_count = len(db.scalars(select(AgentServiceEndpoint.id).where(AgentServiceEndpoint.service_id == service.id)).all())

    return ServiceResponse(
        id=service.id,
        service_id=service.service_id,
        organization_id=service.organization_id,
        agent_id=service.agent_id,
        name=service.name,
        description=service.description,
        version=service.version,
        status=service.status,
        visibility=service.visibility,
        environment=service.environment,
        metadata_json=service.metadata_json or {},
        created_at=service.created_at,
        updated_at=service.updated_at,
        capabilities_count=caps_count,
        endpoints_count=eps_count,
    )


def _find_endpoint(db: Session, ep_id_or_uuid: str | UUID, service_id: UUID) -> AgentServiceEndpoint:
    query = select(AgentServiceEndpoint).where(AgentServiceEndpoint.service_id == service_id)
    if isinstance(ep_id_or_uuid, UUID):
        query = query.where(AgentServiceEndpoint.id == ep_id_or_uuid)
    elif str(ep_id_or_uuid).startswith("ep_"):
        query = query.where(AgentServiceEndpoint.endpoint_id == str(ep_id_or_uuid))
    else:
        try:
            u = UUID(str(ep_id_or_uuid))
            query = query.where(AgentServiceEndpoint.id == u)
        except ValueError:
            query = query.where(AgentServiceEndpoint.endpoint_id == str(ep_id_or_uuid))

    ep = db.scalar(query)
    if not ep:
        raise HTTPException(status_code=404, detail="Service endpoint not found.")
    return ep
