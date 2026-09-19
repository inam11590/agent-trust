"""AgentTrust Protocol (ATP/1.0) Gateway API Endpoints (Step 21)."""

from __future__ import annotations

from typing import Annotated, Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser
from app.core.config import Settings
from app.database.session import get_db
from app.models.agent import Agent
from app.models.agenttrust_protocol import (
    AgentCapability,
    AgentEndpoint,
    ATPDeliveryStatus,
    ATPMessageDelivery,
    ATPMessageRecord,
    EndpointStatus,
)
from app.schemas.agenttrust_protocol import (
    AgentCapabilityCreate,
    AgentCapabilityResponse,
    AgentEndpointCreate,
    AgentEndpointResponse,
    AgentEndpointUpdate,
    ATPGatewayDispatchResponse,
    ATPMessageEnvelope,
    ATPMessageRecordSummary,
    GatewayIdentityResponse,
)
from app.services.gateway_identity import (
    GATEWAY_ISSUER,
    GATEWAY_KEY_ID,
    get_gateway_public_key_base64,
    get_gateway_public_key_pem,
)
from app.services.gateway_pipeline import GatewayPipelineError, process_atp_message
from app.services.organization_context import CurrentWorkspace
from app.services.ssrf_protection import SSRFValidationError, resolve_and_validate_endpoint_url

router = APIRouter(prefix="/atp", tags=["AgentTrust Protocol Gateway"])


# ----------------------------------------------------------------------
# 1. Gateway Health & Public Identity
# ----------------------------------------------------------------------

@router.get("/health", status_code=status.HTTP_200_OK)
def gateway_health() -> Dict[str, Any]:
    """Check AgentTrust Gateway status and supported protocol version."""
    return {
        "status": "operational",
        "gateway": "AgentTrust-Gateway/1.0",
        "protocol": "ATP/1.0",
        "signing_version": "ATP-SIG/1",
        "gateway_key_id": GATEWAY_KEY_ID,
    }


@router.get("/gateway-identity", response_model=GatewayIdentityResponse)
def get_gateway_identity() -> GatewayIdentityResponse:
    """
    Public Gateway Ed25519 identity key used to verify X-ATP-Gateway-Attestation tokens.
    Target agent endpoints inspect this key to trust Gateway-routed messages.
    """
    return GatewayIdentityResponse(
        issuer=GATEWAY_ISSUER,
        key_id=GATEWAY_KEY_ID,
        algorithm="Ed25519",
        public_key_base64=get_gateway_public_key_base64(),
        public_key_pem=get_gateway_public_key_pem(),
        attestation_ttl_seconds=60,
    )


# ----------------------------------------------------------------------
# 2. Main Protocol Gateway Message Route
# ----------------------------------------------------------------------

@router.post(
    "/messages",
    response_model=ATPGatewayDispatchResponse,
    status_code=status.HTTP_200_OK,
    summary="Dispatch ATP/1.0 Message through Gateway",
)
def dispatch_atp_message(
    envelope: ATPMessageEnvelope,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> ATPGatewayDispatchResponse:
    """
    Ingest, verify, authorize, and route an ATP/1.0 agent message.
    Authentication is cryptographic via Ed25519 ATP-SIG/1 signature on the envelope.
    Enforces 11 verification stages, anti-replay, SSRF defense, and short TTL Gateway attestation.
    """
    # In local and test modes, allow private IP resolution for sandbox/mocking
    settings = Settings()
    allow_private = settings.app_env in {"local", "test", "development"}
    enforce_https = settings.app_env in {"production", "staging"}

    try:
        result = process_atp_message(
            db=db,
            envelope=envelope.model_dump(),
            allow_private_ips=allow_private,
            enforce_https=enforce_https,
        )
        if result.get("status") == "PENDING_APPROVAL":
            response.status_code = status.HTTP_202_ACCEPTED
        return ATPGatewayDispatchResponse(**result)
    except GatewayPipelineError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={
                "error": exc.code,
                "message": exc.message,
                "details": exc.details,
            },
        ) from exc


# ----------------------------------------------------------------------
# 3. Message Inspection & Audit
# ----------------------------------------------------------------------

@router.get("/messages", response_model=List[ATPMessageRecordSummary])
def list_atp_messages(
    db: Annotated[Session, Depends(get_db)],
    limit: int = Query(50, ge=1, le=200),
    status_filter: Optional[str] = Query(None, alias="status"),
) -> List[ATPMessageRecordSummary]:
    """List recent ATP messages passing through the gateway."""
    query = select(ATPMessageRecord).order_by(desc(ATPMessageRecord.created_at)).limit(limit)
    if status_filter:
        query = query.where(ATPMessageRecord.status == status_filter)
    records = db.execute(query).scalars().all()
    return [ATPMessageRecordSummary.model_validate(r) for r in records]


@router.get("/messages/{message_id}", status_code=status.HTTP_200_OK)
def get_atp_message(
    message_id: str,
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Retrieve detailed state and delivery trace for an ATP message."""
    record = db.execute(
        select(ATPMessageRecord).where(ATPMessageRecord.message_id == message_id)
    ).scalar_one_or_none()

    if not record:
        raise HTTPException(status_code=404, detail="ATP message not found")

    deliveries = db.execute(
        select(ATPMessageDelivery)
        .where(ATPMessageDelivery.message_id == message_id)
        .order_by(ATPMessageDelivery.attempt_count)
    ).scalars().all()

    return {
        "record": ATPMessageRecordSummary.model_validate(record),
        "deliveries": [
            {
                "id": str(d.id),
                "attempt_count": d.attempt_count,
                "status": d.status,
                "http_status": d.http_status,
                "last_attempt_at": d.last_attempt_at.isoformat() if d.last_attempt_at else None,
                "completed_at": d.completed_at.isoformat() if d.completed_at else None,
                "error_message": d.error_message,
            }
            for d in deliveries
        ],
    }


# ----------------------------------------------------------------------
# 4. Agent Endpoint Management (SSRF-Protected)
# ----------------------------------------------------------------------

@router.post("/endpoints", response_model=AgentEndpointResponse, status_code=status.HTTP_201_CREATED)
def register_agent_endpoint(
    payload: AgentEndpointCreate,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> AgentEndpointResponse:
    """
    Register a destination HTTP(S) endpoint for an agent.
    Performs immediate SSRF pre-validation on the endpoint URL.
    """
    workspace.require("manage_agents")

    # Verify agent belongs to current organization
    agent = db.execute(
        select(Agent).where(Agent.id == payload.agent_id, Agent.organization_id == workspace.organization_id)
    ).scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found in current organization")

    # Validate SSRF
    settings = Settings()
    allow_private = settings.app_env in {"local", "test", "development"}
    enforce_https = settings.app_env in {"production", "staging"}
    try:
        validated_url, _ = resolve_and_validate_endpoint_url(
            payload.endpoint_url,
            allow_private_ips=allow_private,
            enforce_https=enforce_https,
        )
    except SSRFValidationError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": exc.code, "message": f"SSRF Validation Error: {exc.message}"},
        ) from exc

    # Existing endpoint update or create
    endpoint = db.execute(
        select(AgentEndpoint).where(AgentEndpoint.agent_id == payload.agent_id)
    ).scalar_one_or_none()

    if endpoint:
        endpoint.endpoint_url = validated_url
        endpoint.status = EndpointStatus.VERIFIED.value
    else:
        endpoint = AgentEndpoint(
            organization_id=workspace.organization_id,
            agent_id=payload.agent_id,
            endpoint_url=validated_url,
            status=EndpointStatus.VERIFIED.value,
        )
        db.add(endpoint)

    db.commit()
    db.refresh(endpoint)
    return AgentEndpointResponse.model_validate(endpoint)


@router.get("/endpoints", response_model=List[AgentEndpointResponse])
def list_agent_endpoints(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> List[AgentEndpointResponse]:
    """List registered agent endpoints in current organization."""
    endpoints = db.execute(
        select(AgentEndpoint).where(AgentEndpoint.organization_id == workspace.organization_id)
    ).scalars().all()
    return [AgentEndpointResponse.model_validate(ep) for ep in endpoints]


@router.delete("/endpoints/{endpoint_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_agent_endpoint(
    endpoint_id: UUID,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
):
    """Disable or remove an agent endpoint."""
    workspace.require("manage_agents")
    endpoint = db.execute(
        select(AgentEndpoint).where(
            AgentEndpoint.id == endpoint_id,
            AgentEndpoint.organization_id == workspace.organization_id,
        )
    ).scalar_one_or_none()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    db.delete(endpoint)
    db.commit()
    return None


# ----------------------------------------------------------------------
# 5. Agent Capability Catalog
# ----------------------------------------------------------------------

@router.post("/agents/{agent_id}/capabilities", response_model=AgentCapabilityResponse, status_code=status.HTTP_201_CREATED)
def publish_agent_capability(
    agent_id: UUID,
    payload: AgentCapabilityCreate,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> AgentCapabilityResponse:
    """Publish a versioned capability for an agent."""
    workspace.require("manage_agents")
    agent = db.execute(
        select(Agent).where(Agent.id == agent_id, Agent.organization_id == workspace.organization_id)
    ).scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found in current organization")

    # Check for existing capability
    cap = db.execute(
        select(AgentCapability).where(
            AgentCapability.agent_id == agent_id,
            AgentCapability.name == payload.name,
            AgentCapability.version == payload.version,
        )
    ).scalar_one_or_none()

    if cap:
        cap.description = payload.description
        cap.input_schema = payload.input_schema
        cap.output_schema = payload.output_schema
        cap.is_active = True
    else:
        cap = AgentCapability(
            organization_id=workspace.organization_id,
            agent_id=agent_id,
            name=payload.name,
            version=payload.version,
            description=payload.description,
            input_schema=payload.input_schema,
            output_schema=payload.output_schema,
            is_active=True,
        )
        db.add(cap)

    db.commit()
    db.refresh(cap)
    return AgentCapabilityResponse.model_validate(cap)


@router.get("/agents/{agent_id}/capabilities", response_model=List[AgentCapabilityResponse])
def list_agent_capabilities(
    agent_id: UUID,
    db: Annotated[Session, Depends(get_db)],
) -> List[AgentCapabilityResponse]:
    """List public capabilities offered by an agent."""
    caps = db.execute(
        select(AgentCapability).where(AgentCapability.agent_id == agent_id, AgentCapability.is_active.is_(True))
    ).scalars().all()
    return [AgentCapabilityResponse.model_validate(c) for c in caps]
