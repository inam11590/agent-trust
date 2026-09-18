"""REST API endpoints for Cross-Organization Trust management, directory, and policies."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.models.cross_organization_trust import TrustStatus
from app.schemas.cross_organization_trust import (
    ExternalAgentConnectionCreate,
    ExternalAgentConnectionResponse,
    OrganizationPublicProfileResponse,
    OrganizationPublicProfileUpdate,
    TargetOrganizationPolicyResponse,
    TargetOrganizationPolicyUpdate,
    TrustPolicyResponse,
    TrustPolicyUpdate,
    TrustRelationshipResponse,
    TrustRequestCreate,
    TrustRevokeRequest,
)
from app.services.cross_organization_trust import (
    accept_trust_request,
    create_agent_connection,
    create_trust_request,
    get_public_profile,
    get_target_policy,
    get_trust_relationship,
    list_agent_connections,
    list_trust_relationships,
    reject_trust_request,
    revoke_agent_connection,
    revoke_trust_relationship,
    search_directory,
    update_public_profile,
    update_target_policy,
    update_trust_policy,
)
from app.services.organization_context import CurrentWorkspace

router = APIRouter(prefix="/v1/organization-trust", tags=["organization-trust"])


def _populate_trust_response(db: Session, trust) -> TrustRelationshipResponse:
    resp = TrustRelationshipResponse.model_validate(trust)
    if trust.source_organization:
        resp.source_organization_name = trust.source_organization.name
    if trust.target_organization:
        resp.target_organization_name = trust.target_organization.name
    if trust.policy:
        resp.policy = TrustPolicyResponse.model_validate(trust.policy)
    return resp


def _populate_conn_response(db: Session, conn) -> ExternalAgentConnectionResponse:
    resp = ExternalAgentConnectionResponse.model_validate(conn)
    if conn.source_agent:
        resp.source_agent_name = conn.source_agent.name
    if conn.target_agent:
        resp.target_agent_name = conn.target_agent.name
    return resp


@router.get("/directory", response_model=list[OrganizationPublicProfileResponse])
def get_directory(
    query: Annotated[str, Query()] = "",
    db: Session = Depends(get_db),
) -> list[OrganizationPublicProfileResponse]:
    """Search discoverable organizations in the public directory."""
    profiles = search_directory(db, query=query)
    return [OrganizationPublicProfileResponse.model_validate(p) for p in profiles]


@router.post("/requests", response_model=TrustRelationshipResponse, status_code=201)
def request_trust(
    payload: TrustRequestCreate,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Session = Depends(get_db),
) -> TrustRelationshipResponse:
    """Create a directional trust request to another organization."""
    if not workspace.organization_id:
        raise HTTPException(status_code=400, detail="Organization context required")
    workspace.require("manage_organization")

    trust = create_trust_request(
        db,
        source_org_id=workspace.organization_id,
        target_org_id=payload.target_organization_id,
        user_id=user.id,
        expires_at=payload.expires_at,
    )
    response.headers["Location"] = f"/v1/organization-trust/{trust.trust_id}"
    return _populate_trust_response(db, trust)


@router.get("", response_model=list[TrustRelationshipResponse])
def get_trust_relationships(
    workspace: CurrentWorkspace,
    direction: Annotated[str, Query(pattern=r"^(incoming|outgoing|all)$")] = "all",
    status_filter: Annotated[TrustStatus | None, Query(alias="status")] = None,
    db: Session = Depends(get_db),
) -> list[TrustRelationshipResponse]:
    """List trust relationships for the current organization."""
    if not workspace.organization_id:
        raise HTTPException(status_code=400, detail="Organization context required")
    workspace.require("read")

    relationships = list_trust_relationships(
        db,
        org_id=workspace.organization_id,
        direction=direction,
        status_filter=status_filter,
    )
    return [_populate_trust_response(db, r) for r in relationships]


@router.get("/{trust_id}", response_model=TrustRelationshipResponse)
def get_trust(
    trust_id: str,
    workspace: CurrentWorkspace,
    db: Session = Depends(get_db),
) -> TrustRelationshipResponse:
    """Get trust relationship detail."""
    if not workspace.organization_id:
        raise HTTPException(status_code=400, detail="Organization context required")
    workspace.require("read")
    trust = get_trust_relationship(db, trust_id, workspace.organization_id)
    return _populate_trust_response(db, trust)


@router.post("/{trust_id}/accept", response_model=TrustRelationshipResponse)
def accept_trust(
    trust_id: str,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Session = Depends(get_db),
) -> TrustRelationshipResponse:
    """Target organization Owner/Admin accepts an incoming trust request."""
    if not workspace.organization_id:
        raise HTTPException(status_code=400, detail="Organization context required")
    workspace.require("manage_organization")

    trust = accept_trust_request(db, trust_id, user.id, workspace.organization_id)
    return _populate_trust_response(db, trust)


@router.post("/{trust_id}/reject", response_model=TrustRelationshipResponse)
def reject_trust(
    trust_id: str,
    payload: TrustRevokeRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Session = Depends(get_db),
) -> TrustRelationshipResponse:
    """Target organization Owner/Admin rejects an incoming trust request."""
    if not workspace.organization_id:
        raise HTTPException(status_code=400, detail="Organization context required")
    workspace.require("manage_organization")

    trust = reject_trust_request(db, trust_id, user.id, workspace.organization_id, payload.reason)
    return _populate_trust_response(db, trust)


@router.post("/{trust_id}/revoke", response_model=TrustRelationshipResponse)
def revoke_trust(
    trust_id: str,
    payload: TrustRevokeRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Session = Depends(get_db),
) -> TrustRelationshipResponse:
    """Either organization can revoke an active or pending trust relationship."""
    if not workspace.organization_id:
        raise HTTPException(status_code=400, detail="Organization context required")
    workspace.require("manage_organization")

    trust = revoke_trust_relationship(db, trust_id, user.id, workspace.organization_id, payload.reason)
    return _populate_trust_response(db, trust)


@router.put("/{trust_id}/policy", response_model=TrustPolicyResponse)
def set_policy(
    trust_id: str,
    payload: TrustPolicyUpdate,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Session = Depends(get_db),
) -> TrustPolicyResponse:
    """Configure or restrict the trust policy for a trust relationship."""
    if not workspace.organization_id:
        raise HTTPException(status_code=400, detail="Organization context required")
    workspace.require("manage_permissions")

    policy = update_trust_policy(db, trust_id, user.id, workspace.organization_id, payload)
    return TrustPolicyResponse.model_validate(policy)


# ---------------------------------------------------------------------------
# External Agent Connections Endpoints
# ---------------------------------------------------------------------------

@router.post("/{trust_id}/agent-connections", response_model=ExternalAgentConnectionResponse, status_code=201)
def connect_agents(
    trust_id: str,
    payload: ExternalAgentConnectionCreate,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Session = Depends(get_db),
) -> ExternalAgentConnectionResponse:
    """Connect a specific source and target agent under an active trust relationship."""
    if not workspace.organization_id:
        raise HTTPException(status_code=400, detail="Organization context required")
    workspace.require("manage_permissions")

    conn = create_agent_connection(db, trust_id, payload, user.id, workspace.organization_id)
    return _populate_conn_response(db, conn)


@router.get("/{trust_id}/agent-connections", response_model=list[ExternalAgentConnectionResponse])
def get_agent_connections(
    trust_id: str,
    workspace: CurrentWorkspace,
    db: Session = Depends(get_db),
) -> list[ExternalAgentConnectionResponse]:
    """List agent connections for a trust relationship."""
    if not workspace.organization_id:
        raise HTTPException(status_code=400, detail="Organization context required")
    workspace.require("read")

    connections = list_agent_connections(db, trust_id, workspace.organization_id)
    return [_populate_conn_response(db, c) for c in connections]


@router.post("/{trust_id}/agent-connections/{connection_id}/revoke", response_model=ExternalAgentConnectionResponse)
def disconnect_agents(
    trust_id: str,
    connection_id: str,
    payload: TrustRevokeRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Session = Depends(get_db),
) -> ExternalAgentConnectionResponse:
    """Disconnect/revoke an external agent connection."""
    if not workspace.organization_id:
        raise HTTPException(status_code=400, detail="Organization context required")
    workspace.require("manage_permissions")

    conn = revoke_agent_connection(db, trust_id, connection_id, user.id, workspace.organization_id, payload.reason)
    return _populate_conn_response(db, conn)


# ---------------------------------------------------------------------------
# Public Profile & Target Policy Endpoints
# ---------------------------------------------------------------------------

profile_router = APIRouter(prefix="/v1/organizations", tags=["organization-profile"])


@profile_router.get("/{org_id}/public-profile", response_model=OrganizationPublicProfileResponse)
def read_public_profile(org_id: UUID, db: Session = Depends(get_db)) -> OrganizationPublicProfileResponse:
    """Read public profile for an organization."""
    profile = get_public_profile(db, org_id)
    return OrganizationPublicProfileResponse.model_validate(profile)


@profile_router.put("/{org_id}/public-profile", response_model=OrganizationPublicProfileResponse)
def edit_public_profile(
    org_id: UUID,
    payload: OrganizationPublicProfileUpdate,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Session = Depends(get_db),
) -> OrganizationPublicProfileResponse:
    """Update public profile for organization."""
    if workspace.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Organization context mismatch")
    workspace.require("manage_organization")

    profile = update_public_profile(db, org_id, user.id, payload)
    return OrganizationPublicProfileResponse.model_validate(profile)


@profile_router.get("/{org_id}/target-policy", response_model=TargetOrganizationPolicyResponse)
def read_target_policy(
    org_id: UUID,
    workspace: CurrentWorkspace,
    db: Session = Depends(get_db),
) -> TargetOrganizationPolicyResponse:
    """Read target organization inbound request policy."""
    if workspace.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Organization context mismatch")
    workspace.require("read")

    policy = get_target_policy(db, org_id)
    return TargetOrganizationPolicyResponse.model_validate(policy)


@profile_router.put("/{org_id}/target-policy", response_model=TargetOrganizationPolicyResponse)
def edit_target_policy(
    org_id: UUID,
    payload: TargetOrganizationPolicyUpdate,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    db: Session = Depends(get_db),
) -> TargetOrganizationPolicyResponse:
    """Update target organization inbound request policy."""
    if workspace.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Organization context mismatch")
    workspace.require("manage_permissions")

    policy = update_target_policy(db, org_id, user.id, payload)
    return TargetOrganizationPolicyResponse.model_validate(policy)
