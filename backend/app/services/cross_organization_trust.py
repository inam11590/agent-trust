"""Service layer for managing Cross-Organization Trust relationships, policies, and directory."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models import Agent, AgentStatus, Organization, User
from app.models.cross_organization_trust import (
    ExternalAgentConnection,
    OrganizationPublicProfile,
    OrganizationTrustPolicy,
    OrganizationTrustRelationship,
    TargetOrganizationPolicy,
    TrustStatus,
)
from app.schemas.cross_organization_trust import (
    ExternalAgentConnectionCreate,
    OrganizationPublicProfileUpdate,
    TargetOrganizationPolicyUpdate,
    TrustPolicyUpdate,
)
from app.services.security_events import record_security_event


def create_trust_request(
    db: Session,
    source_org_id: UUID,
    target_org_id: UUID,
    user_id: UUID,
    expires_at: datetime | None = None,
) -> OrganizationTrustRelationship:
    """Create a new directional trust request from source to target organization."""
    if source_org_id == target_org_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot establish trust relationship with your own organization",
        )

    target_org = db.get(Organization, target_org_id)
    if not target_org or not target_org.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target organization not found or inactive",
        )

    # Check for existing relationship
    existing = db.scalar(
        select(OrganizationTrustRelationship).where(
            OrganizationTrustRelationship.source_organization_id == source_org_id,
            OrganizationTrustRelationship.target_organization_id == target_org_id,
        )
    )
    if existing:
        if existing.status == TrustStatus.ACTIVE:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Active trust relationship already exists between these organizations",
            )
        elif existing.status == TrustStatus.PENDING:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A pending trust request already exists",
            )
        else:
            # Re-activate / reset existing relationship
            existing.status = TrustStatus.PENDING
            existing.created_by_user_id = user_id
            existing.accepted_by_user_id = None
            existing.accepted_at = None
            existing.revoked_at = None
            existing.revocation_reason = None
            existing.expires_at = expires_at
            existing.updated_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(existing)
            record_security_event(
                db,
                actor_user_id=user_id,
                event_type="organization_trust_requested",
                organization_id=source_org_id,
                target_user_id=None,
                severity="info",
                description=f"Re-requested trust relationship with organization {target_org_id}",
                details={"trust_id": existing.trust_id, "target_organization_id": str(target_org_id)},
            )
            return existing

    trust = OrganizationTrustRelationship(
        source_organization_id=source_org_id,
        target_organization_id=target_org_id,
        status=TrustStatus.PENDING,
        created_by_user_id=user_id,
        expires_at=expires_at,
    )
    db.add(trust)
    db.flush()

    # Create default empty trust policy
    policy = OrganizationTrustPolicy(
        trust_relationship_id=trust.id,
        allowed_actions=[],
        allowed_resources=[],
        require_human_approval=False,
        approval_type="TARGET_APPROVAL",
        allow_agent_delegation=False,
    )
    db.add(policy)
    db.commit()
    db.refresh(trust)

    record_security_event(
        db,
        actor_user_id=user_id,
        event_type="organization_trust_requested",
        organization_id=source_org_id,
        target_user_id=None,
        severity="info",
        description=f"Requested trust relationship with organization {target_org_id}",
        details={"trust_id": trust.trust_id, "target_organization_id": str(target_org_id)},
    )
    return trust


def accept_trust_request(
    db: Session,
    trust_id: str,
    user_id: UUID,
    target_org_id: UUID,
) -> OrganizationTrustRelationship:
    """Accept an incoming trust request. Only the target organization can accept."""
    trust = db.scalar(
        select(OrganizationTrustRelationship).where(OrganizationTrustRelationship.trust_id == trust_id)
    )
    if not trust:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Trust relationship not found")

    if trust.target_organization_id != target_org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the target organization can accept this trust request",
        )

    if trust.status != TrustStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot accept trust request in '{trust.status.value}' state",
        )

    now = datetime.now(timezone.utc)
    if trust.expires_at is not None and trust.expires_at <= now:
        trust.status = TrustStatus.EXPIRED
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Trust request has expired")

    trust.status = TrustStatus.ACTIVE
    trust.accepted_by_user_id = user_id
    trust.accepted_at = now
    trust.updated_at = now
    db.commit()
    db.refresh(trust)

    record_security_event(
        db,
        actor_user_id=user_id,
        event_type="organization_trust_accepted",
        organization_id=target_org_id,
        severity="info",
        description=f"Accepted trust request {trust_id} from organization {trust.source_organization_id}",
        details={"trust_id": trust_id, "source_organization_id": str(trust.source_organization_id)},
    )
    return trust


def reject_trust_request(
    db: Session,
    trust_id: str,
    user_id: UUID,
    target_org_id: UUID,
    reason: str | None = None,
) -> OrganizationTrustRelationship:
    """Reject an incoming trust request. Only the target organization can reject."""
    trust = db.scalar(
        select(OrganizationTrustRelationship).where(OrganizationTrustRelationship.trust_id == trust_id)
    )
    if not trust:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Trust relationship not found")

    if trust.target_organization_id != target_org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the target organization can reject this trust request",
        )

    if trust.status != TrustStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot reject trust request in '{trust.status.value}' state",
        )

    now = datetime.now(timezone.utc)
    trust.status = TrustStatus.REJECTED
    trust.revocation_reason = reason
    trust.updated_at = now
    db.commit()
    db.refresh(trust)

    record_security_event(
        db,
        actor_user_id=user_id,
        event_type="organization_trust_rejected",
        organization_id=target_org_id,
        severity="info",
        description=f"Rejected trust request {trust_id} from organization {trust.source_organization_id}",
        details={"trust_id": trust_id, "reason": reason},
    )
    return trust


def revoke_trust_relationship(
    db: Session,
    trust_id: str,
    user_id: UUID,
    org_id: UUID,
    reason: str,
) -> OrganizationTrustRelationship:
    """Revoke an active or pending trust relationship. Either organization can revoke."""
    trust = db.scalar(
        select(OrganizationTrustRelationship).where(OrganizationTrustRelationship.trust_id == trust_id)
    )
    if not trust:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Trust relationship not found")

    if trust.source_organization_id != org_id and trust.target_organization_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have access to revoke this trust relationship",
        )

    now = datetime.now(timezone.utc)
    trust.status = TrustStatus.REVOKED
    trust.revoked_at = now
    trust.revocation_reason = reason
    trust.updated_at = now

    # Also revoke any associated external agent connections
    connections = db.scalars(
        select(ExternalAgentConnection).where(
            ExternalAgentConnection.trust_relationship_id == trust.id,
            ExternalAgentConnection.status == "ACTIVE",
        )
    ).all()
    for conn in connections:
        conn.status = "REVOKED"
        conn.revoked_at = now
        conn.revocation_reason = f"Trust relationship {trust_id} revoked"

    db.commit()
    db.refresh(trust)

    record_security_event(
        db,
        actor_user_id=user_id,
        event_type="organization_trust_revoked",
        organization_id=org_id,
        severity="medium",
        description=f"Revoked trust relationship {trust_id}: {reason}",
        details={"trust_id": trust_id, "reason": reason},
    )
    return trust


def get_trust_relationship(
    db: Session,
    trust_id: str,
    org_id: UUID,
) -> OrganizationTrustRelationship:
    """Fetch trust relationship ensuring caller belongs to source or target organization."""
    trust = db.scalar(
        select(OrganizationTrustRelationship).where(OrganizationTrustRelationship.trust_id == trust_id)
    )
    if not trust:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Trust relationship not found")

    if trust.source_organization_id != org_id and trust.target_organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Trust relationship not found")

    return trust


def list_trust_relationships(
    db: Session,
    org_id: UUID,
    direction: str = "all",  # "incoming", "outgoing", "all"
    status_filter: TrustStatus | None = None,
) -> list[OrganizationTrustRelationship]:
    """List trust relationships for an organization."""
    stmt = select(OrganizationTrustRelationship)
    if direction == "incoming":
        stmt = stmt.where(OrganizationTrustRelationship.target_organization_id == org_id)
    elif direction == "outgoing":
        stmt = stmt.where(OrganizationTrustRelationship.source_organization_id == org_id)
    else:
        stmt = stmt.where(
            or_(
                OrganizationTrustRelationship.source_organization_id == org_id,
                OrganizationTrustRelationship.target_organization_id == org_id,
            )
        )

    if status_filter:
        stmt = stmt.where(OrganizationTrustRelationship.status == status_filter)

    stmt = stmt.order_by(OrganizationTrustRelationship.created_at.desc())
    return list(db.scalars(stmt).all())


def update_trust_policy(
    db: Session,
    trust_id: str,
    user_id: UUID,
    org_id: UUID,
    payload: TrustPolicyUpdate,
) -> OrganizationTrustPolicy:
    """Configure or update the policy on a trust relationship. Either party can update/restrict."""
    trust = get_trust_relationship(db, trust_id, org_id)
    policy = db.scalar(
        select(OrganizationTrustPolicy).where(OrganizationTrustPolicy.trust_relationship_id == trust.id)
    )
    now = datetime.now(timezone.utc)
    if not policy:
        policy = OrganizationTrustPolicy(trust_relationship_id=trust.id)
        db.add(policy)

    policy.allowed_actions = payload.allowed_actions
    policy.allowed_resources = payload.allowed_resources
    policy.max_amount = payload.max_amount
    policy.currency = payload.currency
    policy.require_human_approval = payload.require_human_approval
    policy.approval_threshold = payload.approval_threshold
    policy.approval_type = payload.approval_type
    policy.allow_agent_delegation = payload.allow_agent_delegation
    policy.max_delegation_depth = payload.max_delegation_depth
    policy.risk_threshold = payload.risk_threshold
    policy.updated_at = now
    db.commit()
    db.refresh(policy)

    record_security_event(
        db,
        actor_user_id=user_id,
        event_type="organization_trust_policy_updated",
        organization_id=org_id,
        severity="low",
        description=f"Updated trust policy for relationship {trust_id}",
        details={"trust_id": trust_id, "actions": payload.allowed_actions},
    )
    return policy


# ---------------------------------------------------------------------------
# External Agent Connections
# ---------------------------------------------------------------------------

def create_agent_connection(
    db: Session,
    trust_id: str,
    payload: ExternalAgentConnectionCreate,
    user_id: UUID,
    org_id: UUID,
) -> ExternalAgentConnection:
    """Connect a specific source agent and target agent under an active trust relationship."""
    trust = get_trust_relationship(db, trust_id, org_id)
    if trust.status != TrustStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot connect agents: trust relationship is in '{trust.status.value}' state",
        )

    source_agent = db.get(Agent, payload.source_agent_id)
    if not source_agent or source_agent.organization_id != trust.source_organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Source agent does not belong to the source organization of this trust relationship",
        )
    if source_agent.status != AgentStatus.ACTIVE:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Source agent is not active")

    target_agent = db.get(Agent, payload.target_agent_id)
    if not target_agent or target_agent.organization_id != trust.target_organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target agent does not belong to the target organization of this trust relationship",
        )
    if target_agent.status != AgentStatus.ACTIVE:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Target agent is not active")

    # Check for existing connection
    existing = db.scalar(
        select(ExternalAgentConnection).where(
            ExternalAgentConnection.trust_relationship_id == trust.id,
            ExternalAgentConnection.source_agent_id == payload.source_agent_id,
            ExternalAgentConnection.target_agent_id == payload.target_agent_id,
        )
    )
    if existing:
        if existing.status == "ACTIVE":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Connection already exists between these agents",
            )
        existing.status = "ACTIVE"
        existing.expires_at = payload.expires_at
        existing.revoked_at = None
        existing.revocation_reason = None
        db.commit()
        db.refresh(existing)
        return existing

    conn = ExternalAgentConnection(
        trust_relationship_id=trust.id,
        source_agent_id=payload.source_agent_id,
        target_agent_id=payload.target_agent_id,
        status="ACTIVE",
        expires_at=payload.expires_at,
    )
    db.add(conn)
    db.commit()
    db.refresh(conn)

    record_security_event(
        db,
        actor_user_id=user_id,
        event_type="external_agent_connected",
        organization_id=org_id,
        severity="info",
        description=f"Connected source agent {source_agent.name} to target agent {target_agent.name}",
        details={"connection_id": conn.connection_id, "trust_id": trust_id},
    )
    return conn


def revoke_agent_connection(
    db: Session,
    trust_id: str,
    connection_id: str,
    user_id: UUID,
    org_id: UUID,
    reason: str,
) -> ExternalAgentConnection:
    """Disconnect/revoke an external agent connection."""
    trust = get_trust_relationship(db, trust_id, org_id)
    conn = db.scalar(
        select(ExternalAgentConnection).where(
            ExternalAgentConnection.connection_id == connection_id,
            ExternalAgentConnection.trust_relationship_id == trust.id,
        )
    )
    if not conn:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="External agent connection not found")

    conn.status = "REVOKED"
    conn.revoked_at = datetime.now(timezone.utc)
    conn.revocation_reason = reason
    db.commit()
    db.refresh(conn)

    record_security_event(
        db,
        actor_user_id=user_id,
        event_type="external_agent_disconnected",
        organization_id=org_id,
        severity="medium",
        description=f"Disconnected external agent connection {connection_id}: {reason}",
        details={"connection_id": connection_id, "reason": reason},
    )
    return conn


def list_agent_connections(
    db: Session,
    trust_id: str,
    org_id: UUID,
) -> list[ExternalAgentConnection]:
    """List agent connections for a trust relationship."""
    trust = get_trust_relationship(db, trust_id, org_id)
    return list(
        db.scalars(
            select(ExternalAgentConnection)
            .where(ExternalAgentConnection.trust_relationship_id == trust.id)
            .order_by(ExternalAgentConnection.created_at.desc())
        ).all()
    )


# ---------------------------------------------------------------------------
# Directory & Public Profiles
# ---------------------------------------------------------------------------

def get_public_profile(db: Session, org_id: UUID) -> OrganizationPublicProfile:
    """Get public profile for an organization."""
    profile = db.scalar(
        select(OrganizationPublicProfile).where(OrganizationPublicProfile.organization_id == org_id)
    )
    if not profile:
        org = db.get(Organization, org_id)
        if not org:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
        profile = OrganizationPublicProfile(
            organization_id=org_id,
            public_name=org.name,
            description="",
            discoverable=True,
            supported_capabilities=[],
            verification_status="UNVERIFIED",
        )
        db.add(profile)
        db.commit()
        db.refresh(profile)
    return profile


def update_public_profile(
    db: Session,
    org_id: UUID,
    user_id: UUID,
    payload: OrganizationPublicProfileUpdate,
) -> OrganizationPublicProfile:
    """Update public organization profile."""
    profile = get_public_profile(db, org_id)
    profile.public_name = payload.public_name
    profile.description = payload.description
    profile.website_domain = payload.website_domain
    profile.discoverable = payload.discoverable
    profile.supported_capabilities = payload.supported_capabilities
    profile.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(profile)
    return profile


def search_directory(db: Session, query: str = "") -> list[OrganizationPublicProfile]:
    """Search discoverable organization profiles."""
    stmt = select(OrganizationPublicProfile).where(OrganizationPublicProfile.discoverable.is_(True))
    if query.strip():
        search = f"%{query.strip().lower()}%"
        stmt = stmt.where(
            or_(
                OrganizationPublicProfile.public_name.ilike(search),
                OrganizationPublicProfile.description.ilike(search),
            )
        )
    return list(db.scalars(stmt.limit(50)).all())


# ---------------------------------------------------------------------------
# Target Organization Policy
# ---------------------------------------------------------------------------

def get_target_policy(db: Session, org_id: UUID) -> TargetOrganizationPolicy:
    """Get target policy for inbound external requests."""
    policy = db.scalar(
        select(TargetOrganizationPolicy).where(TargetOrganizationPolicy.organization_id == org_id)
    )
    if not policy:
        policy = TargetOrganizationPolicy(
            organization_id=org_id,
            allowed_actions=[],
            allowed_resources=[],
            require_human_approval=False,
        )
        db.add(policy)
        db.commit()
        db.refresh(policy)
    return policy


def update_target_policy(
    db: Session,
    org_id: UUID,
    user_id: UUID,
    payload: TargetOrganizationPolicyUpdate,
) -> TargetOrganizationPolicy:
    """Update target organization inbound policy."""
    policy = get_target_policy(db, org_id)
    policy.allowed_actions = payload.allowed_actions
    policy.allowed_resources = payload.allowed_resources
    policy.max_amount = payload.max_amount
    policy.currency = payload.currency
    policy.require_human_approval = payload.require_human_approval
    policy.approval_threshold = payload.approval_threshold
    policy.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(policy)

    record_security_event(
        db,
        actor_user_id=user_id,
        event_type="target_organization_policy_updated",
        organization_id=org_id,
        severity="low",
        description="Updated target organization inbound request policy",
        details={"allowed_actions": payload.allowed_actions},
    )
    return policy
