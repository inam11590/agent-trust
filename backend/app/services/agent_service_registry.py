"""Agent Service Registry, Capability Catalog, and Cryptographic Verification (Step 30).

Provides authoritative service lifecycle management, tenant-isolated registries,
and cryptographic challenge verification for agent endpoints.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import desc, or_, select
from sqlalchemy.orm import Session

from app.models.agent import Agent, AgentStatus
from app.models.agent_service import (
    AgentCallRecord,
    AgentService,
    AgentServiceEndpoint,
    EndpointHealthStatus,
    EndpointProtocol,
    ServiceStatus,
    ServiceVerificationChallenge,
    ServiceVisibility,
)
from app.models.agent_signing import AgentSigningKey, AgentSigningKeyStatus
from app.models.agenttrust_protocol import AgentCapability
from app.models.organization import Organization, SecurityEvent
from app.services.ssrf_protection import SSRFValidationError, resolve_and_validate_endpoint_url


class ServiceRegistryError(Exception):
    """Base exception for service registry errors."""

    def __init__(self, message: str, code: str = "SERVICE_REGISTRY_ERROR", status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code


# --------------------------------------------------------------------------
# Service Lifecycle Management
# --------------------------------------------------------------------------

def create_service(
    db: Session,
    *,
    organization_id: UUID,
    agent_id: UUID,
    name: str,
    description: Optional[str] = None,
    version: str = "1.0.0",
    status: str = ServiceStatus.ACTIVE.value,
    visibility: str = ServiceVisibility.ORGANIZATION.value,
    environment: str = "production",
    metadata_json: Optional[Dict[str, Any]] = None,
) -> AgentService:
    """Create a tenant-isolated AgentService bound to a registered Agent."""
    agent = db.scalar(select(Agent).where(Agent.id == agent_id))
    if not agent:
        raise ServiceRegistryError("Target agent does not exist.", code="AGENT_NOT_FOUND", status_code=404)
    if agent.organization_id != organization_id:
        raise ServiceRegistryError("Target agent does not belong to this organization.", code="TENANT_MISMATCH", status_code=403)
    if agent.status in (AgentStatus.RETIRED, AgentStatus.SUSPENDED):
        raise ServiceRegistryError(
            f"Cannot create service on agent with lifecycle status '{agent.status.value}'.",
            code="AGENT_LIFECYCLE_INVALID",
            status_code=409,
        )

    # Check name uniqueness within organization
    existing = db.scalar(
        select(AgentService).where(
            AgentService.organization_id == organization_id,
            AgentService.name == name,
        )
    )
    if existing:
        raise ServiceRegistryError(
            f"Service with name '{name}' already exists in this organization.",
            code="SERVICE_NAME_CONFLICT",
            status_code=409,
        )

    service = AgentService(
        organization_id=organization_id,
        agent_id=agent_id,
        name=name,
        description=description,
        version=version,
        status=status,
        visibility=visibility,
        environment=environment or agent.environment,
        metadata_json=metadata_json or {},
    )
    db.add(service)
    db.commit()
    db.refresh(service)
    return service


def get_service(
    db: Session,
    service_id_or_uuid: str | UUID,
    organization_id: Optional[UUID] = None,
) -> AgentService:
    """Retrieve an AgentService by service_id ('svc_...') or UUID."""
    query = select(AgentService)
    if isinstance(service_id_or_uuid, UUID):
        query = query.where(AgentService.id == service_id_or_uuid)
    elif str(service_id_or_uuid).startswith("svc_"):
        query = query.where(AgentService.service_id == str(service_id_or_uuid))
    else:
        try:
            u = UUID(str(service_id_or_uuid))
            query = query.where(AgentService.id == u)
        except ValueError:
            query = query.where(AgentService.name == str(service_id_or_uuid))

    service = db.scalar(query)
    if not service:
        raise ServiceRegistryError("Service not found.", code="SERVICE_NOT_FOUND", status_code=404)

    if organization_id and service.organization_id != organization_id:
        # Check if service is public or trusted_org before rejecting
        if service.visibility not in (ServiceVisibility.PUBLIC_DISCOVERABLE.value, ServiceVisibility.TRUSTED_ORGANIZATIONS.value):
            raise ServiceRegistryError("Service access denied.", code="FORBIDDEN", status_code=403)

    return service


def list_services(
    db: Session,
    *,
    organization_id: Optional[UUID] = None,
    agent_id: Optional[UUID] = None,
    status: Optional[str] = None,
    visibility: Optional[str] = None,
    environment: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[AgentService], int]:
    """List services with tenant isolation and multi-attribute filters."""
    query = select(AgentService)
    if organization_id:
        query = query.where(AgentService.organization_id == organization_id)
    if agent_id:
        query = query.where(AgentService.agent_id == agent_id)
    if status:
        query = query.where(AgentService.status == status)
    if visibility:
        query = query.where(AgentService.visibility == visibility)
    if environment:
        query = query.where(AgentService.environment == environment)

    total_query = select(AgentService.id)
    if organization_id:
        total_query = total_query.where(AgentService.organization_id == organization_id)
    if agent_id:
        total_query = total_query.where(AgentService.agent_id == agent_id)
    if status:
        total_query = total_query.where(AgentService.status == status)
    if visibility:
        total_query = total_query.where(AgentService.visibility == visibility)
    if environment:
        total_query = total_query.where(AgentService.environment == environment)

    total = len(db.scalars(total_query).all())
    items = db.scalars(query.order_by(desc(AgentService.created_at)).offset(offset).limit(limit)).all()
    return items, total


def update_service(
    db: Session,
    service_id_or_uuid: str | UUID,
    updates: Dict[str, Any],
    organization_id: Optional[UUID] = None,
) -> AgentService:
    """Update mutable properties of an AgentService."""
    service = get_service(db, service_id_or_uuid, organization_id)
    if organization_id and service.organization_id != organization_id:
        raise ServiceRegistryError("Cannot update service outside your organization.", code="FORBIDDEN", status_code=403)

    for field in ("description", "version", "status", "visibility", "environment", "metadata_json"):
        if field in updates and updates[field] is not None:
            setattr(service, field, updates[field])

    service.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(service)
    return service


def delete_service(
    db: Session,
    service_id_or_uuid: str | UUID,
    organization_id: Optional[UUID] = None,
) -> None:
    """Soft-retire or delete a service."""
    service = get_service(db, service_id_or_uuid, organization_id)
    if organization_id and service.organization_id != organization_id:
        raise ServiceRegistryError("Cannot delete service outside your organization.", code="FORBIDDEN", status_code=403)

    service.status = ServiceStatus.RETIRED.value
    service.updated_at = datetime.now(timezone.utc)
    db.commit()


# --------------------------------------------------------------------------
# Capability Registry
# --------------------------------------------------------------------------

def register_capability(
    db: Session,
    *,
    organization_id: UUID,
    agent_id: UUID,
    service_id: Optional[UUID] = None,
    name: str,
    version: str = "1.0",
    description: Optional[str] = None,
    input_schema: Optional[Dict[str, Any]] = None,
    output_schema: Optional[Dict[str, Any]] = None,
    risk_classification: str = "LOW",
    requires_approval: bool = False,
    approval_threshold_amount: Optional[float] = None,
    rate_limit_per_minute: Optional[int] = None,
) -> AgentCapability:
    """Register or update an AgentCapability bound to a service or agent."""
    agent = db.scalar(select(Agent).where(Agent.id == agent_id))
    if not agent or agent.organization_id != organization_id:
        raise ServiceRegistryError("Invalid agent for capability registration.", code="AGENT_INVALID", status_code=400)

    if service_id:
        service = db.scalar(select(AgentService).where(AgentService.id == service_id))
        if not service or service.organization_id != organization_id:
            raise ServiceRegistryError("Invalid service for capability registration.", code="SERVICE_INVALID", status_code=400)

    # Check existing by (agent_id, name, version)
    existing = db.scalar(
        select(AgentCapability).where(
            AgentCapability.agent_id == agent_id,
            AgentCapability.name == name,
            AgentCapability.version == version,
        )
    )
    if existing:
        existing.service_id = service_id
        existing.description = description
        existing.input_schema = input_schema
        existing.output_schema = output_schema
        existing.risk_classification = risk_classification
        existing.requires_approval = requires_approval
        existing.approval_threshold_amount = approval_threshold_amount
        existing.rate_limit_per_minute = rate_limit_per_minute
        existing.is_active = True
        existing.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(existing)
        return existing

    capability = AgentCapability(
        organization_id=organization_id,
        agent_id=agent_id,
        service_id=service_id,
        name=name,
        version=version,
        description=description,
        input_schema=input_schema or {},
        output_schema=output_schema or {},
        risk_classification=risk_classification,
        requires_approval=requires_approval,
        approval_threshold_amount=approval_threshold_amount,
        rate_limit_per_minute=rate_limit_per_minute,
        is_active=True,
    )
    db.add(capability)
    db.commit()
    db.refresh(capability)
    return capability


def list_capabilities(
    db: Session,
    *,
    organization_id: Optional[UUID] = None,
    service_id: Optional[UUID] = None,
    agent_id: Optional[UUID] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[AgentCapability], int]:
    """Query capabilities across services."""
    query = select(AgentCapability)
    if organization_id:
        query = query.where(AgentCapability.organization_id == organization_id)
    if service_id:
        query = query.where(AgentCapability.service_id == service_id)
    if agent_id:
        query = query.where(AgentCapability.agent_id == agent_id)

    total = len(db.scalars(query).all())
    items = db.scalars(query.order_by(AgentCapability.name).offset(offset).limit(limit)).all()
    return items, total


def get_capability(
    db: Session,
    cap_id_or_name: str | UUID,
    organization_id: Optional[UUID] = None,
) -> AgentCapability:
    """Retrieve capability by cap_... ID or UUID or name."""
    query = select(AgentCapability)
    if isinstance(cap_id_or_name, UUID):
        query = query.where(AgentCapability.id == cap_id_or_name)
    elif str(cap_id_or_name).startswith("cap_"):
        query = query.where(AgentCapability.capability_id == str(cap_id_or_name))
    else:
        query = query.where(AgentCapability.name == str(cap_id_or_name))

    if organization_id:
        query = query.where(AgentCapability.organization_id == organization_id)

    cap = db.scalar(query)
    if not cap:
        raise ServiceRegistryError("Capability not found.", code="CAPABILITY_NOT_FOUND", status_code=404)
    return cap


# --------------------------------------------------------------------------
# Endpoint Registration & Cryptographic Verification
# --------------------------------------------------------------------------

def register_endpoint(
    db: Session,
    *,
    organization_id: UUID,
    service_id: UUID,
    protocol: str = EndpointProtocol.HTTPS.value,
    url: str,
    priority: int = 1,
    weight: int = 100,
    environment: str = "production",
    allow_private_ips: bool = False,
    enforce_https: bool = True,
) -> AgentServiceEndpoint:
    """Register a new service endpoint destination with SSRF validation."""
    service = db.scalar(select(AgentService).where(AgentService.id == service_id))
    if not service or service.organization_id != organization_id:
        raise ServiceRegistryError("Target service not found or unauthorized.", code="SERVICE_NOT_FOUND", status_code=404)

    # Validate URL using SSRF protection if protocol is HTTPS or AGENTTRUST_GATEWAY
    validated_url = url.strip()
    if protocol in (EndpointProtocol.HTTPS.value, EndpointProtocol.AGENTTRUST_GATEWAY.value):
        try:
            validated_url, _ = resolve_and_validate_endpoint_url(
                url,
                allow_private_ips=allow_private_ips,
                enforce_https=(enforce_https and protocol == EndpointProtocol.HTTPS.value),
            )
        except SSRFValidationError as exc:
            raise ServiceRegistryError(
                f"Endpoint URL rejected by SSRF protection: {exc.message}",
                code="SSRF_REJECTED",
                status_code=400,
            ) from exc

    endpoint = AgentServiceEndpoint(
        organization_id=organization_id,
        service_id=service.id,
        agent_id=service.agent_id,
        protocol=protocol,
        url=validated_url,
        priority=priority,
        weight=weight,
        environment=environment or service.environment,
        health_status=EndpointHealthStatus.UNKNOWN.value,
        is_active=True,
    )
    db.add(endpoint)
    db.commit()
    db.refresh(endpoint)
    return endpoint


def list_endpoints(
    db: Session,
    service_id: UUID,
    organization_id: Optional[UUID] = None,
) -> List[AgentServiceEndpoint]:
    """List endpoints for a given service."""
    query = select(AgentServiceEndpoint).where(AgentServiceEndpoint.service_id == service_id)
    if organization_id:
        query = query.where(AgentServiceEndpoint.organization_id == organization_id)
    return db.scalars(query.order_by(AgentServiceEndpoint.priority, desc(AgentServiceEndpoint.weight))).all()


def initiate_endpoint_verification(
    db: Session,
    endpoint_id: UUID,
    ttl_seconds: int = 900,
) -> ServiceVerificationChallenge:
    """Generate a cryptographic ownership challenge token for an endpoint."""
    endpoint = db.scalar(select(AgentServiceEndpoint).where(AgentServiceEndpoint.id == endpoint_id))
    if not endpoint:
        raise ServiceRegistryError("Endpoint not found.", code="ENDPOINT_NOT_FOUND", status_code=404)

    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    challenge = ServiceVerificationChallenge(
        endpoint_id=endpoint.id,
        expires_at=expires_at,
        status="PENDING",
    )
    endpoint.verification_challenge = challenge.challenge_token
    db.add(challenge)
    db.commit()
    db.refresh(challenge)
    return challenge


def verify_endpoint_challenge(
    db: Session,
    endpoint_id: UUID,
    challenge_token: str,
    signature: Optional[str] = None,
    key_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Verify endpoint ownership challenge.
    Supports either:
    1. Cryptographic Ed25519 signature by Agent's registered signing key over challenge payload.
    2. Challenge token direct proof (e.g. from HTTPS pre-flight endpoint probe).
    """
    endpoint = db.scalar(select(AgentServiceEndpoint).where(AgentServiceEndpoint.id == endpoint_id))
    if not endpoint:
        raise ServiceRegistryError("Endpoint not found.", code="ENDPOINT_NOT_FOUND", status_code=404)

    challenge = db.scalar(
        select(ServiceVerificationChallenge)
        .where(
            ServiceVerificationChallenge.endpoint_id == endpoint.id,
            ServiceVerificationChallenge.challenge_token == challenge_token,
            ServiceVerificationChallenge.status == "PENDING",
        )
        .order_by(desc(ServiceVerificationChallenge.created_at))
    )
    if not challenge:
        raise ServiceRegistryError("Challenge not found or already verified.", code="CHALLENGE_INVALID", status_code=404)

    now = datetime.now(timezone.utc)
    challenge_expires = challenge.expires_at
    if challenge_expires.tzinfo is None:
        challenge_expires = challenge_expires.replace(tzinfo=timezone.utc)
    if challenge_expires < now:
        challenge.status = "EXPIRED"
        db.commit()
        raise ServiceRegistryError("Verification challenge has expired.", code="CHALLENGE_EXPIRED", status_code=400)

    # If signature is supplied, verify against agent's registered active signing key
    if signature:
        if not key_id:
            raise ServiceRegistryError("key_id required when signature is supplied.", code="KEY_ID_REQUIRED", status_code=400)

        key = db.scalar(
            select(AgentSigningKey).where(
                AgentSigningKey.key_id == key_id,
                AgentSigningKey.agent_id == endpoint.agent_id,
                AgentSigningKey.status.in_([AgentSigningKeyStatus.ACTIVE, AgentSigningKeyStatus.ROTATING]),
            )
        )
        if not key:
            raise ServiceRegistryError("Valid active signing key not found for agent.", code="KEY_NOT_FOUND", status_code=404)

        try:
            pub_bytes = base64.b64decode(key.public_key, validate=True)
            sig_bytes = base64.b64decode(signature, validate=True)
            verifier = Ed25519PublicKey.from_public_bytes(pub_bytes)
            expected_data = f"AGENTTRUST_VERIFY:{endpoint.endpoint_id}:{challenge_token}".encode("ascii")
            verifier.verify(sig_bytes, expected_data)
        except (InvalidSignature, ValueError, binascii.Error) as exc:
            db.add(SecurityEvent(
                organization_id=endpoint.organization_id,
                event_type="endpoint_verification_failed",
                severity="warning",
                description="Invalid cryptographic signature on endpoint verification challenge.",
                details={"endpoint_id": endpoint.endpoint_id, "key_id": key_id},
            ))
            db.commit()
            raise ServiceRegistryError("Cryptographic signature verification failed.", code="INVALID_SIGNATURE", status_code=403) from exc

    # Mark verified
    challenge.status = "VERIFIED"
    challenge.verified_at = now
    endpoint.verified_at = now
    endpoint.health_status = EndpointHealthStatus.HEALTHY.value
    endpoint.consecutive_failures = 0
    endpoint.last_health_check_at = now
    db.commit()

    return {
        "verified": True,
        "endpoint_id": endpoint.endpoint_id,
        "health_status": endpoint.health_status,
        "verified_at": now.isoformat(),
    }
