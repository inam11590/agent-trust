"""Trusted Agent-to-Agent Service Discovery and Deterministic Router (Step 30).

Implements zero-trust service resolution and deterministic endpoint failover.
Guarantees:
- Service Discovery is NOT Trust; Resolution does NOT authorize action.
- Caller and Target lifecycle checks fail-closed.
- Environment isolation: Sandbox cannot resolve Prod; Prod never routes to Sandbox.
- Visibility & Cross-Org Trust checks enforced.
- Deterministic failover: Priority ASC, Healthy first, Weight DESC.
- No cross-env failover; No silent cross-agent failover.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models.agent import Agent, AgentStatus
from app.models.agent_service import (
    AgentService,
    AgentServiceEndpoint,
    EndpointHealthStatus,
    ServiceStatus,
    ServiceVisibility,
)
from app.models.agenttrust_protocol import AgentCapability
from app.models.cross_organization_trust import (
    OrganizationTrustRelationship,
    TrustStatus,
)
from app.models.organization import SecurityEvent
from app.services.agent_service_registry import get_capability, get_service


class ResolutionError(Exception):
    """Raised when trusted service resolution fails closed."""

    def __init__(self, message: str, code: str = "RESOLUTION_FAILED", status_code: int = 403, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}


def resolve_service(
    db: Session,
    *,
    caller_agent_id: str | UUID,
    service_id_or_name: str | UUID,
    capability_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Resolve routable endpoints for an AgentService adhering to strict zero-trust invariants.
    
    Zero-Trust Principle:
    Service discovery is NOT trust; resolution does NOT authorize action.
    """
    # 1. Validate Caller Agent Lifecycle
    caller = _resolve_and_validate_agent(db, caller_agent_id, is_caller=True)

    # 2. Resolve Service
    service = _find_service(db, service_id_or_name, caller.organization_id)
    if not service:
        raise ResolutionError("Service not found.", code="SERVICE_NOT_FOUND", status_code=404)

    # 3. Validate Target Service & Host Agent Lifecycle
    target_agent = _resolve_and_validate_agent(db, service.agent_id, is_caller=False)

    if service.status == ServiceStatus.DISABLED.value:
        raise ResolutionError(
            f"Service '{service.name}' is currently disabled.",
            code="SERVICE_DISABLED",
            status_code=403,
        )
    if service.status == ServiceStatus.RETIRED.value:
        raise ResolutionError(
            f"Service '{service.name}' has been retired.",
            code="SERVICE_RETIRED",
            status_code=403,
        )

    # 4. Environment Isolation
    caller_env = getattr(caller, "environment", "production") or "production"
    target_env = service.environment or "production"

    if caller_env == "sandbox" and target_env == "production":
        raise ResolutionError(
            "Cross-environment denial: Sandbox caller cannot resolve production service.",
            code="CROSS_ENVIRONMENT_DENIED",
            status_code=403,
        )

    # 5. Visibility & Cross-Org Trust Verification
    _verify_visibility_and_trust(db, caller, service, target_agent)

    # 6. Verify Capability Binding (if requested)
    selected_capability: Optional[AgentCapability] = None
    if capability_name:
        selected_capability = db.scalar(
            select(AgentCapability).where(
                AgentCapability.service_id == service.id,
                AgentCapability.name == capability_name,
                AgentCapability.is_active.is_(True),
            )
        )
        if not selected_capability:
            # Fallback to agent-level capability if not explicitly tied to service_id
            selected_capability = db.scalar(
                select(AgentCapability).where(
                    AgentCapability.agent_id == target_agent.id,
                    AgentCapability.name == capability_name,
                    AgentCapability.is_active.is_(True),
                )
            )
        if not selected_capability:
            raise ResolutionError(
                f"Requested capability '{capability_name}' is not published or active on service '{service.name}'.",
                code="CAPABILITY_NOT_FOUND",
                status_code=404,
            )

    # 7. Query and Deterministically Prioritize Endpoints
    # Enforce environment matching: Production caller ONLY gets production endpoints.
    # Sandbox caller gets sandbox endpoints (or environment-matching).
    endpoints_query = select(AgentServiceEndpoint).where(
        AgentServiceEndpoint.service_id == service.id,
        AgentServiceEndpoint.is_active.is_(True),
    )
    if caller_env == "production":
        endpoints_query = endpoints_query.where(AgentServiceEndpoint.environment == "production")
    else:
        # Sandbox callers match endpoint environment
        endpoints_query = endpoints_query.where(
            AgentServiceEndpoint.environment.in_([caller_env, "sandbox", "development"])
        )

    endpoints = db.scalars(endpoints_query).all()

    if not endpoints:
        raise ResolutionError(
            f"No active endpoints available for service '{service.name}' in environment '{caller_env}'.",
            code="NO_ENDPOINTS_AVAILABLE",
            status_code=503,
        )

    # Deterministic Sort:
    # 1. priority ASC (1 is highest)
    # 2. Healthy status first (HEALTHY=2, DEGRADED=1, UNKNOWN=0, UNAVAILABLE=-1)
    # 3. weight DESC
    # 4. endpoint_id ASC (absolute tie-breaker)
    def health_score(status_str: str) -> int:
        if status_str == EndpointHealthStatus.HEALTHY.value:
            return 3
        if status_str == EndpointHealthStatus.DEGRADED.value:
            return 2
        if status_str == EndpointHealthStatus.UNKNOWN.value:
            return 1
        return 0

    sorted_endpoints = sorted(
        endpoints,
        key=lambda ep: (
            ep.priority,
            -health_score(ep.health_status),
            -ep.weight,
            ep.endpoint_id,
        ),
    )

    primary_endpoint = sorted_endpoints[0]
    failover_endpoints = sorted_endpoints[1:]

    return {
        "status": "RESOLVED",
        "service_id": service.service_id,
        "service_name": service.name,
        "service_status": service.status,
        "service_version": service.version,
        "visibility": service.visibility,
        "target_agent": {
            "id": str(target_agent.id),
            "identifier": target_agent.agent_identifier,
            "name": target_agent.name,
            "status": target_agent.status.value,
        },
        "target_organization_id": str(service.organization_id),
        "primary_endpoint": {
            "endpoint_id": primary_endpoint.endpoint_id,
            "protocol": primary_endpoint.protocol,
            "url": primary_endpoint.url,
            "priority": primary_endpoint.priority,
            "weight": primary_endpoint.weight,
            "health_status": primary_endpoint.health_status,
            "environment": primary_endpoint.environment,
            "verified": primary_endpoint.verified_at is not None,
        },
        "failover_endpoints": [
            {
                "endpoint_id": ep.endpoint_id,
                "protocol": ep.protocol,
                "url": ep.url,
                "priority": ep.priority,
                "weight": ep.weight,
                "health_status": ep.health_status,
                "environment": ep.environment,
                "verified": ep.verified_at is not None,
            }
            for ep in failover_endpoints
        ],
        "capability": {
            "capability_id": selected_capability.capability_id if selected_capability else None,
            "name": selected_capability.name if selected_capability else None,
            "version": selected_capability.version if selected_capability else None,
            "risk_classification": selected_capability.risk_classification if selected_capability else None,
            "requires_approval": selected_capability.requires_approval if selected_capability else False,
            "input_schema": selected_capability.input_schema if selected_capability else None,
        } if selected_capability else None,
        "discovery_advisory": "SERVICE_DISCOVERY_IS_NOT_TRUST_RESOLUTION_DOES_NOT_AUTHORIZE_ACTION",
        "notice": (
            "This resolution does NOT grant authorization to execute. "
            "Invocations must provide valid ATP-SIG/1 signature, ATC/1.0 credentials, and pass runtime APL policy checks."
        ),
    }


def resolve_capability(
    db: Session,
    *,
    caller_agent_id: str | UUID,
    capability_name_or_id: str | UUID,
) -> Dict[str, Any]:
    """
    Convenience method: resolve service endpoints directly by capability name or cap_... ID.
    """
    caller = _resolve_and_validate_agent(db, caller_agent_id, is_caller=True)

    # Find capability
    query = select(AgentCapability).where(AgentCapability.is_active.is_(True))
    if isinstance(capability_name_or_id, UUID):
        query = query.where(AgentCapability.id == capability_name_or_id)
    elif str(capability_name_or_id).startswith("cap_"):
        query = query.where(AgentCapability.capability_id == str(capability_name_or_id))
    else:
        query = query.where(AgentCapability.name == str(capability_name_or_id))

    capabilities = db.scalars(query).all()
    if not capabilities:
        raise ResolutionError(
            f"Capability '{capability_name_or_id}' not found.",
            code="CAPABILITY_NOT_FOUND",
            status_code=404,
        )

    # Find accessible capability
    selected_cap: Optional[AgentCapability] = None
    for cap in capabilities:
        if cap.service_id:
            try:
                service = db.scalar(select(AgentService).where(AgentService.id == cap.service_id))
                if service and service.status in (ServiceStatus.ACTIVE.value, ServiceStatus.DEGRADED.value):
                    target_agent = db.scalar(select(Agent).where(Agent.id == service.agent_id))
                    if target_agent and target_agent.status in (AgentStatus.ACTIVE, AgentStatus.APPROVED):
                        # Test visibility
                        _verify_visibility_and_trust(db, caller, service, target_agent)
                        selected_cap = cap
                        break
            except ResolutionError:
                continue

    if not selected_cap:
        # Fallback to direct resolution
        selected_cap = capabilities[0]

    if not selected_cap.service_id:
        raise ResolutionError(
            f"Capability '{selected_cap.name}' is not bound to a registered AgentService.",
            code="CAPABILITY_NOT_BOUND_TO_SERVICE",
            status_code=400,
        )

    return resolve_service(
        db,
        caller_agent_id=caller.id,
        service_id_or_name=selected_cap.service_id,
        capability_name=selected_cap.name,
    )


# --------------------------------------------------------------------------
# Internal Helpers
# --------------------------------------------------------------------------

def _resolve_and_validate_agent(db: Session, agent_id_or_ident: str | UUID, is_caller: bool) -> Agent:
    """Resolve Agent and verify lifecycle status fails closed."""
    agent: Optional[Agent] = None
    if isinstance(agent_id_or_ident, UUID):
        agent = db.scalar(select(Agent).where(Agent.id == agent_id_or_ident))
    else:
        try:
            u = UUID(str(agent_id_or_ident))
            agent = db.scalar(select(Agent).where(Agent.id == u))
        except ValueError:
            agent = db.scalar(select(Agent).where(Agent.agent_identifier == str(agent_id_or_ident)))

    role_str = "Caller" if is_caller else "Target"
    if not agent:
        raise ResolutionError(f"{role_str} agent not found.", code="AGENT_NOT_FOUND", status_code=404)

    # Fail closed on inactive lifecycle states
    if agent.status == AgentStatus.SUSPENDED:
        raise ResolutionError(
            f"{role_str} agent '{agent.agent_identifier}' is SUSPENDED. Action rejected fail-closed.",
            code=f"{role_str.upper()}_SUSPENDED",
            status_code=403,
        )
    if agent.status == AgentStatus.RETIRED:
        raise ResolutionError(
            f"{role_str} agent '{agent.agent_identifier}' is RETIRED. Action rejected fail-closed.",
            code=f"{role_str.upper()}_RETIRED",
            status_code=403,
        )
    if agent.status not in (AgentStatus.ACTIVE, AgentStatus.APPROVED, AgentStatus.REGISTERED):
        raise ResolutionError(
            f"{role_str} agent '{agent.agent_identifier}' has invalid lifecycle status '{agent.status.value}'.",
            code=f"{role_str.upper()}_NOT_ACTIVE",
            status_code=403,
        )

    return agent


def _find_service(db: Session, service_id_or_name: str | UUID, caller_org_id: Optional[UUID]) -> Optional[AgentService]:
    """Find service by ID, UUID, or name."""
    query = select(AgentService)
    if isinstance(service_id_or_name, UUID):
        return db.scalar(query.where(AgentService.id == service_id_or_name))

    s_str = str(service_id_or_name)
    if s_str.startswith("svc_"):
        return db.scalar(query.where(AgentService.service_id == s_str))

    try:
        u = UUID(s_str)
        return db.scalar(query.where(AgentService.id == u))
    except ValueError:
        pass

    # Search by name; prefer matching caller organization first
    if caller_org_id:
        s = db.scalar(query.where(AgentService.name == s_str, AgentService.organization_id == caller_org_id))
        if s:
            return s

    return db.scalar(query.where(AgentService.name == s_str))


def _verify_visibility_and_trust(
    db: Session,
    caller: Agent,
    service: AgentService,
    target_agent: Agent,
) -> None:
    """Enforce visibility rules and Cross-Organization Trust invariants."""
    visibility = service.visibility

    # 1. PRIVATE: strictly within the same agent
    if visibility == ServiceVisibility.PRIVATE.value:
        if caller.id != target_agent.id:
            raise ResolutionError(
                f"Service '{service.name}' is marked PRIVATE to agent '{target_agent.agent_identifier}'.",
                code="VISIBILITY_PRIVATE_DENIED",
                status_code=403,
            )
        return

    # 2. ORGANIZATION: caller must belong to the exact same organization
    if visibility == ServiceVisibility.ORGANIZATION.value:
        if caller.organization_id != service.organization_id:
            raise ResolutionError(
                f"Service '{service.name}' is restricted to organization '{service.organization_id}'.",
                code="ORGANIZATION_MISMATCH",
                status_code=403,
            )
        return

    # 3. TRUSTED_ORGANIZATIONS: requires active cross-org trust relationship if across orgs
    if visibility == ServiceVisibility.TRUSTED_ORGANIZATIONS.value:
        if caller.organization_id != service.organization_id:
            if not caller.organization_id:
                raise ResolutionError(
                    "Caller agent has no organization and cannot access cross-organization services.",
                    code="CALLER_UNORGANIZED",
                    status_code=403,
                )
            trust = db.scalar(
                select(OrganizationTrustRelationship).where(
                    OrganizationTrustRelationship.source_organization_id == caller.organization_id,
                    OrganizationTrustRelationship.target_organization_id == service.organization_id,
                    OrganizationTrustRelationship.status == TrustStatus.ACTIVE,
                )
            )
            if not trust:
                db.add(SecurityEvent(
                    organization_id=caller.organization_id,
                    event_type="service_resolution_denied",
                    severity="warning",
                    description=f"Cross-organization trust missing to resolve service '{service.name}'.",
                    details={
                        "caller_agent": caller.agent_identifier,
                        "service_id": service.service_id,
                        "target_org_id": str(service.organization_id),
                    },
                ))
                db.commit()
                raise ResolutionError(
                    f"No active cross-organization trust relationship exists between caller organization and target organization '{service.organization_id}'.",
                    code="CROSS_ORG_TRUST_REQUIRED",
                    status_code=403,
                )
        return

    # 4. PUBLIC_DISCOVERABLE: Allowed, zero-trust warning retained
    if visibility == ServiceVisibility.PUBLIC_DISCOVERABLE.value:
        return

    raise ResolutionError(f"Unknown service visibility setting '{visibility}'.", code="INVALID_VISIBILITY", status_code=400)
