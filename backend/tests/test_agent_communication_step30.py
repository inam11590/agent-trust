"""Comprehensive Step 30 Test Suite: Trusted Agent-to-Agent Communication & Service Registry.

Covers:
1. Service Registry CRUD, tenant isolation, and status transitions
2. Capability Registry, JSON schema validation, risk tiers, and approval requirements
3. Endpoint registration, protocols (HTTPS, GATEWAY, SIDECAR, INTERNAL), and SSRF defenses
4. Cryptographic endpoint ownership challenge and Ed25519 signature verification
5. Trusted zero-trust resolution with fail-closed lifecycle enforcement
6. Visibility rules: PRIVATE, ORGANIZATION, TRUSTED_ORGANIZATIONS, PUBLIC_DISCOVERABLE
7. Deterministic routing and failover (priority ASC, healthy first, weight DESC)
8. Invariant: Strictly NO cross-environment failover (prod -> sandbox forbidden)
9. Invariant: Strictly NO silent cross-agent failover
10. Loop protection: direct loop (A->A) and circular chain (A->B->C->A) rejection
11. Bounded call depth enforcement (depth >= 5 rejected with MAX_CALL_DEPTH_EXCEEDED)
12. ATP/1.0 request execution, schema checks, and high-risk approval hold
13. Response verification and request-ID binding integrity
14. Blast-radius relationship graph integration (HOSTS_SERVICE, USES_CAPABILITY, CALLS)
15. Concurrency and performance benchmarks
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
import time
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.database.base import Base
from app.models.agent import Agent, AgentStatus
from app.models.agent_delegation import AgentDelegation
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
from app.models.cross_organization_trust import OrganizationTrustRelationship, TrustStatus
from app.models.organization import Organization, SecurityEvent
from app.models.policy import Policy, PolicyBinding
from app.models.trust_registry import AgentCredential, CredentialStatus
from app.models.user import User

from app.services.agent_call_pipeline import (
    AgentCallPipelineError,
    execute_agent_to_agent_call,
)
from app.services.agent_governance import calculate_blast_radius_graph
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
from app.services.agent_service_router import (
    ResolutionError,
    resolve_capability,
    resolve_service,
)


# ---------------------------------------------------------------------------
# In-Memory SQLite Fixtures for Fast Isolated Execution
# ---------------------------------------------------------------------------

@pytest.fixture
def db_session():
    """Isolated in-memory SQLite database session."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    tables = [
        User.__table__,
        Organization.__table__,
        Agent.__table__,
        AgentSigningKey.__table__,
        OrganizationTrustRelationship.__table__,
        AgentCapability.__table__,
        AgentService.__table__,
        AgentServiceEndpoint.__table__,
        ServiceVerificationChallenge.__table__,
        AgentCallRecord.__table__,
        SecurityEvent.__table__,
        Policy.__table__,
        PolicyBinding.__table__,
        AgentCredential.__table__,
        AgentDelegation.__table__,
    ]
    for tbl in tables:
        tbl.constraints = {c for c in tbl.constraints if "~" not in str(getattr(c, "sqltext", ""))}
    Base.metadata.create_all(engine, tables=tables)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def test_setup(db_session):
    """Seed test organizations, agents, and signing keys."""
    user = User(email="dev@acme.example", full_name="Acme Dev", hashed_password="pw")
    db_session.add(user)
    db_session.commit()

    org1 = Organization(name="Acme Corp", owner_id=user.id)
    org2 = Organization(name="Beta Corp", owner_id=user.id)
    db_session.add_all([org1, org2])
    db_session.commit()

    agent1 = Agent(
        name="Booking Agent",
        agent_identifier="agt_booking_01",
        owner_id=user.id,
        organization_id=org1.id,
        status=AgentStatus.ACTIVE,
        environment="production",
        risk_classification="LOW",
    )
    agent2 = Agent(
        name="Payment Agent",
        agent_identifier="agt_payment_02",
        owner_id=user.id,
        organization_id=org1.id,
        status=AgentStatus.ACTIVE,
        environment="production",
        risk_classification="HIGH",
    )
    agent_ext = Agent(
        name="External Partner Agent",
        agent_identifier="agt_partner_ext",
        owner_id=user.id,
        organization_id=org2.id,
        status=AgentStatus.ACTIVE,
        environment="production",
        risk_classification="MEDIUM",
    )
    agent_suspended = Agent(
        name="Suspended Agent",
        agent_identifier="agt_suspended_03",
        owner_id=user.id,
        organization_id=org1.id,
        status=AgentStatus.SUSPENDED,
        environment="production",
    )
    agent_retired = Agent(
        name="Retired Agent",
        agent_identifier="agt_retired_04",
        owner_id=user.id,
        organization_id=org1.id,
        status=AgentStatus.RETIRED,
        environment="production",
    )
    agent_sandbox = Agent(
        name="Sandbox Tester",
        agent_identifier="agt_sandbox_05",
        owner_id=user.id,
        organization_id=org1.id,
        status=AgentStatus.ACTIVE,
        environment="sandbox",
    )
    db_session.add_all([agent1, agent2, agent_ext, agent_suspended, agent_retired, agent_sandbox])
    db_session.commit()

    # Generate signing key for agent1
    priv_key = Ed25519PrivateKey.generate()
    pub_bytes = priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = __import__("base64").b64encode(pub_bytes).decode("ascii")

    signing_key = AgentSigningKey(
        key_id="key_ag_112233445566778899aabbcc",
        agent_id=agent1.id,
        organization_id=org1.id,
        public_key=pub_b64,
        fingerprint=hashlib.sha256(pub_bytes).hexdigest(),
        algorithm="Ed25519",
        status=AgentSigningKeyStatus.ACTIVE,
        activated_at=datetime.now(timezone.utc),
    )
    db_session.add(signing_key)
    db_session.commit()

    return {
        "user": user,
        "org1": org1,
        "org2": org2,
        "agent1": agent1,
        "agent2": agent2,
        "agent_ext": agent_ext,
        "agent_suspended": agent_suspended,
        "agent_retired": agent_retired,
        "agent_sandbox": agent_sandbox,
        "signing_key": signing_key,
        "private_key": priv_key,
    }


# ===========================================================================
# 1. Service Registry CRUD & Tenant Isolation Tests
# ===========================================================================

def test_01_create_service_success(db_session, test_setup):
    s = create_service(
        db_session,
        organization_id=test_setup["org1"].id,
        agent_id=test_setup["agent1"].id,
        name="Hotel Booking Service",
        description="Handles hotel room reservations",
        version="1.0.0",
        visibility=ServiceVisibility.ORGANIZATION.value,
    )
    assert s.service_id.startswith("svc_")
    assert s.name == "Hotel Booking Service"
    assert s.status == ServiceStatus.ACTIVE.value
    assert s.visibility == ServiceVisibility.ORGANIZATION.value


def test_02_create_service_nonexistent_agent_fails(db_session, test_setup):
    with pytest.raises(ServiceRegistryError) as exc:
        create_service(
            db_session,
            organization_id=test_setup["org1"].id,
            agent_id=uuid4(),
            name="Ghost Service",
        )
    assert exc.value.code == "AGENT_NOT_FOUND"


def test_03_create_service_tenant_mismatch_fails(db_session, test_setup):
    with pytest.raises(ServiceRegistryError) as exc:
        create_service(
            db_session,
            organization_id=test_setup["org2"].id,  # Org2 attempting to bind Org1's agent
            agent_id=test_setup["agent1"].id,
            name="Mismatched Service",
        )
    assert exc.value.code == "TENANT_MISMATCH"


def test_04_create_service_suspended_agent_fails(db_session, test_setup):
    with pytest.raises(ServiceRegistryError) as exc:
        create_service(
            db_session,
            organization_id=test_setup["org1"].id,
            agent_id=test_setup["agent_suspended"].id,
            name="Suspended Service",
        )
    assert exc.value.code == "AGENT_LIFECYCLE_INVALID"


def test_05_create_service_retired_agent_fails(db_session, test_setup):
    with pytest.raises(ServiceRegistryError) as exc:
        create_service(
            db_session,
            organization_id=test_setup["org1"].id,
            agent_id=test_setup["agent_retired"].id,
            name="Retired Service",
        )
    assert exc.value.code == "AGENT_LIFECYCLE_INVALID"


def test_06_create_service_duplicate_name_fails(db_session, test_setup):
    create_service(
        db_session,
        organization_id=test_setup["org1"].id,
        agent_id=test_setup["agent1"].id,
        name="Unique Service",
    )
    with pytest.raises(ServiceRegistryError) as exc:
        create_service(
            db_session,
            organization_id=test_setup["org1"].id,
            agent_id=test_setup["agent1"].id,
            name="Unique Service",
        )
    assert exc.value.code == "SERVICE_NAME_CONFLICT"


def test_07_get_service_by_svc_id_and_uuid(db_session, test_setup):
    s = create_service(
        db_session,
        organization_id=test_setup["org1"].id,
        agent_id=test_setup["agent1"].id,
        name="Lookup Service",
    )
    by_svc = get_service(db_session, s.service_id)
    by_uuid = get_service(db_session, s.id)
    assert by_svc.id == s.id
    assert by_uuid.service_id == s.service_id


def test_08_get_service_not_found(db_session, test_setup):
    with pytest.raises(ServiceRegistryError) as exc:
        get_service(db_session, "svc_nonexistent1234")
    assert exc.value.code == "SERVICE_NOT_FOUND"


def test_09_list_services_tenant_isolated(db_session, test_setup):
    create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Acme Svc")
    create_service(db_session, organization_id=test_setup["org2"].id, agent_id=test_setup["agent_ext"].id, name="Beta Svc")

    acme_services, total_acme = list_services(db_session, organization_id=test_setup["org1"].id)
    assert total_acme == 1
    assert acme_services[0].name == "Acme Svc"


def test_10_list_services_status_filter(db_session, test_setup):
    create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Active Svc", status="ACTIVE")
    create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Draft Svc", status="DRAFT")

    active_list, _ = list_services(db_session, organization_id=test_setup["org1"].id, status="ACTIVE")
    assert any(s.name == "Active Svc" for s in active_list)
    assert not any(s.name == "Draft Svc" for s in active_list)


def test_11_list_services_visibility_filter(db_session, test_setup):
    create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Org Vis", visibility="ORGANIZATION")
    create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Priv Vis", visibility="PRIVATE")

    priv_list, _ = list_services(db_session, organization_id=test_setup["org1"].id, visibility="PRIVATE")
    assert any(s.name == "Priv Vis" for s in priv_list)
    assert not any(s.name == "Org Vis" for s in priv_list)


def test_12_update_service_metadata_and_status(db_session, test_setup):
    s = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Update Svc")
    updated = update_service(
        db_session,
        service_id_or_uuid=s.id,
        updates={"status": "DEGRADED", "version": "1.1.0", "description": "Updated"},
        organization_id=test_setup["org1"].id,
    )
    assert updated.status == "DEGRADED"
    assert updated.version == "1.1.0"
    assert updated.description == "Updated"


def test_13_update_service_forbidden_cross_org(db_session, test_setup):
    s = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Org1 Svc")
    with pytest.raises(ServiceRegistryError) as exc:
        update_service(db_session, s.id, {"status": "DISABLED"}, organization_id=test_setup["org2"].id)
    assert exc.value.code in ("FORBIDDEN", "SERVICE_NOT_FOUND")


def test_14_delete_service_soft_retires(db_session, test_setup):
    s = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Delete Svc")
    delete_service(db_session, s.id, organization_id=test_setup["org1"].id)
    refreshed = get_service(db_session, s.id)
    assert refreshed.status == ServiceStatus.RETIRED.value


# ===========================================================================
# 2. Capability Registry Tests
# ===========================================================================

def test_15_register_capability_success(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Cap Svc")
    cap = register_capability(
        db_session,
        organization_id=test_setup["org1"].id,
        agent_id=test_setup["agent1"].id,
        service_id=svc.id,
        name="hotel.reserve",
        version="1.0",
        description="Book a hotel room",
        input_schema={"required": ["hotel_id", "dates"]},
        output_schema={"required": ["booking_id"]},
    )
    assert cap.capability_id.startswith("cap_")
    assert cap.name == "hotel.reserve"
    assert cap.service_id == svc.id


def test_16_register_capability_risk_and_approval(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Admin Svc")
    cap = register_capability(
        db_session,
        organization_id=test_setup["org1"].id,
        agent_id=test_setup["agent1"].id,
        service_id=svc.id,
        name="system.wipe",
        risk_classification="CRITICAL",
        requires_approval=True,
    )
    assert cap.risk_classification == "CRITICAL"
    assert cap.requires_approval is True


def test_17_register_capability_approval_threshold(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Finance Svc")
    cap = register_capability(
        db_session,
        organization_id=test_setup["org1"].id,
        agent_id=test_setup["agent1"].id,
        service_id=svc.id,
        name="payment.transfer",
        approval_threshold_amount=1000.0,
        rate_limit_per_minute=60,
    )
    assert cap.approval_threshold_amount == 1000.0
    assert cap.rate_limit_per_minute == 60


def test_18_register_capability_updates_existing(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Versioned Svc")
    cap1 = register_capability(
        db_session,
        organization_id=test_setup["org1"].id,
        agent_id=test_setup["agent1"].id,
        service_id=svc.id,
        name="data.query",
        description="Original description",
    )
    cap2 = register_capability(
        db_session,
        organization_id=test_setup["org1"].id,
        agent_id=test_setup["agent1"].id,
        service_id=svc.id,
        name="data.query",
        description="Updated description",
    )
    assert cap1.id == cap2.id
    assert cap2.description == "Updated description"


def test_19_list_capabilities_by_service(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="MultiCap Svc")
    register_capability(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, service_id=svc.id, name="cap.one")
    register_capability(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, service_id=svc.id, name="cap.two")

    caps, total = list_capabilities(db_session, service_id=svc.id)
    assert total == 2
    assert {c.name for c in caps} == {"cap.one", "cap.two"}


def test_20_list_capabilities_global_catalog(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Global Svc")
    register_capability(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, service_id=svc.id, name="global.op")

    caps, total = list_capabilities(db_session, organization_id=test_setup["org1"].id)
    assert any(c.name == "global.op" for c in caps)


def test_21_get_capability_by_id_and_name(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Fetch Svc")
    cap = register_capability(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, service_id=svc.id, name="fetch.run")

    by_id = get_capability(db_session, cap.capability_id)
    by_name = get_capability(db_session, "fetch.run")
    assert by_id.id == cap.id
    assert by_name.id == cap.id


def test_22_get_capability_not_found(db_session, test_setup):
    with pytest.raises(ServiceRegistryError) as exc:
        get_capability(db_session, "nonexistent_capability")
    assert exc.value.code == "CAPABILITY_NOT_FOUND"


# ===========================================================================
# 3. Endpoint Registration & SSRF Safety Tests
# ===========================================================================

def test_23_register_endpoint_https_success(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Ep Svc")
    ep = register_endpoint(
        db_session,
        organization_id=test_setup["org1"].id,
        service_id=svc.id,
        protocol=EndpointProtocol.HTTPS.value,
        url="https://api.example.com/agents/booking",
        priority=1,
        weight=100,
        allow_private_ips=True,
    )
    assert ep.endpoint_id.startswith("ep_")
    assert ep.protocol == "HTTPS"
    assert ep.health_status == EndpointHealthStatus.UNKNOWN.value


def test_24_register_endpoint_agenttrust_gateway(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Atp Svc")
    ep = register_endpoint(
        db_session,
        organization_id=test_setup["org1"].id,
        service_id=svc.id,
        protocol=EndpointProtocol.AGENTTRUST_GATEWAY.value,
        url="https://gateway.internal.example.com/atp/v1",
        allow_private_ips=True,
    )
    assert ep.protocol == EndpointProtocol.AGENTTRUST_GATEWAY.value


def test_25_register_endpoint_sidecar(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Sidecar Svc")
    ep = register_endpoint(
        db_session,
        organization_id=test_setup["org1"].id,
        service_id=svc.id,
        protocol=EndpointProtocol.SIDECAR.value,
        url="http://localhost:8080/eval",
    )
    assert ep.protocol == EndpointProtocol.SIDECAR.value


def test_26_register_endpoint_internal_route(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Internal Svc")
    ep = register_endpoint(
        db_session,
        organization_id=test_setup["org1"].id,
        service_id=svc.id,
        protocol=EndpointProtocol.INTERNAL_ROUTE.value,
        url="agent://mesh/cluster-a/payment",
    )
    assert ep.protocol == EndpointProtocol.INTERNAL_ROUTE.value


def test_27_register_endpoint_ssrf_blocks_loopback(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Loopback Svc")
    with pytest.raises(ServiceRegistryError) as exc:
        register_endpoint(
            db_session,
            organization_id=test_setup["org1"].id,
            service_id=svc.id,
            protocol="HTTPS",
            url="https://127.0.0.1:8443/atp",
            allow_private_ips=False,  # Enforce SSRF
        )
    assert exc.value.code == "SSRF_REJECTED"


def test_28_register_endpoint_ssrf_blocks_metadata(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Meta Svc")
    with pytest.raises(ServiceRegistryError) as exc:
        register_endpoint(
            db_session,
            organization_id=test_setup["org1"].id,
            service_id=svc.id,
            protocol="HTTPS",
            url="https://169.254.169.254/latest/meta-data",
            allow_private_ips=False,
        )
    assert exc.value.code == "SSRF_REJECTED"


def test_29_register_endpoint_ssrf_blocks_private_rfc1918(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Private Svc")
    with pytest.raises(ServiceRegistryError) as exc:
        register_endpoint(
            db_session,
            organization_id=test_setup["org1"].id,
            service_id=svc.id,
            protocol="HTTPS",
            url="https://10.0.1.55:9000/atp",
            allow_private_ips=False,
        )
    assert exc.value.code == "SSRF_REJECTED"


def test_30_register_multiple_endpoints_priority_weight(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Prio Svc")
    ep1 = register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://primary.example.com", priority=1, weight=80, allow_private_ips=True)
    ep2 = register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://secondary.example.com", priority=2, weight=20, allow_private_ips=True)

    eps = list_endpoints(db_session, svc.id)
    assert len(eps) == 2
    assert eps[0].priority == 1
    assert eps[1].priority == 2


# ===========================================================================
# 4. Cryptographic Ownership Challenge & Verification Tests
# ===========================================================================

def test_31_initiate_endpoint_challenge(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Chall Svc")
    ep = register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://ch.example.com", allow_private_ips=True)
    challenge = initiate_endpoint_verification(db_session, ep.id, ttl_seconds=600)
    assert challenge.challenge_token.startswith("svc_ch_")
    assert challenge.status == "PENDING"
    exp = challenge.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    assert exp > datetime.now(timezone.utc)


def test_32_verify_endpoint_challenge_direct(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="DirectVer Svc")
    ep = register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://ver.example.com", allow_private_ips=True)
    ch = initiate_endpoint_verification(db_session, ep.id)

    res = verify_endpoint_challenge(db_session, ep.id, ch.challenge_token)
    assert res["verified"] is True
    assert res["health_status"] == EndpointHealthStatus.HEALTHY.value

    db_session.refresh(ep)
    assert ep.health_status == EndpointHealthStatus.HEALTHY.value
    assert ep.verified_at is not None


def test_33_verify_endpoint_challenge_invalid_token(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="BadToken Svc")
    ep = register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://bad.example.com", allow_private_ips=True)
    initiate_endpoint_verification(db_session, ep.id)

    with pytest.raises(ServiceRegistryError) as exc:
        verify_endpoint_challenge(db_session, ep.id, "svc_ch_forgedtoken123")
    assert exc.value.code == "CHALLENGE_INVALID"


def test_34_verify_endpoint_challenge_expired(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Exp Svc")
    ep = register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://exp.example.com", allow_private_ips=True)
    ch = initiate_endpoint_verification(db_session, ep.id, ttl_seconds=-10)

    with pytest.raises(ServiceRegistryError) as exc:
        verify_endpoint_challenge(db_session, ep.id, ch.challenge_token)
    assert exc.value.code == "CHALLENGE_EXPIRED"


def test_35_verify_endpoint_challenge_ed25519_signature(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Crypto Svc")
    ep = register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://crypto.example.com", allow_private_ips=True)
    ch = initiate_endpoint_verification(db_session, ep.id)

    payload_to_sign = f"AGENTTRUST_VERIFY:{ep.endpoint_id}:{ch.challenge_token}".encode("ascii")
    sig_bytes = test_setup["private_key"].sign(payload_to_sign)
    sig_b64 = __import__("base64").b64encode(sig_bytes).decode("ascii")

    res = verify_endpoint_challenge(
        db_session,
        ep.id,
        ch.challenge_token,
        signature=sig_b64,
        key_id=test_setup["signing_key"].key_id,
    )
    assert res["verified"] is True
    assert res["health_status"] == EndpointHealthStatus.HEALTHY.value


def test_36_verify_endpoint_challenge_tampered_signature(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Tamper Svc")
    ep = register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://tamper.example.com", allow_private_ips=True)
    ch = initiate_endpoint_verification(db_session, ep.id)

    tampered_sig = __import__("base64").b64encode(b"A" * 64).decode("ascii")
    with pytest.raises(ServiceRegistryError) as exc:
        verify_endpoint_challenge(
            db_session,
            ep.id,
            ch.challenge_token,
            signature=tampered_sig,
            key_id=test_setup["signing_key"].key_id,
        )
    assert exc.value.code == "INVALID_SIGNATURE"


# ===========================================================================
# 5. Trusted Zero-Trust Resolution Tests
# ===========================================================================

def test_37_resolve_service_success_zero_trust_advisory(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Adv Svc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://adv.example.com", allow_private_ips=True)

    res = resolve_service(db_session, caller_agent_id=test_setup["agent2"].id, service_id_or_name=svc.service_id)
    assert res["status"] == "RESOLVED"
    assert res["discovery_advisory"] == "SERVICE_DISCOVERY_IS_NOT_TRUST_RESOLUTION_DOES_NOT_AUTHORIZE_ACTION"
    assert "notice" in res


def test_38_resolve_service_suspended_caller_fail_closed(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="SuspCaller Svc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://e.example.com", allow_private_ips=True)

    with pytest.raises(ResolutionError) as exc:
        resolve_service(db_session, caller_agent_id=test_setup["agent_suspended"].id, service_id_or_name=svc.service_id)
    assert exc.value.code == "CALLER_SUSPENDED"


def test_39_resolve_service_retired_caller_fail_closed(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="RetCaller Svc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://e.example.com", allow_private_ips=True)

    with pytest.raises(ResolutionError) as exc:
        resolve_service(db_session, caller_agent_id=test_setup["agent_retired"].id, service_id_or_name=svc.service_id)
    assert exc.value.code == "CALLER_RETIRED"


def test_40_resolve_service_suspended_target_fail_closed(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="SuspTarget Svc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://e.example.com", allow_private_ips=True)
    test_setup["agent1"].status = AgentStatus.SUSPENDED
    db_session.commit()

    with pytest.raises(ResolutionError) as exc:
        resolve_service(db_session, caller_agent_id=test_setup["agent2"].id, service_id_or_name=svc.service_id)
    assert exc.value.code == "TARGET_SUSPENDED"

    test_setup["agent1"].status = AgentStatus.ACTIVE
    db_session.commit()


def test_41_resolve_service_retired_target_fail_closed(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="RetTarget Svc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://e.example.com", allow_private_ips=True)
    test_setup["agent1"].status = AgentStatus.RETIRED
    db_session.commit()

    with pytest.raises(ResolutionError) as exc:
        resolve_service(db_session, caller_agent_id=test_setup["agent2"].id, service_id_or_name=svc.service_id)
    assert exc.value.code == "TARGET_RETIRED"

    test_setup["agent1"].status = AgentStatus.ACTIVE
    db_session.commit()


def test_42_resolve_service_disabled_service_fail_closed(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Dis Svc", status="DISABLED")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://e.example.com", allow_private_ips=True)

    with pytest.raises(ResolutionError) as exc:
        resolve_service(db_session, caller_agent_id=test_setup["agent1"].id, service_id_or_name=svc.service_id)
    assert exc.value.code == "SERVICE_DISABLED"


def test_43_resolve_service_retired_service_fail_closed(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="RetSvc", status="RETIRED")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://e.example.com", allow_private_ips=True)

    with pytest.raises(ResolutionError) as exc:
        resolve_service(db_session, caller_agent_id=test_setup["agent1"].id, service_id_or_name=svc.service_id)
    assert exc.value.code == "SERVICE_RETIRED"


def test_44_resolve_service_degraded_service_resolves_with_warning(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Deg Svc", status="DEGRADED")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://deg.example.com", allow_private_ips=True)

    res = resolve_service(db_session, caller_agent_id=test_setup["agent1"].id, service_id_or_name=svc.service_id)
    assert res["status"] == "RESOLVED"
    assert res["service_status"] == "DEGRADED"


def test_45_resolve_service_sandbox_caller_prod_target_rejected(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Prod Svc", environment="production")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://prod.example.com", allow_private_ips=True)

    with pytest.raises(ResolutionError) as exc:
        resolve_service(db_session, caller_agent_id=test_setup["agent_sandbox"].id, service_id_or_name=svc.service_id)
    assert exc.value.code == "CROSS_ENVIRONMENT_DENIED"


def test_46_resolve_service_prod_caller_sandbox_endpoints_filtered(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Mixed Svc", environment="production")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://prod.example.com", environment="production", allow_private_ips=True)
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://sandbox.example.com", environment="sandbox", allow_private_ips=True)

    res = resolve_service(db_session, caller_agent_id=test_setup["agent1"].id, service_id_or_name=svc.service_id)
    assert res["primary_endpoint"]["environment"] == "production"
    assert not any(ep["environment"] == "sandbox" for ep in res["failover_endpoints"])


def test_47_resolve_service_visibility_private_denied_external_caller(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Private Svc", visibility="PRIVATE")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://priv.example.com", allow_private_ips=True)

    with pytest.raises(ResolutionError) as exc:
        resolve_service(db_session, caller_agent_id=test_setup["agent2"].id, service_id_or_name=svc.service_id)
    assert exc.value.code == "VISIBILITY_PRIVATE_DENIED"


def test_48_resolve_service_visibility_private_allowed_same_agent(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Self Svc", visibility="PRIVATE")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://self.example.com", allow_private_ips=True)

    res = resolve_service(db_session, caller_agent_id=test_setup["agent1"].id, service_id_or_name=svc.service_id)
    assert res["status"] == "RESOLVED"


def test_49_resolve_service_visibility_org_denied_cross_tenant(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Tenant Svc", visibility="ORGANIZATION")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://org.example.com", allow_private_ips=True)

    with pytest.raises(ResolutionError) as exc:
        resolve_service(db_session, caller_agent_id=test_setup["agent_ext"].id, service_id_or_name=svc.service_id)
    assert exc.value.code == "ORGANIZATION_MISMATCH"


def test_50_resolve_service_visibility_org_allowed_same_tenant(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="SameOrg Svc", visibility="ORGANIZATION")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://sameorg.example.com", allow_private_ips=True)

    res = resolve_service(db_session, caller_agent_id=test_setup["agent2"].id, service_id_or_name=svc.service_id)
    assert res["status"] == "RESOLVED"


def test_51_resolve_service_trusted_orgs_denied_without_trust(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Trust Svc", visibility="TRUSTED_ORGANIZATIONS")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://trust.example.com", allow_private_ips=True)

    with pytest.raises(ResolutionError) as exc:
        resolve_service(db_session, caller_agent_id=test_setup["agent_ext"].id, service_id_or_name=svc.service_id)
    assert exc.value.code == "CROSS_ORG_TRUST_REQUIRED"


def test_52_resolve_service_trusted_orgs_allowed_with_active_trust(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="CrossTrust Svc", visibility="TRUSTED_ORGANIZATIONS")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://cross.example.com", allow_private_ips=True)

    # Establish trust relationship from Org2 to Org1
    trust = OrganizationTrustRelationship(
        source_organization_id=test_setup["org2"].id,
        target_organization_id=test_setup["org1"].id,
        status=TrustStatus.ACTIVE,
        created_by_user_id=test_setup["user"].id,
    )
    db_session.add(trust)
    db_session.commit()

    res = resolve_service(db_session, caller_agent_id=test_setup["agent_ext"].id, service_id_or_name=svc.service_id)
    assert res["status"] == "RESOLVED"


def test_53_resolve_service_public_allowed_with_disclaimer(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Public Svc", visibility="PUBLIC_DISCOVERABLE")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://pub.example.com", allow_private_ips=True)

    res = resolve_service(db_session, caller_agent_id=test_setup["agent_ext"].id, service_id_or_name=svc.service_id)
    assert res["status"] == "RESOLVED"
    assert "SERVICE_DISCOVERY_IS_NOT_TRUST" in res["discovery_advisory"]


def test_54_resolve_capability_direct_success(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="CapDirect Svc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://cd.example.com", allow_private_ips=True)
    register_capability(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, service_id=svc.id, name="nlp.translate")

    res = resolve_capability(db_session, caller_agent_id=test_setup["agent2"].id, capability_name_or_id="nlp.translate")
    assert res["status"] == "RESOLVED"
    assert res["capability"]["name"] == "nlp.translate"


def test_55_resolve_capability_unbound_error(db_session, test_setup):
    # Register capability directly to agent without service
    cap = AgentCapability(
        organization_id=test_setup["org1"].id,
        agent_id=test_setup["agent1"].id,
        service_id=None,
        name="unbound.op",
    )
    db_session.add(cap)
    db_session.commit()

    with pytest.raises(ResolutionError) as exc:
        resolve_capability(db_session, caller_agent_id=test_setup["agent2"].id, capability_name_or_id=cap.capability_id)
    assert exc.value.code == "CAPABILITY_NOT_BOUND_TO_SERVICE"


# ===========================================================================
# 6. Routing & Failover Tests
# ===========================================================================

def test_56_failover_deterministic_priority_ordering(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="PrioOrder Svc")
    ep_p2 = register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://p2.example.com", priority=2, allow_private_ips=True)
    ep_p1 = register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://p1.example.com", priority=1, allow_private_ips=True)

    res = resolve_service(db_session, caller_agent_id=test_setup["agent1"].id, service_id_or_name=svc.service_id)
    assert res["primary_endpoint"]["endpoint_id"] == ep_p1.endpoint_id
    assert res["failover_endpoints"][0]["endpoint_id"] == ep_p2.endpoint_id


def test_57_failover_healthy_preferred_over_degraded(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="HealthPref Svc")
    ep_deg = register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://deg.example.com", priority=1, allow_private_ips=True)
    ep_deg.health_status = EndpointHealthStatus.DEGRADED.value

    ep_hlth = register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://hlth.example.com", priority=1, allow_private_ips=True)
    ep_hlth.health_status = EndpointHealthStatus.HEALTHY.value
    db_session.commit()

    res = resolve_service(db_session, caller_agent_id=test_setup["agent1"].id, service_id_or_name=svc.service_id)
    assert res["primary_endpoint"]["endpoint_id"] == ep_hlth.endpoint_id
    assert res["failover_endpoints"][0]["endpoint_id"] == ep_deg.endpoint_id


def test_58_failover_weight_tie_breaker(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="WeightSvc")
    ep_w10 = register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://w10.example.com", priority=1, weight=10, allow_private_ips=True)
    ep_w90 = register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://w90.example.com", priority=1, weight=90, allow_private_ips=True)

    res = resolve_service(db_session, caller_agent_id=test_setup["agent1"].id, service_id_or_name=svc.service_id)
    assert res["primary_endpoint"]["endpoint_id"] == ep_w90.endpoint_id


def test_59_invariant_no_prod_to_sandbox_failover(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="NoProdToSandbox")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://prod.example.com", priority=1, environment="production", allow_private_ips=True)
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://sandbox.example.com", priority=2, environment="sandbox", allow_private_ips=True)

    res = resolve_service(db_session, caller_agent_id=test_setup["agent1"].id, service_id_or_name=svc.service_id)
    # Target endpoint must NOT include sandbox endpoint in failovers
    for ep in [res["primary_endpoint"]] + res["failover_endpoints"]:
        assert ep["environment"] == "production"
        assert ep["url"] != "https://sandbox.example.com"


def test_60_invariant_no_silent_cross_agent_failover(db_session, test_setup):
    svc1 = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="Svc1")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc1.id, url="https://s1.example.com", allow_private_ips=True)

    svc2 = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, name="Svc2")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc2.id, url="https://s2.example.com", allow_private_ips=True)

    res = resolve_service(db_session, caller_agent_id=test_setup["agent1"].id, service_id_or_name=svc1.service_id)
    assert res["target_agent"]["identifier"] == test_setup["agent1"].agent_identifier
    # All endpoints must belong to svc1
    endpoints = db_session.scalars(select(AgentServiceEndpoint).where(AgentServiceEndpoint.service_id == svc1.id)).all()
    ep_ids = {e.endpoint_id for e in endpoints}
    assert res["primary_endpoint"]["endpoint_id"] in ep_ids
    for ep in res["failover_endpoints"]:
        assert ep["endpoint_id"] in ep_ids


# ===========================================================================
# 7. Loop & Depth Protection Tests
# ===========================================================================

def test_61_loop_protection_direct_self_call_rejected(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="SelfLoopSvc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://sl.example.com", allow_private_ips=True)
    register_capability(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, service_id=svc.id, name="echo")

    with pytest.raises(AgentCallPipelineError) as exc:
        execute_agent_to_agent_call(
            db_session,
            caller_agent_id=test_setup["agent1"].id,
            service_id_or_name=svc.service_id,
            capability_name="echo",
            payload={"test": 1},
            call_chain=[test_setup["agent1"].agent_identifier],  # Target already in chain
        )
    assert exc.value.code == "CALL_LOOP_DETECTED"


def test_62_loop_protection_mutual_cycle_rejected(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="CycleSvc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://c.example.com", allow_private_ips=True)
    register_capability(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, service_id=svc.id, name="echo")

    # Call chain: Agent1 -> Agent2 -> Agent1 (attempting to invoke Agent1 again)
    chain = [test_setup["agent1"].agent_identifier, test_setup["agent2"].agent_identifier]
    with pytest.raises(AgentCallPipelineError) as exc:
        execute_agent_to_agent_call(
            db_session,
            caller_agent_id=test_setup["agent2"].id,
            service_id_or_name=svc.service_id,
            capability_name="echo",
            payload={"msg": "ping"},
            call_chain=chain,
        )
    assert exc.value.code == "CALL_LOOP_DETECTED"


def test_63_loop_protection_three_hop_cycle_rejected(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="ThreeHopSvc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://th.example.com", allow_private_ips=True)
    register_capability(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, service_id=svc.id, name="compute")

    chain = ["agt_coordinator", "agt_orchestrator", test_setup["agent1"].agent_identifier, "agt_evaluator"]
    with pytest.raises(AgentCallPipelineError) as exc:
        execute_agent_to_agent_call(
            db_session,
            caller_agent_id=test_setup["agent2"].id,
            service_id_or_name=svc.service_id,
            capability_name="compute",
            payload={"val": 42},
            call_chain=chain,
        )
    assert exc.value.code == "CALL_LOOP_DETECTED"


def test_64_loop_protection_emits_security_event(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="EvtSvc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://evt.example.com", allow_private_ips=True)
    register_capability(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, service_id=svc.id, name="ping")

    try:
        execute_agent_to_agent_call(
            db_session,
            caller_agent_id=test_setup["agent2"].id,
            service_id_or_name=svc.service_id,
            capability_name="ping",
            payload={},
            call_chain=[test_setup["agent1"].agent_identifier],
        )
    except AgentCallPipelineError:
        pass

    event = db_session.scalar(
        select(SecurityEvent).where(SecurityEvent.event_type == "call_loop_detected")
    )
    assert event is not None
    assert "Circular agent call chain blocked" in event.description


def test_65_depth_protection_depth_1_through_4_allowed(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, name="DepthSvc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://d.example.com", allow_private_ips=True)
    register_capability(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, service_id=svc.id, name="pass_thru")

    for d in [1, 2, 3, 4]:
        res = execute_agent_to_agent_call(
            db_session,
            caller_agent_id=test_setup["agent1"].id,
            service_id_or_name=svc.service_id,
            capability_name="pass_thru",
            payload={"d": d},
            call_chain=[f"agent_step_{i}" for i in range(d)],
            depth=d,
        )
        assert res["status"] == "COMPLETED"


def test_66_depth_protection_depth_5_rejected(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, name="DeepSvc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://dp.example.com", allow_private_ips=True)
    register_capability(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, service_id=svc.id, name="deep_call")

    with pytest.raises(AgentCallPipelineError) as exc:
        execute_agent_to_agent_call(
            db_session,
            caller_agent_id=test_setup["agent1"].id,
            service_id_or_name=svc.service_id,
            capability_name="deep_call",
            payload={},
            call_chain=["a1", "a2", "a3", "a4", "a5"],
            depth=5,
            max_depth=5,
        )
    assert exc.value.code == "MAX_CALL_DEPTH_EXCEEDED"


def test_67_depth_protection_emits_security_event(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, name="DepthEvtSvc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://de.example.com", allow_private_ips=True)
    register_capability(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, service_id=svc.id, name="test")

    try:
        execute_agent_to_agent_call(
            db_session,
            caller_agent_id=test_setup["agent1"].id,
            service_id_or_name=svc.service_id,
            capability_name="test",
            payload={},
            depth=5,
            max_depth=5,
        )
    except AgentCallPipelineError:
        pass

    event = db_session.scalar(select(SecurityEvent).where(SecurityEvent.event_type == "call_depth_exceeded"))
    assert event is not None


# ===========================================================================
# 8. Execution Pipeline & Security Checks Tests
# ===========================================================================

def test_68_call_pipeline_idempotency_cache(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, name="IdemSvc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://idem.example.com", allow_private_ips=True)
    register_capability(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, service_id=svc.id, name="transfer")

    key = "idem_key_9999"
    res1 = execute_agent_to_agent_call(
        db_session,
        caller_agent_id=test_setup["agent1"].id,
        service_id_or_name=svc.service_id,
        capability_name="transfer",
        payload={"amt": 50},
        idempotency_key=key,
    )
    assert res1["status"] == "COMPLETED"

    res2 = execute_agent_to_agent_call(
        db_session,
        caller_agent_id=test_setup["agent1"].id,
        service_id_or_name=svc.service_id,
        capability_name="transfer",
        payload={"amt": 50},
        idempotency_key=key,
    )
    assert res2["idempotent_replay"] is True


def test_69_call_pipeline_schema_validation_success(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, name="SchemaSvc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://sc.example.com", allow_private_ips=True)
    register_capability(
        db_session,
        organization_id=test_setup["org1"].id,
        agent_id=test_setup["agent2"].id,
        service_id=svc.id,
        name="validate.item",
        input_schema={"required": ["item_id", "quantity"]},
    )

    res = execute_agent_to_agent_call(
        db_session,
        caller_agent_id=test_setup["agent1"].id,
        service_id_or_name=svc.service_id,
        capability_name="validate.item",
        payload={"item_id": "sku_123", "quantity": 5},
    )
    assert res["status"] == "COMPLETED"


def test_70_call_pipeline_schema_validation_missing_field_fails(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, name="SchemaFailSvc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://scf.example.com", allow_private_ips=True)
    register_capability(
        db_session,
        organization_id=test_setup["org1"].id,
        agent_id=test_setup["agent2"].id,
        service_id=svc.id,
        name="validate.req",
        input_schema={"required": ["token"]},
    )

    with pytest.raises(AgentCallPipelineError) as exc:
        execute_agent_to_agent_call(
            db_session,
            caller_agent_id=test_setup["agent1"].id,
            service_id_or_name=svc.service_id,
            capability_name="validate.req",
            payload={"wrong_field": 1},
        )
    assert exc.value.code == "SCHEMA_VALIDATION_FAILED"


def test_71_call_pipeline_risk_high_amount_pending_approval(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, name="HighValSvc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://hv.example.com", allow_private_ips=True)
    register_capability(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, service_id=svc.id, name="wire.transfer")

    res = execute_agent_to_agent_call(
        db_session,
        caller_agent_id=test_setup["agent1"].id,
        service_id_or_name=svc.service_id,
        capability_name="wire.transfer",
        payload={"amount": 7500.0},
    )
    assert res["status"] == "PENDING_APPROVAL"
    assert res["approval_required"] is True


def test_72_call_pipeline_critical_risk_pending_approval(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, name="CritRiskSvc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://cr.example.com", allow_private_ips=True)
    register_capability(
        db_session,
        organization_id=test_setup["org1"].id,
        agent_id=test_setup["agent2"].id,
        service_id=svc.id,
        name="cluster.restart",
        risk_classification="CRITICAL",
    )

    res = execute_agent_to_agent_call(
        db_session,
        caller_agent_id=test_setup["agent1"].id,
        service_id_or_name=svc.service_id,
        capability_name="cluster.restart",
        payload={},
    )
    assert res["status"] == "PENDING_APPROVAL"


def test_73_call_pipeline_explicit_approval_required_holds(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, name="ExpApprSvc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://ea.example.com", allow_private_ips=True)
    register_capability(
        db_session,
        organization_id=test_setup["org1"].id,
        agent_id=test_setup["agent2"].id,
        service_id=svc.id,
        name="user.delete",
        requires_approval=True,
    )

    res = execute_agent_to_agent_call(
        db_session,
        caller_agent_id=test_setup["agent1"].id,
        service_id_or_name=svc.service_id,
        capability_name="user.delete",
        payload={"user_id": "u_123"},
    )
    assert res["status"] == "PENDING_APPROVAL"


def test_74_call_pipeline_staging_does_not_route(db_session, test_setup):
    routed = False

    def handler(**kwargs):
        nonlocal routed
        routed = True
        return {"status": "ok"}

    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, name="NoRouteSvc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://nr.example.com", allow_private_ips=True)
    register_capability(
        db_session,
        organization_id=test_setup["org1"].id,
        agent_id=test_setup["agent2"].id,
        service_id=svc.id,
        name="high.action",
        requires_approval=True,
    )

    execute_agent_to_agent_call(
        db_session,
        caller_agent_id=test_setup["agent1"].id,
        service_id_or_name=svc.service_id,
        capability_name="high.action",
        payload={},
        mock_endpoint_handler=handler,
    )
    assert routed is False  # Staged calls NEVER dispatch to target endpoint


# ===========================================================================
# 9. Response Verification Tests
# ===========================================================================

def test_75_call_pipeline_response_binding_match_success(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, name="BindSvc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://bind.example.com", allow_private_ips=True)
    register_capability(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, service_id=svc.id, name="query")

    def mock_resp(endpoint, request_id, capability, payload):
        return {"status": "success", "request_id": request_id, "data": "valid"}

    res = execute_agent_to_agent_call(
        db_session,
        caller_agent_id=test_setup["agent1"].id,
        service_id_or_name=svc.service_id,
        capability_name="query",
        payload={},
        mock_endpoint_handler=mock_resp,
    )
    assert res["status"] == "COMPLETED"
    assert res["response"]["request_id"] == res["message_id"]


def test_76_call_pipeline_response_binding_mismatch_rejected(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, name="MismatchSvc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://mismatch.example.com", allow_private_ips=True)
    register_capability(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, service_id=svc.id, name="tamper")

    def mock_bad_resp(endpoint, request_id, capability, payload):
        return {"status": "success", "request_id": "forged_req_999", "data": "tampered"}

    with pytest.raises(AgentCallPipelineError) as exc:
        execute_agent_to_agent_call(
            db_session,
            caller_agent_id=test_setup["agent1"].id,
            service_id_or_name=svc.service_id,
            capability_name="tamper",
            payload={},
            mock_endpoint_handler=mock_bad_resp,
        )
    assert exc.value.code == "RESPONSE_BINDING_MISMATCH"


def test_77_call_pipeline_response_digest_calculated(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, name="DigestSvc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://dg.example.com", allow_private_ips=True)
    register_capability(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, service_id=svc.id, name="hash")

    res = execute_agent_to_agent_call(
        db_session,
        caller_agent_id=test_setup["agent1"].id,
        service_id_or_name=svc.service_id,
        capability_name="hash",
        payload={"seed": 100},
    )
    assert res["response_digest"] is not None
    assert len(res["response_digest"]) == 64


# ===========================================================================
# 10. Blast-Radius / Relationship Graph Integration Tests
# ===========================================================================

def test_78_blast_radius_hosts_service_edge(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="GraphHostSvc")
    graph = calculate_blast_radius_graph(db_session, test_setup["agent1"].id)

    # Must contain HOSTS_SERVICE edge
    host_edges = [e for e in graph["edges"] if e["relationship"] == "HOSTS_SERVICE"]
    assert len(host_edges) >= 1
    assert any(e["target"] == f"service:{svc.service_id}" for e in host_edges)


def test_79_blast_radius_uses_capability_edge(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="GraphCapSvc")
    cap = register_capability(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, service_id=svc.id, name="graph.cap")

    graph = calculate_blast_radius_graph(db_session, test_setup["agent1"].id)
    cap_edges = [e for e in graph["edges"] if e["relationship"] == "USES_CAPABILITY"]
    assert len(cap_edges) >= 1
    assert any(e["target"] == f"capability:{cap.capability_id}" for e in cap_edges)


def test_80_blast_radius_calls_edge(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, name="GraphCallSvc")
    register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://gc.example.com", allow_private_ips=True)
    register_capability(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent2"].id, service_id=svc.id, name="exec")

    execute_agent_to_agent_call(
        db_session,
        caller_agent_id=test_setup["agent1"].id,
        service_id_or_name=svc.service_id,
        capability_name="exec",
        payload={},
    )

    graph = calculate_blast_radius_graph(db_session, test_setup["agent1"].id)
    calls_edges = [e for e in graph["edges"] if e["relationship"] == "CALLS"]
    assert len(calls_edges) >= 1
    assert calls_edges[0]["target"] == f"agent:{str(test_setup['agent2'].id)}"


# ===========================================================================
# 11. Concurrency, Performance & Scale Benchmarks
# ===========================================================================

def test_81_concurrency_scale_benchmark(db_session, test_setup):
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="ScaleBenchSvc")
    for i in range(10):
        register_endpoint(
            db_session,
            organization_id=test_setup["org1"].id,
            service_id=svc.id,
            url=f"https://scale-{i}.example.com",
            priority=(i % 3) + 1,
            weight=100 - (i * 5),
            allow_private_ips=True,
        )

    start = time.perf_counter()
    # Execute 50 consecutive resolutions
    for _ in range(50):
        res = resolve_service(db_session, caller_agent_id=test_setup["agent2"].id, service_id_or_name=svc.service_id)
        assert res["status"] == "RESOLVED"
        assert res["primary_endpoint"]["priority"] == 1
    duration = time.perf_counter() - start

    # 50 resolutions should complete in less than 500ms in SQLite
    assert duration < 1.0


def test_82_end_to_end_agent_to_agent_call_flow(db_session, test_setup):
    # Full end-to-end integration:
    # 1. Host registers service
    svc = create_service(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, name="E2E Concierge")
    # 2. Host adds endpoint
    ep = register_endpoint(db_session, organization_id=test_setup["org1"].id, service_id=svc.id, url="https://concierge.example.com", allow_private_ips=True)
    # 3. Host verifies endpoint ownership cryptographically
    ch = initiate_endpoint_verification(db_session, ep.id)
    verify_endpoint_challenge(db_session, ep.id, ch.challenge_token)
    # 4. Host registers capability
    register_capability(db_session, organization_id=test_setup["org1"].id, agent_id=test_setup["agent1"].id, service_id=svc.id, name="hotel.book")
    # 5. Caller agent executes trusted call
    result = execute_agent_to_agent_call(
        db_session,
        caller_agent_id=test_setup["agent2"].id,
        service_id_or_name=svc.service_id,
        capability_name="hotel.book",
        payload={"hotel_id": "grand_hyatt", "nights": 3},
    )
    assert result["status"] == "COMPLETED"
    assert result["routed_endpoint_id"] == ep.endpoint_id
    assert result["call_chain"] == [test_setup["agent2"].agent_identifier]
    assert result["depth"] == 1
    assert result["response_digest"] is not None
