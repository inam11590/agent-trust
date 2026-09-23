"""Seed script to populate a rich, production-grade MVP dataset for Web & Mobile App testing.

Usage:
    python backend/scripts/seed_mvp.py
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
from uuid import uuid4

# Ensure backend directory is in python path
BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.core.config import Settings
from app.core.security import hash_password
from app.database.session import create_database_engine
from app.models.agent import Agent, AgentStatus
from app.models.agent_delegation import AgentDelegation, DelegationStatus
from app.models.agent_service import (
    AgentCallRecord,
    AgentService,
    AgentServiceEndpoint,
    EndpointHealthStatus,
    EndpointProtocol,
    ServiceStatus,
    ServiceVisibility,
)
from app.models.agent_signing import AgentSigningKey, AgentSigningKeyStatus
from app.models.agenttrust_protocol import AgentCapability
from app.models.cross_organization_trust import OrganizationTrustRelationship, TrustStatus
from app.models.organization import (
    MemberStatus,
    Organization,
    OrganizationMember,
    OrganizationRole,
    SecurityEvent,
)
from app.models.policy import Policy, PolicyBinding
from app.models.trust_registry import AgentCredential, CredentialStatus
from app.models.user import User


def seed_mvp():
    settings = Settings()
    engine = create_database_engine(settings)
    Session = sessionmaker(bind=engine)
    db = Session()

    print("[START] Starting AgentTrust MVP Seeding...")

    # 1. Demo Users
    users_data = [
        {"email": "admin@acme.ai", "name": "Alice Admin", "role": OrganizationRole.OWNER},
        {"email": "developer@acme.ai", "name": "Bob Developer", "role": OrganizationRole.DEVELOPER},
        {"email": "viewer@acme.ai", "name": "Charlie Viewer", "role": OrganizationRole.VIEWER},
    ]

    seeded_users = {}
    default_password = "Password123!"
    hashed_pw = hash_password(default_password)

    for u in users_data:
        user = db.scalar(select(User).where(User.email == u["email"]))
        if not user:
            user = User(
                email=u["email"],
                full_name=u["name"],
                hashed_password=hashed_pw,
                is_active=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            print(f"  ✅ Created user: {u['email']}")
        else:
            user.hashed_password = hashed_pw
            user.is_active = True
            db.commit()
            print(f"  ℹ️  Reused user: {u['email']}")
        seeded_users[u["email"]] = (user, u["role"])

    owner_user, _ = seeded_users["admin@acme.ai"]

    # 2. Primary Organization: Acme AI Corp
    org_name = "Acme AI Corp"
    org = db.scalar(select(Organization).where(Organization.name == org_name))
    if not org:
        org = Organization(
            name=org_name,
            owner_id=owner_user.id,
            is_active=True,
            production_access_status="APPROVED",
            production_approved_at=datetime.now(timezone.utc),
        )
        db.add(org)
        db.commit()
        db.refresh(org)
        print(f"  ✅ Created organization: {org_name}")
    else:
        print(f"  ℹ️  Reused organization: {org_name}")

    # Bind Members
    for email, (u, role) in seeded_users.items():
        member = db.scalar(
            select(OrganizationMember).where(
                OrganizationMember.organization_id == org.id,
                OrganizationMember.user_id == u.id,
            )
        )
        if not member:
            member = OrganizationMember(
                organization_id=org.id,
                user_id=u.id,
                role=role,
                status=MemberStatus.ACTIVE,
            )
            db.add(member)
            db.commit()

    # 3. Secondary Organization: Partner Logistics Ltd (for Cross-Org Trust demo)
    partner_user = db.scalar(select(User).where(User.email == "admin@logistics.example"))
    if not partner_user:
        partner_user = User(
            email="admin@logistics.example",
            full_name="David Dispatch",
            hashed_password=hashed_pw,
            is_active=True,
        )
        db.add(partner_user)
        db.commit()
        db.refresh(partner_user)

    partner_org = db.scalar(select(Organization).where(Organization.name == "Partner Logistics Ltd"))
    if not partner_org:
        partner_org = Organization(
            name="Partner Logistics Ltd",
            owner_id=partner_user.id,
            is_active=True,
            production_access_status="APPROVED",
            production_approved_at=datetime.now(timezone.utc),
        )
        db.add(partner_org)
        db.commit()
        db.refresh(partner_org)
        print(f"  ✅ Created partner organization: Partner Logistics Ltd")

    # Cross-Organization Trust Relationship
    trust = db.scalar(
        select(OrganizationTrustRelationship).where(
            OrganizationTrustRelationship.source_organization_id == org.id,
            OrganizationTrustRelationship.target_organization_id == partner_org.id,
        )
    )
    if not trust:
        trust = OrganizationTrustRelationship(
            source_organization_id=org.id,
            target_organization_id=partner_org.id,
            status=TrustStatus.ACTIVE,
            created_by_user_id=owner_user.id,
            accepted_by_user_id=partner_user.id,
            accepted_at=datetime.now(timezone.utc),
        )
        db.add(trust)
        db.commit()
        print(f"  ✅ Established Cross-Organization Trust between Acme AI Corp & Partner Logistics Ltd")

    # 4. Realistic MVP Agents for Acme AI Corp
    agents_spec = [
        {
            "name": "Customer Support Concierge",
            "identifier": "agt_concierge_01",
            "status": AgentStatus.ACTIVE,
            "risk": "LOW",
            "env": "production",
            "func": "Customer Operations",
        },
        {
            "name": "Financial Payment Agent",
            "identifier": "agt_payment_02",
            "status": AgentStatus.ACTIVE,
            "risk": "HIGH",
            "env": "production",
            "func": "Treasury & Payments",
        },
        {
            "name": "Travel Booking Copilot",
            "identifier": "agt_booking_03",
            "status": AgentStatus.ACTIVE,
            "risk": "MEDIUM",
            "env": "production",
            "func": "Travel & Logistics",
        },
        {
            "name": "Data Analytics Worker",
            "identifier": "agt_analytics_04",
            "status": AgentStatus.ACTIVE,
            "risk": "LOW",
            "env": "production",
            "func": "Business Intelligence",
        },
        {
            "name": "Staging Code Reviewer",
            "identifier": "agt_staging_05",
            "status": AgentStatus.INACTIVE,
            "risk": "LOW",
            "env": "staging",
            "func": "Engineering",
        },
        {
            "name": "Deprecated Order Sync",
            "identifier": "agt_legacy_06",
            "status": AgentStatus.SUSPENDED,
            "risk": "HIGH",
            "env": "production",
            "func": "Legacy Integration",
        },
    ]

    seeded_agents = {}
    for spec in agents_spec:
        agent = db.scalar(select(Agent).where(Agent.agent_identifier == spec["identifier"]))
        if not agent:
            agent = Agent(
                name=spec["name"],
                agent_identifier=spec["identifier"],
                owner_id=owner_user.id,
                organization_id=org.id,
                status=spec["status"],
                risk_classification=spec["risk"],
                environment=spec["env"],
                business_function=spec["func"],
            )
            db.add(agent)
            db.commit()
            db.refresh(agent)
            print(f"  ✅ Created agent: {spec['name']} ({spec['identifier']})")
        else:
            agent.status = spec["status"]
            db.commit()
        seeded_agents[spec["identifier"]] = agent

    # 5. Ed25519 Signing Keys for Active Agents
    for identifier, ag in seeded_agents.items():
        if ag.status == AgentStatus.ACTIVE:
            key = db.scalar(select(AgentSigningKey).where(AgentSigningKey.agent_id == ag.id))
            if not key:
                priv = Ed25519PrivateKey.generate()
                pub_bytes = priv.public_key().public_bytes(
                    encoding=Encoding.Raw,
                    format=PublicFormat.Raw,
                )
                pub_b64 = __import__("base64").b64encode(pub_bytes).decode("ascii")
                fingerprint = hashlib.sha256(pub_bytes).hexdigest()
                key_id = f"key_{uuid4().hex[:20]}"
                key = AgentSigningKey(
                    key_id=key_id,
                    agent_id=ag.id,
                    organization_id=org.id,
                    algorithm="Ed25519",
                    public_key=pub_b64,
                    fingerprint=fingerprint,
                    status=AgentSigningKeyStatus.ACTIVE,
                    activated_at=datetime.now(timezone.utc),
                )
                db.add(key)
                db.commit()

    # 6. Step 30 Services & Endpoints & Capabilities
    # Service 1: Concierge Booking Service
    booking_agent = seeded_agents["agt_booking_03"]
    svc_booking = db.scalar(select(AgentService).where(AgentService.name == "Concierge Booking Service"))
    if not svc_booking:
        svc_booking = AgentService(
            organization_id=org.id,
            agent_id=booking_agent.id,
            name="Concierge Booking Service",
            description="End-to-end flight, hotel, and itinerary coordination service",
            version="1.2.0",
            status=ServiceStatus.ACTIVE.value,
            visibility=ServiceVisibility.ORGANIZATION.value,
            environment="production",
        )
        db.add(svc_booking)
        db.commit()
        db.refresh(svc_booking)

        # Endpoints
        ep1 = AgentServiceEndpoint(
            organization_id=org.id,
            service_id=svc_booking.id,
            agent_id=booking_agent.id,
            protocol=EndpointProtocol.HTTPS.value,
            url="https://booking.acme.ai/api/v1",
            priority=1,
            weight=100,
            health_status=EndpointHealthStatus.HEALTHY.value,
            verified_at=datetime.now(timezone.utc),
        )
        db.add(ep1)

        # Capabilities
        cap1 = AgentCapability(
            organization_id=org.id,
            agent_id=booking_agent.id,
            service_id=svc_booking.id,
            name="book_flight",
            description="Book airline tickets via authorized GDS API",
            risk_classification="MEDIUM",
            input_schema={"type": "object", "properties": {"origin": {"type": "string"}, "destination": {"type": "string"}, "date": {"type": "string"}}, "required": ["origin", "destination", "date"]},
            rate_limit_per_minute=60,
        )
        cap2 = AgentCapability(
            organization_id=org.id,
            agent_id=booking_agent.id,
            service_id=svc_booking.id,
            name="cancel_reservation",
            description="Cancel itinerary reservation and calculate refund eligibility",
            risk_classification="HIGH",
            requires_approval=True,
            approval_threshold_amount=500.0,
            input_schema={"type": "object", "properties": {"booking_id": {"type": "string"}, "reason": {"type": "string"}}, "required": ["booking_id"]},
        )
        db.add_all([cap1, cap2])
        db.commit()
        print("  ✅ Registered Service: Concierge Booking Service with 2 capabilities")

    # Service 2: Payment Gateway Service
    payment_agent = seeded_agents["agt_payment_02"]
    svc_payment = db.scalar(select(AgentService).where(AgentService.name == "Financial Payment Gateway"))
    if not svc_payment:
        svc_payment = AgentService(
            organization_id=org.id,
            agent_id=payment_agent.id,
            name="Financial Payment Gateway",
            description="Enterprise agent payment processing and ledger reconciliation",
            version="2.0.1",
            status=ServiceStatus.ACTIVE.value,
            visibility=ServiceVisibility.TRUSTED_ORGANIZATIONS.value,
            environment="production",
        )
        db.add(svc_payment)
        db.commit()
        db.refresh(svc_payment)

        ep2 = AgentServiceEndpoint(
            organization_id=org.id,
            service_id=svc_payment.id,
            agent_id=payment_agent.id,
            protocol=EndpointProtocol.AGENTTRUST_GATEWAY.value,
            url="https://gateway.acme.ai/atp/v1",
            priority=1,
            weight=100,
            health_status=EndpointHealthStatus.HEALTHY.value,
            verified_at=datetime.now(timezone.utc),
        )
        db.add(ep2)

        cap_pay1 = AgentCapability(
            organization_id=org.id,
            agent_id=payment_agent.id,
            service_id=svc_payment.id,
            name="process_refund",
            description="Authorize and dispatch immediate customer refund payment",
            risk_classification="CRITICAL",
            requires_approval=True,
            approval_threshold_amount=250.0,
            input_schema={"type": "object", "properties": {"transaction_id": {"type": "string"}, "amount": {"type": "number"}, "currency": {"type": "string"}}, "required": ["transaction_id", "amount"]},
        )
        cap_pay2 = AgentCapability(
            organization_id=org.id,
            agent_id=payment_agent.id,
            service_id=svc_payment.id,
            name="check_balance",
            description="Query corporate billing escrow balance",
            risk_classification="LOW",
            input_schema={"type": "object", "properties": {"account_id": {"type": "string"}}, "required": ["account_id"]},
        )
        db.add_all([cap_pay1, cap_pay2])
        db.commit()
        print("  ✅ Registered Service: Financial Payment Gateway with 2 capabilities")

    # 7. Agent Permissions & Delegations (Concierge -> Payment)
    from decimal import Decimal
    from app.models.permission import Permission, PermissionStatus

    concierge_ag = seeded_agents["agt_concierge_01"]
    perm = db.scalar(
        select(Permission).where(
            Permission.agent_id == concierge_ag.id,
            Permission.action == "process_refund",
        )
    )
    if not perm:
        perm = Permission(
            owner_id=owner_user.id,
            agent_id=concierge_ag.id,
            action="process_refund",
            resource="payment:refund",
            maximum_amount=Decimal("1000.00"),
            currency="USD",
            valid_from=datetime.now(timezone.utc) - timedelta(days=1),
            expires_at=datetime.now(timezone.utc) + timedelta(days=180),
            status=PermissionStatus.ACTIVE,
        )
        db.add(perm)
        db.commit()
        db.refresh(perm)

    delg = db.scalar(
        select(AgentDelegation).where(
            AgentDelegation.parent_agent_id == concierge_ag.id,
            AgentDelegation.child_agent_id == payment_agent.id,
        )
    )
    if not delg:
        delg = AgentDelegation(
            parent_agent_id=concierge_ag.id,
            child_agent_id=payment_agent.id,
            parent_permission_id=perm.id,
            organization_id=org.id,
            action="process_refund",
            resource="payment:refund",
            maximum_amount=500.0,
            currency="USD",
            requires_approval=True,
            allow_further_delegation=False,
            current_depth=1,
            max_delegation_depth=3,
            expires_at=datetime.now(timezone.utc) + timedelta(days=90),
            status=DelegationStatus.ACTIVE,
        )
        db.add(delg)
        db.commit()
        print("  ✅ Created Delegation: Concierge -> Payment Agent (process_refund up to $500)")

    # 8. Sample Telemetry & Call Records (Step 30)
    existing_calls = db.scalars(select(AgentCallRecord)).all()
    if not existing_calls:
        call1 = AgentCallRecord(
            message_id=f"msg_{uuid4().hex[:16]}",
            source_organization_id=org.id,
            source_agent_id=concierge_ag.id,
            target_organization_id=org.id,
            target_agent_id=booking_agent.id,
            service_id=svc_booking.id,
            capability_name="book_flight",
            call_chain=[concierge_ag.agent_identifier, booking_agent.agent_identifier],
            depth=1,
            status="COMPLETED",
            duration_ms=45.2,
            response_digest="res_sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e464",
            created_at=datetime.now(timezone.utc) - timedelta(minutes=15),
        )
        call2 = AgentCallRecord(
            message_id=f"msg_{uuid4().hex[:16]}",
            source_organization_id=org.id,
            source_agent_id=concierge_ag.id,
            target_organization_id=org.id,
            target_agent_id=payment_agent.id,
            service_id=svc_payment.id,
            capability_name="process_refund",
            call_chain=[concierge_ag.agent_identifier, payment_agent.agent_identifier],
            depth=1,
            status="PENDING_APPROVAL",
            duration_ms=88.5,
            response_digest=None,
            created_at=datetime.now(timezone.utc) - timedelta(minutes=5),
        )
        db.add_all([call1, call2])
        db.commit()
        print("  ✅ Seeded live AgentCallRecord telemetry")

    # 9. Security Events
    existing_events = db.scalars(select(SecurityEvent).where(SecurityEvent.organization_id == org.id)).all()
    if not existing_events:
        sec1 = SecurityEvent(
            organization_id=org.id,
            event_type="LOOP_DETECTED_BLOCKED",
            category="THREAT_DETECTION",
            severity="high",
            decision="BLOCKED",
            description="Circular invocation chain [agt_concierge_01 -> agt_booking_03 -> agt_concierge_01] was intercepted and blocked.",
            created_at=datetime.now(timezone.utc) - timedelta(hours=2),
        )
        sec2 = SecurityEvent(
            organization_id=org.id,
            event_type="UNAUTHORIZED_CAPABILITY_ACCESS",
            category="AUTHORIZATION",
            severity="medium",
            decision="DENIED",
            description="Unmanaged external agent attempted to invoke high-risk payment capability without active trust certificate.",
            created_at=datetime.now(timezone.utc) - timedelta(hours=5),
        )
        db.add_all([sec1, sec2])
        db.commit()
        print("  ✅ Seeded Security Events for SOC & Security Center")

    db.close()
    print("\n✨ MVP Seeding Complete! All Web & Mobile App components are populated and ready.")


if __name__ == "__main__":
    seed_mvp()
