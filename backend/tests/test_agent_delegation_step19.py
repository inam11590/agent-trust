"""Step 19: Agent-to-Agent Trust (Delegation) test suite."""

import base64
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.session import create_database_engine, get_db
from app.main import create_app
from app.models import (
    Agent,
    AgentDelegation,
    AgentSigningKey,
    AgentSigningKeyStatus,
    AgentStatus,
    AuditDecision,
    AuditLog,
    AuthorizationRequestRecord,
    AuthorizationRequestStatus,
    DelegationStatus,
    MemberStatus,
    Organization,
    OrganizationMember,
    OrganizationRole,
    Permission,
    PermissionStatus,
    User,
)
from app.schemas.agent_delegation import AgentDelegationCreate
from app.services.agent_delegation import (
    create_delegation,
    get_delegation_chain,
    revoke_delegation,
    verify_delegation_chain,
)
from app.services.agent_signing import canonical_request, fingerprint
from app.services.authorization import authorize_action
from app.schemas.authorization import AuthorizationRequest
from app.schemas.developer import APIKeyCreate
from app.services.api_keys import create_api_key

pytestmark = pytest.mark.skipif(os.getenv("RUN_DATABASE_TESTS") != "1", reason="Database tests disabled")


@pytest.fixture(scope="module")
def engine():
    value = create_database_engine(Settings())
    yield value
    value.dispose()


@pytest.fixture
def db(engine):
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
                yield session
        finally:
            transaction.rollback()


@pytest.fixture
def client(db):
    app = create_app()
    app.state.settings = Settings(
        _env_file=None,
        app_env="test",
        jwt_secret_key=secrets.token_urlsafe(48),
        postgres_user="",
        postgres_password="",
        redis_url="",
    )
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as value:
        yield value


def _create_user(db: Session, email_prefix: str = "user") -> User:
    user = User(
        email=f"{email_prefix}-{uuid4()}@example.com",
        hashed_password="fakehash_step19",
        full_name="Delegation Test User",
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _create_org(db: Session, user: User, name: str = "Test Org") -> Organization:
    org = Organization(name=name, owner_id=user.id)
    db.add(org)
    db.commit()
    db.refresh(org)

    member = OrganizationMember(
        organization_id=org.id,
        user_id=user.id,
        role=OrganizationRole.OWNER,
        status=MemberStatus.ACTIVE,
    )
    db.add(member)
    db.commit()
    return org


def _create_agent(db: Session, user: User, org: Organization, name: str) -> Agent:
    agent = Agent(
        name=name,
        agent_identifier=f"agt_{secrets.token_hex(12)}",
        owner_id=user.id,
        organization_id=org.id,
        status=AgentStatus.ACTIVE,
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return agent


def _create_permission(
    db: Session,
    user: User,
    agent: Agent,
    action: str = "payments:transfer",
    resource: str = "account:123",
    maximum_amount: Decimal | None = Decimal("1000.00"),
    currency: str | None = "USD",
    requires_approval: bool = False,
    allow_delegation: bool = True,
    duration_hours: int = 24,
) -> Permission:
    now = datetime.now(timezone.utc)
    perm = Permission(
        owner_id=user.id,
        agent_id=agent.id,
        action=action,
        resource=resource,
        maximum_amount=maximum_amount,
        currency=currency,
        requires_approval=requires_approval,
        allow_delegation=allow_delegation,
        valid_from=now - timedelta(minutes=5),
        expires_at=now + timedelta(hours=duration_hours),
        status=PermissionStatus.ACTIVE,
    )
    db.add(perm)
    db.commit()
    db.refresh(perm)
    return perm


def _setup_signing_key(db: Session, agent: Agent) -> tuple[Ed25519PrivateKey, AgentSigningKey]:
    key = Ed25519PrivateKey.generate()
    pub_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    now = datetime.now(timezone.utc)
    signing_key = AgentSigningKey(
        agent_id=agent.id,
        organization_id=agent.organization_id,
        key_id=f"key_ag_{secrets.token_hex(12)}",
        public_key=pub_b64,
        algorithm="Ed25519",
        fingerprint=fingerprint(pub_bytes),
        status=AgentSigningKeyStatus.ACTIVE,
        activated_at=now,
        expires_at=now + timedelta(days=30),
    )
    db.add(signing_key)
    db.commit()
    db.refresh(signing_key)
    return key, signing_key


def _create_api_key(db: Session, user: User, org: Organization) -> str:
    _, raw_key = create_api_key(db, user, APIKeyCreate(name="Delegation Test Key"), organization_id=org.id)
    return raw_key


# =========================================================================
# 1. Delegation Creation & Constraints Verification
# =========================================================================

def test_delegation_create_direct_success(db: Session):
    user = _create_user(db)
    org = _create_org(db, user)
    agent_a = _create_agent(db, user, org, "Agent A")
    agent_b = _create_agent(db, user, org, "Agent B")
    perm = _create_permission(db, user, agent_a, maximum_amount=Decimal("1000.00"))

    now = datetime.now(timezone.utc)
    payload = AgentDelegationCreate(
        parent_agent_id=agent_a.id,
        child_agent_id=agent_b.id,
        parent_permission_id=perm.id,
        action="payments:transfer",
        resource="account:123",
        maximum_amount=Decimal("500.00"),
        currency="USD",
        requires_approval=False,
        allow_further_delegation=True,
        expires_at=now + timedelta(hours=12),
    )
    delegation = create_delegation(db, payload)
    assert delegation.id is not None
    assert delegation.delegation_id.startswith("dlg_")
    assert delegation.current_depth == 1
    assert delegation.status == DelegationStatus.ACTIVE
    assert delegation.maximum_amount == Decimal("500.00")


def test_delegation_create_amount_escalation_rejected(db: Session):
    user = _create_user(db)
    org = _create_org(db, user)
    agent_a = _create_agent(db, user, org, "Agent A")
    agent_b = _create_agent(db, user, org, "Agent B")
    perm = _create_permission(db, user, agent_a, maximum_amount=Decimal("500.00"))

    now = datetime.now(timezone.utc)
    payload = AgentDelegationCreate(
        parent_agent_id=agent_a.id,
        child_agent_id=agent_b.id,
        parent_permission_id=perm.id,
        action="payments:transfer",
        resource="account:123",
        maximum_amount=Decimal("600.00"),  # Exceeds parent limit
        currency="USD",
        expires_at=now + timedelta(hours=1),
    )
    with pytest.raises(Exception) as exc:
        create_delegation(db, payload)
    assert "exceeds" in str(exc.value.detail).lower()


def test_delegation_create_expiry_escalation_rejected(db: Session):
    user = _create_user(db)
    org = _create_org(db, user)
    agent_a = _create_agent(db, user, org, "Agent A")
    agent_b = _create_agent(db, user, org, "Agent B")
    perm = _create_permission(db, user, agent_a, duration_hours=6)

    now = datetime.now(timezone.utc)
    payload = AgentDelegationCreate(
        parent_agent_id=agent_a.id,
        child_agent_id=agent_b.id,
        parent_permission_id=perm.id,
        action="payments:transfer",
        resource="account:123",
        maximum_amount=Decimal("100.00"),
        currency="USD",
        expires_at=now + timedelta(hours=10),  # Exceeds parent 6h
    )
    with pytest.raises(Exception) as exc:
        create_delegation(db, payload)
    assert "expiry" in str(exc.value.detail).lower()


def test_delegation_create_action_mismatch_rejected(db: Session):
    user = _create_user(db)
    org = _create_org(db, user)
    agent_a = _create_agent(db, user, org, "Agent A")
    agent_b = _create_agent(db, user, org, "Agent B")
    perm = _create_permission(db, user, agent_a, action="payments:transfer")

    now = datetime.now(timezone.utc)
    payload = AgentDelegationCreate(
        parent_agent_id=agent_a.id,
        child_agent_id=agent_b.id,
        parent_permission_id=perm.id,
        action="payments:refund",  # Mismatched action
        resource="account:123",
        maximum_amount=Decimal("100.00"),
        currency="USD",
        expires_at=now + timedelta(hours=1),
    )
    with pytest.raises(Exception) as exc:
        create_delegation(db, payload)
    assert "action" in str(exc.value.detail).lower()


def test_delegation_create_approval_escalation_rejected(db: Session):
    user = _create_user(db)
    org = _create_org(db, user)
    agent_a = _create_agent(db, user, org, "Agent A")
    agent_b = _create_agent(db, user, org, "Agent B")
    perm = _create_permission(db, user, agent_a, requires_approval=True)

    now = datetime.now(timezone.utc)
    payload = AgentDelegationCreate(
        parent_agent_id=agent_a.id,
        child_agent_id=agent_b.id,
        parent_permission_id=perm.id,
        action="payments:transfer",
        resource="account:123",
        maximum_amount=Decimal("100.00"),
        currency="USD",
        requires_approval=False,  # Cannot drop approval requirement
        expires_at=now + timedelta(hours=1),
    )
    with pytest.raises(Exception) as exc:
        create_delegation(db, payload)
    assert "approval" in str(exc.value.detail).lower()


def test_delegation_create_non_delegatable_parent_rejected(db: Session):
    user = _create_user(db)
    org = _create_org(db, user)
    agent_a = _create_agent(db, user, org, "Agent A")
    agent_b = _create_agent(db, user, org, "Agent B")
    perm = _create_permission(db, user, agent_a, allow_delegation=False)

    now = datetime.now(timezone.utc)
    payload = AgentDelegationCreate(
        parent_agent_id=agent_a.id,
        child_agent_id=agent_b.id,
        parent_permission_id=perm.id,
        action="payments:transfer",
        resource="account:123",
        maximum_amount=Decimal("100.00"),
        currency="USD",
        expires_at=now + timedelta(hours=1),
    )
    with pytest.raises(Exception) as exc:
        create_delegation(db, payload)
    assert "does not permit delegation" in str(exc.value.detail).lower()


def test_delegation_create_self_delegation_rejected(db: Session):
    user = _create_user(db)
    org = _create_org(db, user)
    agent_a = _create_agent(db, user, org, "Agent A")
    perm = _create_permission(db, user, agent_a)

    now = datetime.now(timezone.utc)
    with pytest.raises(Exception) as exc:
        AgentDelegationCreate(
            parent_agent_id=agent_a.id,
            child_agent_id=agent_a.id,  # Self delegation
            parent_permission_id=perm.id,
            action="payments:transfer",
            resource="account:123",
            maximum_amount=Decimal("100.00"),
            currency="USD",
            expires_at=now + timedelta(hours=1),
        )
    assert "cannot be the same agent" in str(exc.value)


def test_delegation_create_cross_organization_rejected(db: Session):
    user = _create_user(db)
    org1 = _create_org(db, user, "Org 1")
    org2 = _create_org(db, user, "Org 2")
    agent_a = _create_agent(db, user, org1, "Agent A Org 1")
    agent_b = _create_agent(db, user, org2, "Agent B Org 2")
    perm = _create_permission(db, user, agent_a)

    now = datetime.now(timezone.utc)
    payload = AgentDelegationCreate(
        parent_agent_id=agent_a.id,
        child_agent_id=agent_b.id,
        parent_permission_id=perm.id,
        action="payments:transfer",
        resource="account:123",
        maximum_amount=Decimal("100.00"),
        currency="USD",
        expires_at=now + timedelta(hours=1),
    )
    with pytest.raises(Exception) as exc:
        create_delegation(db, payload)
    assert "cross-organization" in str(exc.value.detail).lower()


# =========================================================================
# 2. Multi-step Transitive Delegation & Depth Checks
# =========================================================================

def test_delegation_chain_multi_step_success(db: Session):
    user = _create_user(db)
    org = _create_org(db, user)
    agent_a = _create_agent(db, user, org, "Agent A")
    agent_b = _create_agent(db, user, org, "Agent B")
    agent_c = _create_agent(db, user, org, "Agent C")
    perm = _create_permission(db, user, agent_a, maximum_amount=Decimal("1000.00"))

    now = datetime.now(timezone.utc)
    # Step 1: A -> B
    dlg1 = create_delegation(db, AgentDelegationCreate(
        parent_agent_id=agent_a.id,
        child_agent_id=agent_b.id,
        parent_permission_id=perm.id,
        action="payments:transfer",
        resource="account:123",
        maximum_amount=Decimal("500.00"),
        currency="USD",
        allow_further_delegation=True,
        expires_at=now + timedelta(hours=12),
    ))
    assert dlg1.current_depth == 1

    # Step 2: B -> C
    dlg2 = create_delegation(db, AgentDelegationCreate(
        parent_agent_id=agent_b.id,
        child_agent_id=agent_c.id,
        parent_permission_id=perm.id,
        parent_delegation_id=dlg1.id,
        action="payments:transfer",
        resource="account:123",
        maximum_amount=Decimal("200.00"),
        currency="USD",
        allow_further_delegation=False,
        expires_at=now + timedelta(hours=6),
    ))
    assert dlg2.current_depth == 2

    # Verify chain from C
    is_valid, reason, meta = verify_delegation_chain(
        db,
        delegation_id=dlg2.delegation_id,
        action="payments:transfer",
        resource="account:123",
        amount=Decimal("150.00"),
        currency="USD",
    )
    assert is_valid is True
    assert reason == "OK"
    assert meta["depth"] == 2
    assert meta["effective_maximum_amount"] == Decimal("200.00")


def test_delegation_chain_disallow_further_delegation(db: Session):
    user = _create_user(db)
    org = _create_org(db, user)
    agent_a = _create_agent(db, user, org, "Agent A")
    agent_b = _create_agent(db, user, org, "Agent B")
    agent_c = _create_agent(db, user, org, "Agent C")
    perm = _create_permission(db, user, agent_a)

    now = datetime.now(timezone.utc)
    dlg1 = create_delegation(db, AgentDelegationCreate(
        parent_agent_id=agent_a.id,
        child_agent_id=agent_b.id,
        parent_permission_id=perm.id,
        action="payments:transfer",
        resource="account:123",
        maximum_amount=Decimal("500.00"),
        currency="USD",
        allow_further_delegation=False,  # NO further delegation!
        expires_at=now + timedelta(hours=12),
    ))

    with pytest.raises(Exception) as exc:
        create_delegation(db, AgentDelegationCreate(
            parent_agent_id=agent_b.id,
            child_agent_id=agent_c.id,
            parent_permission_id=perm.id,
            parent_delegation_id=dlg1.id,
            action="payments:transfer",
            resource="account:123",
            maximum_amount=Decimal("200.00"),
            currency="USD",
            expires_at=now + timedelta(hours=6),
        ))
    assert "does not allow further sub-delegation" in str(exc.value.detail).lower()


def test_delegation_depth_limit_enforced(db: Session):
    user = _create_user(db)
    org = _create_org(db, user)
    agent_a = _create_agent(db, user, org, "Agent A")
    agent_b = _create_agent(db, user, org, "Agent B")
    agent_c = _create_agent(db, user, org, "Agent C")
    agent_d = _create_agent(db, user, org, "Agent D")
    agent_e = _create_agent(db, user, org, "Agent E")
    perm = _create_permission(db, user, agent_a, maximum_amount=Decimal("1000.00"))

    now = datetime.now(timezone.utc)
    # A -> B (depth 1)
    dlg1 = create_delegation(db, AgentDelegationCreate(
        parent_agent_id=agent_a.id, child_agent_id=agent_b.id, parent_permission_id=perm.id,
        action="payments:transfer", resource="account:123", maximum_amount=Decimal("800.00"),
        currency="USD", allow_further_delegation=True, expires_at=now + timedelta(hours=10),
    ))
    # B -> C (depth 2)
    dlg2 = create_delegation(db, AgentDelegationCreate(
        parent_agent_id=agent_b.id, child_agent_id=agent_c.id, parent_permission_id=perm.id,
        parent_delegation_id=dlg1.id, action="payments:transfer", resource="account:123",
        maximum_amount=Decimal("600.00"), currency="USD", allow_further_delegation=True,
        expires_at=now + timedelta(hours=8),
    ))
    # C -> D (depth 3)
    dlg3 = create_delegation(db, AgentDelegationCreate(
        parent_agent_id=agent_c.id, child_agent_id=agent_d.id, parent_permission_id=perm.id,
        parent_delegation_id=dlg2.id, action="payments:transfer", resource="account:123",
        maximum_amount=Decimal("400.00"), currency="USD", allow_further_delegation=True,
        expires_at=now + timedelta(hours=6),
    ))
    assert dlg3.current_depth == 3

    # D -> E (depth 4: exceeds default max depth 3)
    with pytest.raises(Exception) as exc:
        create_delegation(db, AgentDelegationCreate(
            parent_agent_id=agent_d.id, child_agent_id=agent_e.id, parent_permission_id=perm.id,
            parent_delegation_id=dlg3.id, action="payments:transfer", resource="account:123",
            maximum_amount=Decimal("200.00"), currency="USD", allow_further_delegation=True,
            expires_at=now + timedelta(hours=4),
        ))
    assert "exceeds maximum allowed depth" in str(exc.value.detail).lower()


def test_delegation_cycle_prevention(db: Session):
    user = _create_user(db)
    org = _create_org(db, user)
    agent_a = _create_agent(db, user, org, "Agent A")
    agent_b = _create_agent(db, user, org, "Agent B")
    agent_c = _create_agent(db, user, org, "Agent C")
    perm = _create_permission(db, user, agent_a)

    now = datetime.now(timezone.utc)
    dlg1 = create_delegation(db, AgentDelegationCreate(
        parent_agent_id=agent_a.id, child_agent_id=agent_b.id, parent_permission_id=perm.id,
        action="payments:transfer", resource="account:123", maximum_amount=Decimal("800.00"),
        currency="USD", allow_further_delegation=True, expires_at=now + timedelta(hours=10),
    ))
    dlg2 = create_delegation(db, AgentDelegationCreate(
        parent_agent_id=agent_b.id, child_agent_id=agent_c.id, parent_permission_id=perm.id,
        parent_delegation_id=dlg1.id, action="payments:transfer", resource="account:123",
        maximum_amount=Decimal("600.00"), currency="USD", allow_further_delegation=True,
        expires_at=now + timedelta(hours=8),
    ))

    # Cycle: C delegates back to A (A was root)
    with pytest.raises(Exception) as exc:
        create_delegation(db, AgentDelegationCreate(
            parent_agent_id=agent_c.id, child_agent_id=agent_a.id, parent_permission_id=perm.id,
            parent_delegation_id=dlg2.id, action="payments:transfer", resource="account:123",
            maximum_amount=Decimal("400.00"), currency="USD", expires_at=now + timedelta(hours=6),
        ))
    assert "cycle detected" in str(exc.value.detail).lower()


# =========================================================================
# 3. Authorization Execution Under Delegation
# =========================================================================

def test_child_execution_authorized(db: Session):
    user = _create_user(db)
    org = _create_org(db, user)
    agent_a = _create_agent(db, user, org, "Agent A")
    agent_b = _create_agent(db, user, org, "Agent B")
    perm = _create_permission(db, user, agent_a, maximum_amount=Decimal("1000.00"))

    now = datetime.now(timezone.utc)
    dlg = create_delegation(db, AgentDelegationCreate(
        parent_agent_id=agent_a.id, child_agent_id=agent_b.id, parent_permission_id=perm.id,
        action="payments:transfer", resource="account:123", maximum_amount=Decimal("500.00"),
        currency="USD", expires_at=now + timedelta(hours=12),
    ))

    # Child agent B requests authorization with delegation_id
    req = AuthorizationRequest(
        agent_id=agent_b.agent_identifier,
        action="payments:transfer",
        resource="account:123",
        amount=Decimal("250.00"),
        currency="USD",
        delegation_id=dlg.delegation_id,
    )
    result = authorize_action(db, owner_id=user.id, request=req, organization_scope=org.id)
    assert result.decision == "APPROVED"

    # Verify audit log captures delegation
    audit = db.scalar(select(AuditLog).where(AuditLog.request_id == result.request_id))
    assert audit is not None
    assert audit.delegation_id == dlg.delegation_id
    assert audit.parent_agent_id == agent_a.id
    assert audit.agent_identifier == agent_b.agent_identifier


def test_child_execution_exceeds_delegated_amount(db: Session):
    user = _create_user(db)
    org = _create_org(db, user)
    agent_a = _create_agent(db, user, org, "Agent A")
    agent_b = _create_agent(db, user, org, "Agent B")
    perm = _create_permission(db, user, agent_a, maximum_amount=Decimal("1000.00"))

    now = datetime.now(timezone.utc)
    dlg = create_delegation(db, AgentDelegationCreate(
        parent_agent_id=agent_a.id, child_agent_id=agent_b.id, parent_permission_id=perm.id,
        action="payments:transfer", resource="account:123", maximum_amount=Decimal("300.00"),
        currency="USD", expires_at=now + timedelta(hours=12),
    ))

    # Request $350 (exceeds child's $300 limit, even though parent had $1000)
    req = AuthorizationRequest(
        agent_id=agent_b.agent_identifier,
        action="payments:transfer",
        resource="account:123",
        amount=Decimal("350.00"),
        currency="USD",
        delegation_id=dlg.delegation_id,
    )
    result = authorize_action(db, owner_id=user.id, request=req, organization_scope=org.id)
    assert result.decision == "REJECTED"
    assert "delegation invalid" in result.reason.lower()


def test_child_execution_requires_human_approval(db: Session):
    user = _create_user(db)
    org = _create_org(db, user)
    agent_a = _create_agent(db, user, org, "Agent A")
    agent_b = _create_agent(db, user, org, "Agent B")
    perm = _create_permission(db, user, agent_a, maximum_amount=Decimal("1000.00"), requires_approval=True)

    now = datetime.now(timezone.utc)
    dlg = create_delegation(db, AgentDelegationCreate(
        parent_agent_id=agent_a.id, child_agent_id=agent_b.id, parent_permission_id=perm.id,
        action="payments:transfer", resource="account:123", maximum_amount=Decimal("500.00"),
        currency="USD", requires_approval=True, expires_at=now + timedelta(hours=12),
    ))

    req = AuthorizationRequest(
        agent_id=agent_b.agent_identifier,
        action="payments:transfer",
        resource="account:123",
        amount=Decimal("200.00"),
        currency="USD",
        delegation_id=dlg.delegation_id,
    )
    result = authorize_action(db, owner_id=user.id, request=req, organization_scope=org.id)
    assert result.decision == "PENDING"

    # Verify pending record
    pending = db.scalar(select(AuthorizationRequestRecord).where(AuthorizationRequestRecord.request_id == result.request_id))
    assert pending is not None
    assert pending.delegation_id == dlg.delegation_id
    assert pending.parent_agent_id == agent_a.id
    assert pending.agent_id == agent_b.id


# =========================================================================
# 4. Cascade Revocation & Immediate Invalidation
# =========================================================================

def test_cascade_revocation_of_delegation(db: Session):
    user = _create_user(db)
    org = _create_org(db, user)
    agent_a = _create_agent(db, user, org, "Agent A")
    agent_b = _create_agent(db, user, org, "Agent B")
    agent_c = _create_agent(db, user, org, "Agent C")
    perm = _create_permission(db, user, agent_a)

    now = datetime.now(timezone.utc)
    dlg1 = create_delegation(db, AgentDelegationCreate(
        parent_agent_id=agent_a.id, child_agent_id=agent_b.id, parent_permission_id=perm.id,
        action="payments:transfer", resource="account:123", maximum_amount=Decimal("500.00"),
        currency="USD", allow_further_delegation=True, expires_at=now + timedelta(hours=12),
    ))
    dlg2 = create_delegation(db, AgentDelegationCreate(
        parent_agent_id=agent_b.id, child_agent_id=agent_c.id, parent_permission_id=perm.id,
        parent_delegation_id=dlg1.id, action="payments:transfer", resource="account:123",
        maximum_amount=Decimal("200.00"), currency="USD", expires_at=now + timedelta(hours=6),
    ))

    # Revoke dlg1 with cascade
    revoke_delegation(db, delegation_id=dlg1.delegation_id, revoked_by_user_id=user.id, reason="Security audit")

    # Refresh dlg2
    db.refresh(dlg2)
    assert dlg1.status == DelegationStatus.REVOKED
    assert dlg2.status == DelegationStatus.REVOKED
    assert "Cascade revocation" in (dlg2.revocation_reason or "")

    # Child agent C request must fail
    req = AuthorizationRequest(
        agent_id=agent_c.agent_identifier,
        action="payments:transfer",
        resource="account:123",
        amount=Decimal("50.00"),
        currency="USD",
        delegation_id=dlg2.delegation_id,
    )
    result = authorize_action(db, owner_id=user.id, request=req, organization_scope=org.id)
    assert result.decision == "REJECTED"
    assert "delegation_revoked" in result.reason.lower()


def test_cascade_revocation_of_root_permission(db: Session):
    user = _create_user(db)
    org = _create_org(db, user)
    agent_a = _create_agent(db, user, org, "Agent A")
    agent_b = _create_agent(db, user, org, "Agent B")
    perm = _create_permission(db, user, agent_a)

    now = datetime.now(timezone.utc)
    dlg = create_delegation(db, AgentDelegationCreate(
        parent_agent_id=agent_a.id, child_agent_id=agent_b.id, parent_permission_id=perm.id,
        action="payments:transfer", resource="account:123", maximum_amount=Decimal("500.00"),
        currency="USD", expires_at=now + timedelta(hours=12),
    ))

    # Revoke parent permission directly
    perm.status = PermissionStatus.REVOKED
    db.commit()

    # Child agent B attempts action
    req = AuthorizationRequest(
        agent_id=agent_b.agent_identifier,
        action="payments:transfer",
        resource="account:123",
        amount=Decimal("100.00"),
        currency="USD",
        delegation_id=dlg.delegation_id,
    )
    result = authorize_action(db, owner_id=user.id, request=req, organization_scope=org.id)
    assert result.decision == "REJECTED"
    assert "parent_permission_revoked" in result.reason.lower()


def test_inactive_parent_agent_blocks_delegation(db: Session):
    user = _create_user(db)
    org = _create_org(db, user)
    agent_a = _create_agent(db, user, org, "Agent A")
    agent_b = _create_agent(db, user, org, "Agent B")
    perm = _create_permission(db, user, agent_a)

    now = datetime.now(timezone.utc)
    dlg = create_delegation(db, AgentDelegationCreate(
        parent_agent_id=agent_a.id, child_agent_id=agent_b.id, parent_permission_id=perm.id,
        action="payments:transfer", resource="account:123", maximum_amount=Decimal("500.00"),
        currency="USD", expires_at=now + timedelta(hours=12),
    ))

    # Deactivate parent agent A
    agent_a.status = AgentStatus.SUSPENDED
    db.commit()

    req = AuthorizationRequest(
        agent_id=agent_b.agent_identifier,
        action="payments:transfer",
        resource="account:123",
        amount=Decimal("100.00"),
        currency="USD",
        delegation_id=dlg.delegation_id,
    )
    result = authorize_action(db, owner_id=user.id, request=req, organization_scope=org.id)
    assert result.decision == "REJECTED"
    assert "parent_agent_inactive" in result.reason.lower()


# =========================================================================
# 5. Cryptographically Signed Child Requests
# =========================================================================

def test_signed_child_agent_request(client: TestClient, db: Session):
    user = _create_user(db)
    org = _create_org(db, user)
    agent_a = _create_agent(db, user, org, "Agent A")
    agent_b = _create_agent(db, user, org, "Agent B")
    perm = _create_permission(db, user, agent_a, maximum_amount=Decimal("1000.00"))

    now = datetime.now(timezone.utc)
    dlg = create_delegation(db, AgentDelegationCreate(
        parent_agent_id=agent_a.id, child_agent_id=agent_b.id, parent_permission_id=perm.id,
        action="payments:transfer", resource="account:123", maximum_amount=Decimal("500.00"),
        currency="USD", expires_at=now + timedelta(hours=12),
    ))

    # Setup API Key for Developer Auth
    api_key = _create_api_key(db, user, org)

    # Setup Ed25519 signing key for Child Agent B
    priv_key, signing_key = _setup_signing_key(db, agent_b)

    # Build exact request body containing delegation_id
    body_dict = {
        "agent_id": agent_b.agent_identifier,
        "action": "payments:transfer",
        "resource": "account:123",
        "amount": "250.0000",
        "currency": "USD",
        "delegation_id": dlg.delegation_id,
    }
    import json
    body_bytes = json.dumps(body_dict, separators=(",", ":")).encode("utf-8")

    nonce = f"nonce_{secrets.token_hex(16)}"
    timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    canonical = canonical_request(
        method="POST",
        path="/api/v1/authorize",
        agent_id=agent_b.agent_identifier,
        key_id=signing_key.key_id,
        timestamp=timestamp_str,
        nonce=nonce,
        body=body_bytes,
    )
    sig = priv_key.sign(canonical)
    sig_b64 = base64.b64encode(sig).decode("ascii")

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
        "X-Agent-ID": agent_b.agent_identifier,
        "X-Agent-Key-ID": signing_key.key_id,
        "X-Agent-Timestamp": timestamp_str,
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": sig_b64,
        "X-Agent-Signature-Version": "v1",
    }

    resp = client.post("/api/v1/authorize", content=body_bytes, headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "APPROVED"

    record = db.scalar(select(AuditLog).where(AuditLog.request_id == data["request_id"]))
    assert record is not None
    assert record.delegation_id == dlg.delegation_id
    assert record.parent_agent_id == agent_a.id
    assert record.signature_verified is True


def test_signed_child_agent_replay_prevented(client: TestClient, db: Session):
    user = _create_user(db)
    org = _create_org(db, user)
    agent_a = _create_agent(db, user, org, "Agent A")
    agent_b = _create_agent(db, user, org, "Agent B")
    perm = _create_permission(db, user, agent_a, maximum_amount=Decimal("1000.00"))

    now = datetime.now(timezone.utc)
    dlg = create_delegation(db, AgentDelegationCreate(
        parent_agent_id=agent_a.id, child_agent_id=agent_b.id, parent_permission_id=perm.id,
        action="payments:transfer", resource="account:123", maximum_amount=Decimal("500.00"),
        currency="USD", expires_at=now + timedelta(hours=12),
    ))

    api_key = _create_api_key(db, user, org)
    priv_key, signing_key = _setup_signing_key(db, agent_b)

    import json
    body_dict = {
        "agent_id": agent_b.agent_identifier,
        "action": "payments:transfer",
        "resource": "account:123",
        "amount": "100.0000",
        "currency": "USD",
        "delegation_id": dlg.delegation_id,
    }
    body_bytes = json.dumps(body_dict, separators=(",", ":")).encode("utf-8")
    nonce = f"nonce_{secrets.token_hex(16)}"
    timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    canonical = canonical_request(
        method="POST", path="/api/v1/authorize",
        agent_id=agent_b.agent_identifier, key_id=signing_key.key_id,
        timestamp=timestamp_str, nonce=nonce, body=body_bytes,
    )
    sig_b64 = base64.b64encode(priv_key.sign(canonical)).decode("ascii")

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
        "X-Agent-ID": agent_b.agent_identifier,
        "X-Agent-Key-ID": signing_key.key_id,
        "X-Agent-Timestamp": timestamp_str,
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": sig_b64,
        "X-Agent-Signature-Version": "v1",
    }

    resp1 = client.post("/api/v1/authorize", content=body_bytes, headers=headers)
    assert resp1.status_code == 200

    # Replay identical request
    resp2 = client.post("/api/v1/authorize", content=body_bytes, headers=headers)
    assert resp2.status_code == 409
    assert resp2.json()["detail"] == "REPLAY_DETECTED"


# =========================================================================
# 6. Delegation API & Chain Inspection
# =========================================================================

def test_delegation_chain_response_structure(db: Session):
    user = _create_user(db)
    org = _create_org(db, user)
    agent_a = _create_agent(db, user, org, "Agent A")
    agent_b = _create_agent(db, user, org, "Agent B")
    perm = _create_permission(db, user, agent_a, maximum_amount=Decimal("1000.00"))

    now = datetime.now(timezone.utc)
    dlg = create_delegation(db, AgentDelegationCreate(
        parent_agent_id=agent_a.id, child_agent_id=agent_b.id, parent_permission_id=perm.id,
        action="payments:transfer", resource="account:123", maximum_amount=Decimal("400.00"),
        currency="USD", expires_at=now + timedelta(hours=12),
    ))

    chain_resp = get_delegation_chain(db, dlg.delegation_id)
    assert chain_resp.is_valid is True
    assert chain_resp.effective_maximum_amount == Decimal("400.00")
    assert chain_resp.effective_action == "payments:transfer"
    assert len(chain_resp.chain) == 2
    # Node 0: Root User Permission (depth 0)
    assert chain_resp.chain[0].depth == 0
    assert chain_resp.chain[0].maximum_amount == Decimal("1000.00")
    # Node 1: Delegation to Agent B (depth 1)
    assert chain_resp.chain[1].depth == 1
    assert chain_resp.chain[1].delegation_id == dlg.delegation_id

