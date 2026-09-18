"""End-to-End Web MVP Verification Test Suite.

Verifies the complete user flow:
1. Registration & Login
2. Multi-tenant isolation (confirm users cannot access another organization's data)
3. Agent registration
4. Permission settings
5. Action authorization & denial of unauthorized actions
6. Human approval and rejection flow
7. Activity history & audit logging
8. Step 19 delegation constraints, limits, and immediate cascade revocation
"""

import os
import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.session import create_database_engine, get_db
from app.main import create_app
from app.models import (
    Agent,
    AgentStatus,
    AuditLog,
    AuthorizationRequestRecord,
    DelegationStatus,
    Organization,
    OrganizationMember,
    OrganizationRole,
    Permission,
    PermissionStatus,
    User,
)
from app.schemas.authorization import AuthorizationRequest
from app.services.authorization import authorize_action
from app.services.agent_delegation import create_delegation, revoke_delegation
from app.schemas.agent_delegation import AgentDelegationCreate

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


def test_e2e_main_website_flow_and_security(client: TestClient, db: Session):
    # -------------------------------------------------------------------------
    # 1. Registration & Login (User 1 in Org 1, User 2 in Org 2)
    # -------------------------------------------------------------------------
    email_u1 = f"alice-{uuid4()}@example.com"
    pwd_u1 = "Password123!Safe"
    reg_u1 = client.post("/auth/register", json={
        "email": email_u1, "password": pwd_u1, "full_name": "Alice Admin"
    })
    assert reg_u1.status_code == 201, reg_u1.text
    login_u1 = client.post("/auth/login", json={"email": email_u1, "password": pwd_u1})
    assert login_u1.status_code == 200, login_u1.text
    token_u1 = login_u1.json()["access_token"]
    headers_u1 = {"Authorization": f"Bearer {token_u1}"}

    email_u2 = f"bob-{uuid4()}@example.com"
    pwd_u2 = "Password456!Safe"
    reg_u2 = client.post("/auth/register", json={
        "email": email_u2, "password": pwd_u2, "full_name": "Bob External"
    })
    assert reg_u2.status_code == 201, reg_u2.text
    login_u2 = client.post("/auth/login", json={"email": email_u2, "password": pwd_u2})
    assert login_u2.status_code == 200
    token_u2 = login_u2.json()["access_token"]
    headers_u2 = {"Authorization": f"Bearer {token_u2}"}

    # Create User 1 and User 2 Organizations
    org_res_1 = client.post("/organizations", headers=headers_u1, json={"name": "Alice Org"})
    assert org_res_1.status_code == 201, org_res_1.text
    org_id_1 = org_res_1.json()["id"]

    org_res_2 = client.post("/organizations", headers=headers_u2, json={"name": "Bob Org"})
    assert org_res_2.status_code == 201, org_res_2.text
    org_id_2 = org_res_2.json()["id"]
    assert org_id_1 != org_id_2

    # Set Organization Context Header
    headers_u1["X-Organization-ID"] = org_id_1
    headers_u2["X-Organization-ID"] = org_id_2

    # -------------------------------------------------------------------------
    # 2. Agent Registration
    # -------------------------------------------------------------------------
    # Alice creates Agent 1A and Agent 1B
    create_agent_1a = client.post("/agents", headers=headers_u1, json={
        "name": "Finance Orchestrator", "description": "High-level finance agent"
    })
    assert create_agent_1a.status_code == 201
    agent_1a = create_agent_1a.json()

    create_agent_1b = client.post("/agents", headers=headers_u1, json={
        "name": "Payment Sub-Worker", "description": "Downstream payment agent"
    })
    assert create_agent_1b.status_code == 201
    agent_1b = create_agent_1b.json()

    # Bob creates Agent 2A in Org 2
    create_agent_2a = client.post("/agents", headers=headers_u2, json={
        "name": "Bob Private Agent", "description": "Bob Org agent"
    })
    assert create_agent_2a.status_code == 201
    agent_2a = create_agent_2a.json()

    # Activate agents in database
    db.get(Agent, UUID(agent_1a["id"])).status = AgentStatus.ACTIVE
    db.get(Agent, UUID(agent_1b["id"])).status = AgentStatus.ACTIVE
    db.get(Agent, UUID(agent_2a["id"])).status = AgentStatus.ACTIVE
    db.commit()

    # -------------------------------------------------------------------------
    # 3. Multi-Tenant Isolation Check
    # -------------------------------------------------------------------------
    # Bob attempts to access Alice's agent -> Must be 404 / 403 Forbidden
    cross_get = client.get(f"/agents/{agent_1a['id']}", headers=headers_u2)
    assert cross_get.status_code in {403, 404}

    # Alice's agents list does not show Bob's agent
    alice_agents = client.get("/agents", headers=headers_u1).json()
    alice_agent_ids = [a["id"] for a in alice_agents]
    assert agent_1a["id"] in alice_agent_ids
    assert agent_1b["id"] in alice_agent_ids
    assert agent_2a["id"] not in alice_agent_ids

    # -------------------------------------------------------------------------
    # 4. Permission Settings
    # -------------------------------------------------------------------------
    now = datetime.now(timezone.utc)
    # Grant Root Permission to Agent 1A: payments:transfer on account:123, max $1000, allow_delegation=True
    perm_payload_1a = {
        "agent_id": agent_1a["id"],
        "action": "payments:transfer",
        "resource": "account:123",
        "maximum_amount": "1000.00",
        "currency": "USD",
        "requires_approval": False,
        "allow_delegation": True,
        "valid_from": (now - timedelta(minutes=5)).isoformat(),
        "expires_at": (now + timedelta(days=7)).isoformat(),
    }
    create_perm_1a = client.post("/permissions", headers=headers_u1, json=perm_payload_1a)
    assert create_perm_1a.status_code == 201
    perm_1a = create_perm_1a.json()

    # Grant High-Risk Permission to Agent 1B: database:drop requiring approval
    perm_payload_1b = {
        "agent_id": agent_1b["id"],
        "action": "database:drop",
        "resource": "db:production",
        "requires_approval": True,
        "allow_delegation": False,
        "valid_from": (now - timedelta(minutes=5)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
    }
    create_perm_1b = client.post("/permissions", headers=headers_u1, json=perm_payload_1b)
    assert create_perm_1b.status_code == 201
    perm_1b = create_perm_1b.json()

    # -------------------------------------------------------------------------
    # 5. Action Authorization & Denial of Unauthorized Actions
    # -------------------------------------------------------------------------
    # Alice's API key
    key_res = client.post("/developer/api-keys", headers=headers_u1, json={"name": "Alice Backend Key"})
    assert key_res.status_code == 201
    api_key_alice = key_res.json()["api_key"]
    api_headers_alice = {"X-API-Key": api_key_alice}

    # Case A: Valid authorized action within limits ($400 < $1000) -> APPROVED
    auth_valid = client.post("/api/v1/authorize", headers=api_headers_alice, json={
        "agent_id": agent_1a["agent_identifier"],
        "action": "payments:transfer",
        "resource": "account:123",
        "amount": "400.00",
        "currency": "USD",
    })
    assert auth_valid.status_code == 200
    assert auth_valid.json()["status"] == "APPROVED"

    # Case B: Unauthorized action not permitted -> REJECTED
    auth_unauthorized_action = client.post("/api/v1/authorize", headers=api_headers_alice, json={
        "agent_id": agent_1a["agent_identifier"],
        "action": "cloud:deploy",
        "resource": "cluster:prod",
    })
    assert auth_unauthorized_action.status_code == 200
    assert auth_unauthorized_action.json()["status"] == "REJECTED"

    # Case C: Exceeding amount limit ($1500 > $1000) -> REJECTED
    auth_limit_exceeded = client.post("/api/v1/authorize", headers=api_headers_alice, json={
        "agent_id": agent_1a["agent_identifier"],
        "action": "payments:transfer",
        "resource": "account:123",
        "amount": "1500.00",
        "currency": "USD",
    })
    assert auth_limit_exceeded.status_code == 200
    assert auth_limit_exceeded.json()["status"] == "REJECTED"

    # -------------------------------------------------------------------------
    # 6. Human Approval & Rejection Flow
    # -------------------------------------------------------------------------
    # Case D: Action requiring human approval -> PENDING
    auth_pending = client.post("/api/v1/authorize", headers=api_headers_alice, json={
        "agent_id": agent_1b["agent_identifier"],
        "action": "database:drop",
        "resource": "db:production",
    })
    assert auth_pending.status_code == 200
    assert auth_pending.json()["status"] == "PENDING"
    pending_req_id = auth_pending.json()["request_id"]

    # Pending request appears in authorization-requests list
    pending_list = client.get("/authorization-requests", headers=headers_u1)
    assert pending_list.status_code == 200
    items = pending_list.json()["items"]
    assert any(r["request_id"] == pending_req_id for r in items)

    # Approve the pending request
    record_db = db.scalar(select(AuthorizationRequestRecord).where(AuthorizationRequestRecord.request_id == pending_req_id))
    approve_res = client.post(f"/authorization-requests/{record_db.id}/approve", headers=headers_u1)
    assert approve_res.status_code == 200
    assert approve_res.json()["status"] == "APPROVED"

    # Subsequent check of request status returns APPROVED
    check_req = client.get(f"/api/v1/authorization-requests/{pending_req_id}", headers=api_headers_alice)
    assert check_req.status_code == 200
    assert check_req.json()["status"] == "APPROVED"

    # -------------------------------------------------------------------------
    # 7. Activity History & Audit Logs
    # -------------------------------------------------------------------------
    audit_res = client.get("/audit-logs", headers=headers_u1)
    assert audit_res.status_code == 200
    logs = audit_res.json()["items"]
    assert len(logs) >= 3
    # Check that audit log recorded decision
    decisions = {l["decision"] for l in logs}
    assert "APPROVED" in decisions
    assert "REJECTED" in decisions

    # -------------------------------------------------------------------------
    # 8. Step 19 Delegation: Monotonic Limits, Authorization & Revocation
    # -------------------------------------------------------------------------
    # 8a: Monotonic Limit: Agent 1A attempts to delegate $1500 (> parent limit $1000) -> Must fail
    delg_escalate = client.post("/agent-delegations", headers=headers_u1, json={
        "parent_agent_id": agent_1a["id"],
        "child_agent_id": agent_1b["id"],
        "parent_permission_id": perm_1a["id"],
        "action": "payments:transfer",
        "resource": "account:123",
        "maximum_amount": "1500.00",
        "currency": "USD",
        "expires_at": (now + timedelta(days=2)).isoformat(),
    })
    assert delg_escalate.status_code == 400
    assert "exceeds parent" in delg_escalate.text.lower()

    # 8b: Cross-Org Delegation Rejected: Agent 1A delegates to Bob's Agent 2A -> Must fail
    delg_cross_org = client.post("/agent-delegations", headers=headers_u1, json={
        "parent_agent_id": agent_1a["id"],
        "child_agent_id": agent_2a["id"],
        "parent_permission_id": perm_1a["id"],
        "action": "payments:transfer",
        "resource": "account:123",
        "maximum_amount": "500.00",
        "currency": "USD",
        "expires_at": (now + timedelta(days=2)).isoformat(),
    })
    assert delg_cross_org.status_code == 400
    assert "cross-organization delegation is strictly forbidden" in delg_cross_org.text.lower()

    # 8c: Valid Delegation Created: Agent 1A delegates $500 to Agent 1B
    delg_create = client.post("/agent-delegations", headers=headers_u1, json={
        "parent_agent_id": agent_1a["id"],
        "child_agent_id": agent_1b["id"],
        "parent_permission_id": perm_1a["id"],
        "action": "payments:transfer",
        "resource": "account:123",
        "maximum_amount": "500.00",
        "currency": "USD",
        "allow_further_delegation": False,
        "expires_at": (now + timedelta(days=2)).isoformat(),
    })
    assert delg_create.status_code == 201
    delegation = delg_create.json()
    delg_id = delegation["delegation_id"]

    # 8d: Child Agent 1B executes delegated action for $350 (< $500) -> APPROVED
    child_req = client.post("/api/v1/authorize", headers=api_headers_alice, json={
        "agent_id": agent_1b["agent_identifier"],
        "action": "payments:transfer",
        "resource": "account:123",
        "amount": "350.00",
        "currency": "USD",
        "delegation_id": delg_id,
    })
    assert child_req.status_code == 200
    assert child_req.json()["status"] == "APPROVED"

    # 8e: Child Agent 1B attempts $600 (> delegated $500) -> REJECTED
    child_over_limit = client.post("/api/v1/authorize", headers=api_headers_alice, json={
        "agent_id": agent_1b["agent_identifier"],
        "action": "payments:transfer",
        "resource": "account:123",
        "amount": "600.00",
        "currency": "USD",
        "delegation_id": delg_id,
    })
    assert child_over_limit.status_code == 200
    assert child_over_limit.json()["status"] == "REJECTED"

    # 8f: Cascade Revocation: Revoking delegation immediately prevents child actions
    revoke_res = client.post(f"/agent-delegations/{delg_id}/revoke", headers=headers_u1, json={
        "reason": "Security rotation"
    })
    assert revoke_res.status_code == 200
    assert revoke_res.json()["status"] == "REVOKED"

    # Subsequent execution by child with revoked delegation is immediately REJECTED
    child_after_revoke = client.post("/api/v1/authorize", headers=api_headers_alice, json={
        "agent_id": agent_1b["agent_identifier"],
        "action": "payments:transfer",
        "resource": "account:123",
        "amount": "100.00",
        "currency": "USD",
        "delegation_id": delg_id,
    })
    assert child_after_revoke.status_code == 200
    assert child_after_revoke.json()["status"] == "REJECTED"
    assert "delegation" in child_after_revoke.json()["reason"].lower()
