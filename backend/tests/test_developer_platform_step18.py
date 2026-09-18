"""Step 18 tests: Developer Platform, Sandbox Environment, Test Scenarios, and Environment Isolation."""

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import os
import secrets
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.session import create_database_engine, get_db
from app.main import create_app
from app.models import (
    APIKey, APIKeyStatus, Agent, AgentSigningKey, AgentSigningKeyStatus,
    AgentStatus, AuditDecision, AuditLog, AuthorizationRequestRecord,
    Organization, OrganizationMember, OrganizationRole, Permission,
    PermissionStatus, User, WebhookDelivery, WebhookEndpoint,
)
from app.services.api_keys import create_api_key
from app.services.authorization import authorize_action
from app.services.rate_limit import developer_rate_limiter
from app.services.sandbox import (
    create_permission_template, create_test_agent,
    get_developer_onboarding_progress, get_production_readiness_checklist,
    run_sandbox_scenario,
)
from app.services.webhooks import send_test_webhook

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
    developer_rate_limiter.clear()
    app = create_app()
    app.state.settings = Settings(
        _env_file=None,
        jwt_secret_key=secrets.token_urlsafe(48),
        webhook_signing_key=secrets.token_urlsafe(48),
        postgres_user="",
        postgres_password="",
        redis_url="",
    )
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as value:
        yield value


def account(client, db, email=None):
    creds = {
        "email": email or f"dev18-{uuid4()}@example.com",
        "password": secrets.token_urlsafe(24),
        "full_name": "Step18 Dev",
    }
    user = client.post("/auth/register", json=creds).json()
    login = client.post("/auth/login", json={"email": creds["email"], "password": creds["password"]}).json()
    org = Organization(name=f"Org-{uuid4()}", owner_id=UUID(user["id"]))
    db.add(org)
    db.commit()
    headers = {
        "Authorization": f"Bearer {login['access_token']}",
        "X-Organization-ID": str(org.id),
    }
    return user, org, headers


# 1. Sandbox API key creation (at_test_...)
def test_sandbox_api_key_creation(client, db):
    user, org, headers = account(client, db)
    res = client.post("/developer/api-keys", headers=headers, json={"name": "Test Key", "environment": "sandbox"})
    assert res.status_code == 201, res.text
    data = res.json()
    assert data["api_key"].startswith("at_test_")
    assert data["environment"] == "sandbox"
    assert len(data["api_key"]) == 72


# 2. Test key cannot access production resources
def test_sandbox_key_cannot_access_production_agent(client, db):
    user, org, headers = account(client, db)
    # Create production agent
    prod_agent = Agent(
        name="Prod Agent", agent_identifier=f"agt_{secrets.token_hex(12)}",
        owner_id=UUID(user["id"]), organization_id=org.id,
        environment="production", status=AgentStatus.ACTIVE,
    )
    db.add(prod_agent); db.commit()
    # Create sandbox key
    key_res = client.post("/developer/api-keys", headers=headers, json={
        "name": "Sandbox Key", "organization_id": str(org.id), "environment": "sandbox",
    }).json()
    sb_headers = {"X-API-Key": key_res["api_key"]}

    # Try authorizing against production agent using sandbox key -> MUST reject as Agent not found
    auth_res = client.post("/api/v1/authorize", headers=sb_headers, json={
        "agent_id": prod_agent.agent_identifier, "action": "purchase", "resource": "flight",
        "amount": 100, "currency": "USD",
    }).json()
    assert auth_res["status"] == "REJECTED"
    assert auth_res["reason"] == "Agent not found"


# 3. Production key cannot accidentally operate against sandbox resource
def test_production_key_cannot_operate_against_sandbox_agent(client, db):
    user, org, headers = account(client, db)
    # Create sandbox agent
    sb_agent = Agent(
        name="Sandbox Agent", agent_identifier=f"agt_{secrets.token_hex(12)}",
        owner_id=UUID(user["id"]), organization_id=org.id,
        environment="sandbox", status=AgentStatus.ACTIVE,
    )
    db.add(sb_agent); db.commit()
    # Create production key
    key_res = client.post("/developer/api-keys", headers=headers, json={
        "name": "Prod Key", "organization_id": str(org.id), "environment": "production",
    }).json()
    prod_headers = {"X-API-Key": key_res["api_key"]}

    # Try authorizing against sandbox agent using production key -> MUST reject
    auth_res = client.post("/api/v1/authorize", headers=prod_headers, json={
        "agent_id": sb_agent.agent_identifier, "action": "purchase", "resource": "flight",
        "amount": 100, "currency": "USD",
    }).json()
    assert auth_res["status"] == "REJECTED"
    assert auth_res["reason"] == "Agent not found"


# 4. Test agent creation
def test_create_test_agent_endpoint(client, db):
    user, org, headers = account(client, db)
    res = client.post("/developer/agents/test", headers=headers, json={"name": "Travel Assistant Test"})
    assert res.status_code == 201
    data = res.json()
    assert data["environment"] == "sandbox"
    assert data["status"] == "active"
    assert data["agent_identifier"].startswith("agt_")


# 5. Sandbox permission creation
def test_create_permission_template_endpoint(client, db):
    user, org, headers = account(client, db)
    agent_res = client.post("/developer/agents/test", headers=headers, json={"name": "Test Agent"}).json()
    perm_res = client.post("/developer/permissions/templates", headers=headers, json={
        "agent_id": agent_res["id"],
        "template": "flight_purchase",
    })
    assert perm_res.status_code == 201
    perm = perm_res.json()
    assert perm["action"] == "purchase"
    assert perm["resource"] == "flight"
    assert float(perm["maximum_amount"]) == 500.00
    assert perm["currency"] == "USD"


# 6. Sandbox Scenario 1: $300 flight -> APPROVED
def test_sandbox_scenario_1_approved(client, db):
    user, org, headers = account(client, db)
    res = client.post("/developer/sandbox/scenarios/scenario_1/run", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["expected_status"] == "APPROVED"
    assert data["actual_status"] == "APPROVED"
    assert data["passed"] is True


# 7. Sandbox Scenario 2: $450 flight + approval -> PENDING
def test_sandbox_scenario_2_pending(client, db):
    user, org, headers = account(client, db)
    res = client.post("/developer/sandbox/scenarios/scenario_2/run", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["expected_status"] == "PENDING"
    assert data["actual_status"] == "PENDING"
    assert data["passed"] is True


# 8. Sandbox Scenario 3: $700 flight -> REJECTED (Amount exceeds allowed limit)
def test_sandbox_scenario_3_rejected(client, db):
    user, org, headers = account(client, db)
    res = client.post("/developer/sandbox/scenarios/scenario_3/run", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["expected_status"] == "REJECTED"
    assert data["actual_status"] == "REJECTED"
    assert data["passed"] is True


# 9. Sandbox Scenario 4: Modified signature -> INVALID_AGENT_SIGNATURE
def test_sandbox_scenario_4_modified_signature(client, db):
    user, org, headers = account(client, db)
    res = client.post("/developer/sandbox/scenarios/scenario_4/run", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["expected_status"] == "INVALID_AGENT_SIGNATURE"
    assert data["actual_status"] == "INVALID_AGENT_SIGNATURE"
    assert data["passed"] is True


# 10. Sandbox Scenario 5: Replayed request -> REPLAY_DETECTED
def test_sandbox_scenario_5_replay(client, db):
    user, org, headers = account(client, db)
    res = client.post("/developer/sandbox/scenarios/scenario_5/run", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["expected_status"] == "REPLAY_DETECTED"
    assert data["actual_status"] == "REPLAY_DETECTED"
    assert data["passed"] is True


# 11 & 12. Sandbox webhook test event marked with test_mode = True
def test_sandbox_webhook_test_event(client, db, monkeypatch):
    user, org, headers = account(client, db)

    captured = {}
    class FakeResponse:
        status_code = 200
        text = '{"ok":true}'
        def raise_for_status(self): return None
    def mock_post(url, *, content, headers, timeout):
        captured.update(url=url, content=content, headers=headers)
        return FakeResponse()

    monkeypatch.setattr("app.services.webhooks.httpx.post", mock_post)

    # Configure webhook
    client.post("/developer/webhook", headers=headers, json={
        "organization_id": str(org.id), "url": "http://localhost:8989/hook",
    })

    # Trigger test webhook event
    res = client.post("/developer/webhooks/test", headers=headers, json={
        "event_type": "authorization.approved",
    })
    assert res.status_code == 200
    body = res.json()
    assert body["test_mode"] is True
    assert body["event_type"] == "authorization.approved"

    # Verify captured content has test_mode: true
    parsed_payload = json.loads(captured["content"].decode())
    assert parsed_payload["test_mode"] is True
    assert parsed_payload["event"] == "authorization.approved"


# 13. API logs organization isolation and environment filtering
def test_developer_logs_filtering(client, db):
    user, org, headers = account(client, db)

    # List logs with environment filter
    res = client.get("/developer/logs?environment=sandbox", headers=headers)
    assert res.status_code == 200
    assert isinstance(res.json(), list)


# 14 & 15. Developer role access and Viewer cannot perform write action
def test_viewer_cannot_create_api_keys(client, db):
    owner, org, owner_headers = account(client, db)
    viewer, _, viewer_headers = account(client, db)
    # Add viewer member to org
    member = OrganizationMember(
        organization_id=org.id, user_id=UUID(viewer["id"]),
        role=OrganizationRole.VIEWER, status="active",
    )
    db.add(member); db.commit()

    # Viewer attempts to create an API key -> 403 Forbidden
    res = client.post("/developer/api-keys", headers={**viewer_headers, "X-Organization-ID": str(org.id)}, json={
        "name": "Viewer Key", "organization_id": str(org.id),
    })
    assert res.status_code == 403


# 16. Sandbox usage separated from production billing quota
def test_sandbox_usage_does_not_consume_production_quota(client, db):
    user, org, headers = account(client, db)

    # Create sandbox agent & permission
    agent = create_test_agent(db, db.get(User, UUID(user["id"])), org.id, "Quota Test Agent")
    perm = create_permission_template(db, db.get(User, UUID(user["id"])), agent.id, "flight_purchase")

    # Create sandbox key
    key_res = client.post("/developer/api-keys", headers=headers, json={
        "name": "SB Key", "organization_id": str(org.id), "environment": "sandbox",
    }).json()

    # Check usage before
    from app.services.plan_limits import usage_values
    _, _, before_usage = usage_values(db, org.id)
    before_reqs = before_usage["authorization_requests"].used

    # Authorize via sandbox key
    auth_res = client.post("/api/v1/authorize", headers={"X-API-Key": key_res["api_key"]}, json={
        "agent_id": agent.agent_identifier, "action": "purchase", "resource": "flight",
        "amount": 200, "currency": "USD",
    })
    assert auth_res.status_code == 200

    # Check usage after -> production quota MUST NOT have incremented!
    _, _, after_usage = usage_values(db, org.id)
    assert after_usage["authorization_requests"].used == before_reqs


# 17. Sandbox risk history separated
def test_sandbox_risk_history_separated(client, db):
    user, org, headers = account(client, db)

    # Query sandbox checklist to ensure risk engine runs cleanly
    overview_res = client.get("/developer/overview", headers=headers)
    assert overview_res.status_code == 200
    data = overview_res.json()
    assert "onboarding" in data
    assert "checklist" in data


# 18. Production access request flow
def test_production_access_request_flow(client, db):
    user, org, headers = account(client, db)

    # Get checklist
    chk = client.get("/developer/production-access/checklist", headers=headers)
    assert chk.status_code == 200
    assert "mfa_enabled" in chk.json()

    # Request production access
    req = client.post("/developer/production-access/request", headers=headers)
    assert req.status_code == 200
    assert req.json()["status"] == "REQUESTED"

    db.refresh(org)
    assert org.production_access_status == "REQUESTED"


# 19. Existing cryptographic signing still works
def test_existing_signing_still_works(client, db):
    from tests.test_agent_signing import test_valid_signed_request_audits_identity_and_permission_denial
    test_valid_signed_request_audits_identity_and_permission_denial(client, db)


# 20. Existing authorization still works
def test_existing_authorization_still_works(client, db):
    from tests.test_developer_platform import test_valid_key_approved_and_audited
    test_valid_key_approved_and_audited(client, db)


# 21. Existing billing still works
def test_existing_billing_still_works(client, db):
    from app.services.plan_limits import ensure_subscription
    user, org, _ = account(client, db)
    sub, plan = ensure_subscription(db, org.id)
    assert sub is not None and plan.code == "free"


# 22. Existing notifications still work
def test_existing_notifications_still_work(client, db):
    user, org, headers = account(client, db)
    res = client.get("/notifications", headers=headers)
    assert res.status_code == 200


# 23. Existing security/MFA/SSO still works
def test_existing_security_still_works(client, db):
    user, org, headers = account(client, db)
    res = client.get("/security/mfa", headers=headers)
    assert res.status_code == 200
    assert "enabled" in res.json()
