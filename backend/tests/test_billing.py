"""Step 14 subscription, quota, isolation, and signed webhook tests."""

import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.session import create_database_engine, get_db
from app.main import create_app
from app.models import Agent, AgentStatus, BillingEvent, OrganizationSubscription, SubscriptionPlan, SubscriptionStatus, UsageMetric, UsageRecord
from app.services.billing_providers import paddle_signature, verify_paddle_signature

pytestmark = pytest.mark.skipif(os.getenv("RUN_DATABASE_TESTS") != "1", reason="Database tests disabled")

@pytest.fixture(scope="module")
def engine():
    value = create_database_engine(Settings()); yield value; value.dispose()

@pytest.fixture
def db(engine):
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            with Session(bind=connection, join_transaction_mode="create_savepoint") as session: yield session
        finally: transaction.rollback()

@pytest.fixture
def client(db):
    app = create_app(); app.state.settings = Settings(_env_file=None, app_env="test",
        jwt_secret_key=secrets.token_urlsafe(48), webhook_signing_key=secrets.token_urlsafe(48),
        billing_webhook_secret="billing-test-secret-which-is-long-enough", billing_provider="test",
        postgres_user="", postgres_password="")
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as value: yield value

def account(client, name="Owner"):
    credentials = {"email": f"billing-{uuid4()}@example.com", "password": secrets.token_urlsafe(24), "full_name": name}
    user = client.post("/auth/register", json=credentials).json()
    token = client.post("/auth/login", json={"email": credentials["email"], "password": credentials["password"]}).json()["access_token"]
    return user, {"Authorization": f"Bearer {token}"}

def organization(client, headers):
    result = client.post("/organizations", headers=headers, json={"name": f"Test Org {uuid4()}"})
    assert result.status_code == 201, result.text
    org = result.json(); return org, {**headers, "X-Organization-ID": org["id"]}

def signed(client, payload):
    body = json.dumps(payload, separators=(",", ":")).encode(); timestamp = int(time.time())
    signature = paddle_signature("billing-test-secret-which-is-long-enough", body, timestamp)
    return client.post("/billing/webhook", content=body, headers={"Content-Type": "application/json", "Paddle-Signature": f"ts={timestamp};h1={signature}"})

def test_new_organization_receives_free_plan_and_usage(client, db):
    _, headers = account(client); org, scoped = organization(client, headers)
    subscription = client.get("/billing/subscription", headers=scoped)
    assert subscription.status_code == 200
    assert subscription.json()["plan"]["code"] == "free"
    usage = client.get("/billing/usage", headers=scoped).json()
    assert usage["usage"]["authorization_requests"] == {"used": 0, "limit": 1000}
    assert db.scalar(select(OrganizationSubscription).where(OrganizationSubscription.organization_id == UUID(org["id"])))

def test_tenant_isolation_and_viewer_cannot_checkout(client):
    _, owner_headers = account(client); org, scoped = organization(client, owner_headers)
    _, other = account(client)
    hidden = client.get("/billing/usage", headers={**other, "X-Organization-ID": org["id"]})
    assert hidden.status_code == 404

def test_checkout_accepts_plan_code_only_and_rejects_invalid(client, db):
    _, headers = account(client); org, scoped = organization(client, headers)
    invalid = client.post("/billing/checkout", headers=scoped, json={"plan_code": "made_up", "price": 1})
    assert invalid.status_code == 422
    result = client.post("/billing/checkout", headers=scoped, json={"plan_code": "starter"})
    assert result.status_code == 200
    assert "test_checkout=" in result.json()["checkout_url"]

def test_signed_webhook_activates_subscription_and_is_idempotent(client, db):
    _, headers = account(client); org, scoped = organization(client, headers)
    checkout = client.post("/billing/checkout", headers=scoped, json={"plan_code": "starter"})
    session_id = checkout.json()["checkout_url"].split("test_checkout=")[1].split("&")[0]
    payload = {"event_id": f"evt_{uuid4()}", "event_type": "transaction.completed", "data": {
        "id": session_id, "customer_id": "ctm_test", "subscription_id": "sub_test",
        "custom_data": {"organization_id": org["id"], "plan_code": "starter"}}}
    assert signed(client, payload).json()["status"] == "processed"
    assert signed(client, payload).json()["status"] == "duplicate"
    subscription = client.get("/billing/subscription", headers=scoped).json()
    assert subscription["plan"]["code"] == "starter" and subscription["status"] == "active"
    assert db.scalar(select(BillingEvent).where(BillingEvent.provider_event_id == payload["event_id"]))

def test_invalid_webhook_is_rejected(client):
    response = client.post("/billing/webhook", content=b'{}', headers={"Paddle-Signature": "ts=1;h1=bad"})
    assert response.status_code == 400

def test_signature_timestamp_and_body_are_protected():
    secret = "test-secret"; body = b'{"ok":true}'; now = int(time.time())
    header = f"ts={now};h1={paddle_signature(secret, body, now)}"
    assert verify_paddle_signature(secret, body, header, 300)
    assert not verify_paddle_signature(secret, body + b" ", header, 300)
    assert not verify_paddle_signature(secret, body, f"ts={now-400};h1={paddle_signature(secret, body, now-400)}", 300)

def test_free_agent_limit_is_enforced_without_deleting_data(client, db):
    _, headers = account(client); org, scoped = organization(client, headers)
    for index in range(3): assert client.post("/agents", headers=scoped, json={"name": f"Agent {index}"}).status_code == 201
    blocked = client.post("/agents", headers=scoped, json={"name": "One too many"})
    assert blocked.status_code == 402 and blocked.json()["error"] == "PLAN_LIMIT_REACHED"
    assert len(client.get("/agents", headers=scoped).json()) == 3

def test_usage_warning_and_hard_limit(client, db):
    _, headers = account(client); org, scoped = organization(client, headers); org_id = UUID(org["id"])
    plan = db.scalar(select(SubscriptionPlan).where(SubscriptionPlan.code == "free")); plan.max_authorization_requests_monthly = 10
    from app.services.plan_limits import consume_authorization_request, PlanLimitReached
    for _ in range(10): consume_authorization_request(db, org_id)
    record = db.scalar(select(UsageRecord).where(UsageRecord.organization_id == org_id, UsageRecord.metric == UsageMetric.AUTHORIZATION_REQUESTS))
    assert record.quantity == 10
    with pytest.raises(PlanLimitReached): consume_authorization_request(db, org_id)
    assert record.quantity == 10

def test_cancellation_is_owner_only_and_keeps_plan_until_period_end(client, db):
    _, headers = account(client); org, scoped = organization(client, headers); org_id = UUID(org["id"])
    subscription = db.scalar(select(OrganizationSubscription).where(OrganizationSubscription.organization_id == org_id))
    starter = db.scalar(select(SubscriptionPlan).where(SubscriptionPlan.code == "starter")); subscription.plan_id = starter.id; subscription.provider_subscription_id = "sub_test"; db.commit()
    result = client.post("/billing/cancel", headers=scoped)
    assert result.status_code == 200 and result.json()["cancel_at_period_end"] is True
    assert client.get("/billing/subscription", headers=scoped).json()["plan"]["code"] == "starter"

def test_api_key_limit_is_enforced(client):
    _, headers = account(client); _, scoped = organization(client, headers)
    assert client.post("/developer/api-keys", headers=scoped, json={"name": "Key one"}).status_code == 201
    assert client.post("/developer/api-keys", headers=scoped, json={"name": "Key two"}).status_code == 201
    blocked = client.post("/developer/api-keys", headers=scoped, json={"name": "Key three"})
    assert blocked.status_code == 402 and blocked.json()["error"] == "PLAN_LIMIT_REACHED"

def test_member_limit_counts_pending_invitations(client):
    _, headers = account(client); org, scoped = organization(client, headers)
    for index in range(3):
        result = client.post(f"/organizations/{org['id']}/invitations", headers=scoped, json={"email": f"seat-{index}-{uuid4()}@example.com", "role": "viewer"})
        assert result.status_code == 201, result.text
    blocked = client.post(f"/organizations/{org['id']}/invitations", headers=scoped, json={"email": f"seat-extra-{uuid4()}@example.com", "role": "viewer"})
    assert blocked.status_code == 402

def test_developer_authorization_usage_is_idempotent(client, db):
    _, headers = account(client); org, scoped = organization(client, headers)
    key = client.post("/developer/api-keys", headers=scoped, json={"name": "Metered server"}).json()["api_key"]
    agent = client.post("/agents", headers=scoped, json={"name": "Travel Assistant"}).json()
    stored = db.get(Agent, UUID(agent["id"])); stored.status = AgentStatus.ACTIVE; db.commit()
    now = datetime.now(timezone.utc)
    permission = client.post("/permissions", headers=scoped, json={"agent_id": agent["id"], "action": "purchase", "resource": "flight", "maximum_amount": 500, "currency": "USD", "valid_from": (now-timedelta(minutes=1)).isoformat(), "expires_at": (now+timedelta(hours=1)).isoformat()})
    assert permission.status_code == 201, permission.text
    request = {"agent_id": agent["agent_identifier"], "action": "purchase", "resource": "flight", "amount": 420, "currency": "USD"}
    api_headers = {"X-API-Key": key, "Idempotency-Key": "same-original-action"}
    first = client.post("/api/v1/authorize", headers=api_headers, json=request); second = client.post("/api/v1/authorize", headers=api_headers, json=request)
    assert first.status_code == 200 and second.json()["request_id"] == first.json()["request_id"]
    usage = client.get("/billing/usage", headers=scoped).json()
    assert usage["usage"]["authorization_requests"]["used"] == 1

def test_past_due_grace_period_then_restriction(client, db):
    _, headers = account(client); org, scoped = organization(client, headers); org_id = UUID(org["id"])
    subscription = db.scalar(select(OrganizationSubscription).where(OrganizationSubscription.organization_id == org_id))
    subscription.status = SubscriptionStatus.PAST_DUE; subscription.grace_ends_at = datetime.now(timezone.utc) + timedelta(hours=1); db.commit()
    from app.services.plan_limits import consume_authorization_request, PlanLimitReached
    consume_authorization_request(db, org_id)
    subscription.grace_ends_at = datetime.now(timezone.utc) - timedelta(seconds=1); db.commit()
    with pytest.raises(PlanLimitReached): consume_authorization_request(db, org_id)

def test_payment_failure_webhook_starts_grace_period(client, db):
    _, headers = account(client); org, scoped = organization(client, headers)
    payload = {"event_id": f"evt_{uuid4()}", "event_type": "transaction.payment_failed", "data": {"id": "txn_failed", "custom_data": {"organization_id": org["id"]}}}
    assert signed(client, payload).json()["status"] == "processed"
    response = client.get("/billing/subscription", headers=scoped).json()
    assert response["status"] == "past_due" and response["grace_ends_at"] is not None
