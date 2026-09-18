"""Developer API key, versioned API, idempotency, and webhook tests."""

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.session import create_database_engine, get_db
from app.main import create_app
from app.models import (
    APIKey, APIKeyStatus, Agent, AgentStatus, AuditLog, DeveloperRequest,
    Organization, WebhookDelivery,
)
from app.services.rate_limit import developer_rate_limiter
from app.services.webhooks import sign_webhook, verify_webhook_signature

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
        _env_file=None, jwt_secret_key=secrets.token_urlsafe(48),
        webhook_signing_key=secrets.token_urlsafe(48),
        postgres_user="", postgres_password="",
    )
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as value:
        yield value


def account(client):
    credentials = {"email": f"dev-{uuid4()}@example.com", "password": secrets.token_urlsafe(24), "full_name": "Developer"}
    user = client.post("/auth/register", json=credentials).json()
    login = client.post("/auth/login", json={"email": credentials["email"], "password": credentials["password"]}).json()
    return user, {"Authorization": f"Bearer {login['access_token']}"}


def create_key(client, headers, **changes):
    response = client.post("/developer/api-keys", headers=headers, json={"name": "Production Backend", **changes})
    assert response.status_code == 201, response.text
    body = response.json()
    return body, {"X-API-Key": body["api_key"]}


def setup_agent(client, db, headers, organization_id=None, approval=False):
    agent = client.post("/agents", headers=headers, json={"name": "Travel Assistant", "organization_id": organization_id}).json()
    db.get(Agent, UUID(agent["id"])).status = AgentStatus.ACTIVE
    db.commit()
    now = datetime.now(timezone.utc)
    response = client.post("/permissions", headers=headers, json={
        "agent_id": agent["id"], "action": "purchase", "resource": "flight",
        "maximum_amount": 500, "currency": "USD", "requires_approval": approval,
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
    })
    assert response.status_code == 201, response.text
    return agent


def authorize(client, key_headers, agent, amount=420, idempotency=None):
    headers = dict(key_headers)
    if idempotency:
        headers["Idempotency-Key"] = idempotency
    return client.post("/api/v1/authorize", headers=headers, json={
        "agent_id": agent["agent_identifier"], "action": "purchase",
        "resource": "flight", "amount": amount, "currency": "USD",
    })


def test_key_is_shown_once_and_only_hash_is_stored(client, db):
    user, headers = account(client)
    created, _ = create_key(client, headers)
    stored = db.get(APIKey, UUID(created["id"]))
    assert created["api_key"].startswith("at_live_")
    assert stored.key_hash == hashlib.sha256(created["api_key"].encode()).hexdigest()
    assert stored.created_by_user_id == UUID(user["id"])
    listed = client.get("/developer/api-keys", headers=headers).json()[0]
    assert "api_key" not in listed and "key_hash" not in listed


def test_valid_key_approved_and_audited(client, db):
    _, headers = account(client)
    created, key_headers = create_key(client, headers)
    agent = setup_agent(client, db, headers)
    result = authorize(client, key_headers, agent)
    assert result.status_code == 200 and result.json()["status"] == "APPROVED"
    assert db.scalar(select(AuditLog).where(AuditLog.request_id == result.json()["request_id"])) is not None
    db.refresh(db.get(APIKey, UUID(created["id"])))
    assert db.get(APIKey, UUID(created["id"])).last_used_at is not None


def test_invalid_revoked_and_expired_keys_are_rejected(client, db):
    _, headers = account(client)
    created, key_headers = create_key(client, headers)
    invalid = {"X-API-Key": "at_live_" + "x" * 64}
    assert client.get("/api/v1/authorization-requests/req_" + "a" * 24, headers=invalid).status_code == 401
    client.post(f"/developer/api-keys/{created['id']}/revoke", headers=headers)
    assert client.get("/api/v1/authorization-requests/req_" + "a" * 24, headers=key_headers).status_code == 401
    second, second_headers = create_key(client, headers, name="Expiring")
    record = db.get(APIKey, UUID(second["id"]))
    record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    assert client.get("/api/v1/authorization-requests/req_" + "a" * 24, headers=second_headers).status_code == 401
    db.refresh(record)
    assert record.status == APIKeyStatus.EXPIRED


def test_organization_scope_blocks_other_organization(client, db):
    user, headers = account(client)
    first = Organization(name="Company A", owner_id=UUID(user["id"]))
    second = Organization(name="Company B", owner_id=UUID(user["id"]))
    db.add_all([first, second]); db.commit()
    _, key_headers = create_key(client, headers, organization_id=str(first.id))
    agent = setup_agent(client, db, headers, str(second.id))
    result = authorize(client, key_headers, agent).json()
    assert result["status"] == "REJECTED" and result["reason"] == "Agent not found"


def test_rejected_and_pending_developer_results(client, db):
    _, headers = account(client)
    _, key_headers = create_key(client, headers)
    automatic = setup_agent(client, db, headers)
    rejected = authorize(client, key_headers, automatic, 700).json()
    assert rejected["status"] == "REJECTED" and rejected["reason"] == "Amount exceeds allowed limit"
    manual = setup_agent(client, db, headers, approval=True)
    pending = authorize(client, key_headers, manual).json()
    assert pending["status"] == "PENDING" and pending["reason"] == "User approval required"


def test_pending_status_changes_after_existing_mobile_approval(client, db):
    _, headers = account(client)
    _, key_headers = create_key(client, headers)
    agent = setup_agent(client, db, headers, approval=True)
    pending = authorize(client, key_headers, agent).json()
    item = client.get("/authorization-requests?status=PENDING", headers=headers).json()["items"][0]
    assert client.post(f"/authorization-requests/{item['id']}/approve", headers=headers).json()["status"] == "APPROVED"
    status = client.get(f"/api/v1/authorization-requests/{pending['request_id']}", headers=key_headers).json()
    assert status == {"request_id": pending["request_id"], "status": "APPROVED", "reason": "Approved by user"}


def test_request_status_is_private_to_the_creating_key(client, db):
    _, headers = account(client)
    _, first = create_key(client, headers)
    _, second = create_key(client, headers, name="Second")
    agent = setup_agent(client, db, headers)
    request_id = authorize(client, first, agent).json()["request_id"]
    assert client.get(f"/api/v1/authorization-requests/{request_id}", headers=second).status_code == 404


def test_idempotency_reuses_result_and_rejects_changed_payload(client, db):
    _, headers = account(client)
    created, key_headers = create_key(client, headers)
    agent = setup_agent(client, db, headers)
    first = authorize(client, key_headers, agent, idempotency="checkout-123")
    second = authorize(client, key_headers, agent, idempotency="checkout-123")
    assert first.json() == second.json()
    count = db.scalar(select(func.count()).select_from(DeveloperRequest).where(DeveloperRequest.api_key_id == UUID(created["id"])))
    assert count == 1
    assert authorize(client, key_headers, agent, 421, "checkout-123").status_code == 409


def test_rate_limit_is_per_key(client, db):
    _, headers = account(client)
    _, key_headers = create_key(client, headers)
    agent = setup_agent(client, db, headers)
    client.app.state.settings.developer_rate_limit_per_minute = 2
    assert authorize(client, key_headers, agent).status_code == 200
    assert authorize(client, key_headers, agent).status_code == 200
    limited = authorize(client, key_headers, agent)
    assert limited.status_code == 429 and limited.json()["detail"] == "Rate limit exceeded."


@pytest.mark.parametrize("payload", [
    {},
    {"agent_id": "bad", "action": "purchase", "resource": "flight"},
    {"agent_id": "agt_" + "a" * 24, "action": "", "resource": "flight"},
    {"agent_id": "agt_" + "a" * 24, "action": "purchase", "resource": ""},
    {"agent_id": "agt_" + "a" * 24, "action": "purchase", "resource": "flight", "amount": -1, "currency": "USD"},
    {"agent_id": "agt_" + "a" * 24, "action": "purchase", "resource": "flight", "amount": 1, "currency": "US"},
])
def test_request_validation(client, payload):
    _, headers = account(client)
    _, key_headers = create_key(client, headers)
    assert client.post("/api/v1/authorize", headers=key_headers, json=payload).status_code == 422


def test_webhook_signature_detects_payload_changes():
    secret = "whsec_test"
    approved = sign_webhook(secret, 1700000000, b'{"status":"APPROVED"}')
    assert approved == sign_webhook(secret, 1700000000, b'{"status":"APPROVED"}')
    assert approved != sign_webhook(secret, 1700000000, b'{"status":"REJECTED"}')
    now = datetime.fromtimestamp(1700000000, tz=timezone.utc)
    assert verify_webhook_signature(
        secret, f"t=1700000000,v1={approved}", b'{"status":"APPROVED"}', now=now,
    )
    old = sign_webhook(secret, 1699999000, b'{"status":"APPROVED"}')
    assert not verify_webhook_signature(
        secret, f"t=1699999000,v1={old}", b'{"status":"APPROVED"}', now=now,
    )


def test_mobile_decision_sends_signed_webhook(client, db, monkeypatch):
    user, headers = account(client)
    organization = Organization(name="Webhook Company", owner_id=UUID(user["id"]))
    db.add(organization)
    db.commit()
    workspace_headers = {**headers, "X-Organization-ID": str(organization.id)}
    configured = client.post("/developer/webhook", headers=headers, json={
        "organization_id": str(organization.id),
        "url": "http://localhost:9999/agenttrust",
    })
    assert configured.status_code == 201
    signing_secret = configured.json()["signing_secret"]
    captured = {}

    class SuccessfulResponse:
        def raise_for_status(self):
            return None

    def fake_post(url, *, content, headers, timeout):
        captured.update(url=url, content=content, headers=headers, timeout=timeout)
        return SuccessfulResponse()

    monkeypatch.setattr("app.services.webhooks.httpx.post", fake_post)
    _, key_headers = create_key(client, headers, organization_id=str(organization.id))
    automatic_agent = setup_agent(client, db, headers, str(organization.id))
    automatic = authorize(client, key_headers, automatic_agent).json()
    automatic_delivery = db.scalar(select(WebhookDelivery).where(
        WebhookDelivery.request_id == automatic["request_id"],
    ))
    assert automatic_delivery is not None and automatic_delivery.status == "delivered"

    agent = setup_agent(client, db, headers, str(organization.id), approval=True)
    request = client.post("/authorize", headers=workspace_headers, json={
        "agent_id": agent["agent_identifier"], "action": "purchase",
        "resource": "flight", "amount": 420, "currency": "USD",
    }).json()
    item = client.get("/authorization-requests?status=PENDING", headers=workspace_headers).json()["items"][0]
    decided = client.post(f"/authorization-requests/{item['id']}/approve", headers=workspace_headers)
    assert decided.status_code == 200
    delivery = db.scalar(select(WebhookDelivery).where(WebhookDelivery.request_id == request["request_id"]))
    assert delivery is not None and delivery.status == "delivered" and delivery.attempt_count == 1
    timestamp, signature = captured["headers"]["AgentTrust-Signature"].split(",")
    timestamp_value = int(timestamp.removeprefix("t="))
    assert signature == "v1=" + sign_webhook(signing_secret, timestamp_value, captured["content"])
