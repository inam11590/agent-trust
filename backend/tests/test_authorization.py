"""Authorization engine tests against PostgreSQL; each test rolls back its rows."""

import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.session import create_database_engine, get_db
from app.main import create_app
from app.models import Agent, AgentStatus, Permission, PermissionStatus

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_DATABASE_TESTS") != "1",
    reason="Set RUN_DATABASE_TESTS=1 to test authorization against migrated PostgreSQL.",
)


@pytest.fixture(scope="module")
def engine():
    engine = create_database_engine(Settings())
    yield engine
    engine.dispose()


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
        jwt_secret_key=secrets.token_urlsafe(48),
        postgres_user="",
        postgres_password="",
    )
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as client:
        yield client


def register_and_login(client: TestClient) -> tuple[dict, dict[str, str]]:
    credentials = {
        "email": f"authorization-owner-{uuid4()}@example.com",
        "password": secrets.token_urlsafe(24),
        "full_name": "Authorization Owner",
    }
    user_response = client.post("/auth/register", json=credentials)
    assert user_response.status_code == 201, user_response.text
    login_response = client.post(
        "/auth/login",
        json={"email": credentials["email"], "password": credentials["password"]},
    )
    assert login_response.status_code == 200, login_response.text
    headers = {"Authorization": f"Bearer {login_response.json()['access_token']}"}
    return user_response.json(), headers


def create_active_agent(client: TestClient, db: Session, headers: dict[str, str]) -> dict:
    response = client.post("/agents", json={"name": "Travel Assistant"}, headers=headers)
    assert response.status_code == 201, response.text
    agent = response.json()
    stored = db.get(Agent, UUID(agent["id"]))
    stored.status = AgentStatus.ACTIVE
    db.commit()
    return agent


def grant(
    client: TestClient,
    headers: dict[str, str],
    agent: dict,
    **updates,
) -> dict:
    now = datetime.now(timezone.utc)
    payload = {
        "agent_id": agent["id"],
        "action": "purchase",
        "resource": "flight",
        "maximum_amount": "500.00",
        "currency": "USD",
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=24)).isoformat(),
    }
    payload.update(updates)
    response = client.post("/permissions", json=payload, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def authorization_payload(agent: dict, **updates) -> dict:
    payload = {
        "agent_id": agent["agent_identifier"],
        "action": "purchase",
        "resource": "flight",
        "amount": "420.00",
        "currency": "USD",
    }
    payload.update(updates)
    return payload


def decide(client: TestClient, headers: dict[str, str], agent: dict, **updates):
    return client.post("/authorize", json=authorization_payload(agent, **updates), headers=headers)


def assert_rejected(response, reason: str) -> None:
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "REJECTED"
    assert body["reason"] == reason
    assert re.fullmatch(r"req_[0-9a-f]{24}", body["request_id"])
    assert response.headers["Cache-Control"] == "no-store"


def test_approved_action(client, db):
    _, headers = register_and_login(client)
    agent = create_active_agent(client, db, headers)
    grant(client, headers, agent)
    response = decide(client, headers, agent)
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "APPROVED"
    assert body["reason"] == "Permission valid"
    assert re.fullmatch(r"req_[0-9a-f]{24}", body["request_id"])
    assert response.headers["Cache-Control"] == "no-store"


def test_amount_equal_to_maximum_is_approved(client, db):
    _, headers = register_and_login(client)
    agent = create_active_agent(client, db, headers)
    grant(client, headers, agent)
    assert decide(client, headers, agent, amount="500.00").json()["decision"] == "APPROVED"


def test_amount_too_high(client, db):
    _, headers = register_and_login(client)
    agent = create_active_agent(client, db, headers)
    grant(client, headers, agent)
    assert_rejected(decide(client, headers, agent, amount="500.01"), "Amount exceeds allowed limit")


def test_expired_permission(client, db):
    user, headers = register_and_login(client)
    agent = create_active_agent(client, db, headers)
    now = datetime.now(timezone.utc)
    permission = Permission(
        owner_id=UUID(user["id"]),
        agent_id=UUID(agent["id"]),
        action="purchase",
        resource="flight",
        maximum_amount=Decimal("500"),
        currency="USD",
        valid_from=now - timedelta(hours=25),
        expires_at=now - timedelta(hours=1),
    )
    db.add(permission)
    db.commit()
    assert_rejected(decide(client, headers, agent), "Permission expired")
    db.refresh(permission)
    assert permission.status == PermissionStatus.EXPIRED


def test_revoked_permission(client, db):
    _, headers = register_and_login(client)
    agent = create_active_agent(client, db, headers)
    permission = grant(client, headers, agent)
    revoked = client.post(f"/permissions/{permission['id']}/revoke", headers=headers)
    assert revoked.status_code == 200
    assert_rejected(decide(client, headers, agent), "Permission revoked")


def test_suspended_agent(client, db):
    _, headers = register_and_login(client)
    agent = create_active_agent(client, db, headers)
    grant(client, headers, agent)
    stored = db.get(Agent, UUID(agent["id"]))
    stored.status = AgentStatus.SUSPENDED
    db.commit()
    assert_rejected(decide(client, headers, agent), "Agent is not active")


def test_inactive_agent(client, db):
    _, headers = register_and_login(client)
    response = client.post("/agents", json={"name": "Inactive Agent"}, headers=headers)
    agent = response.json()
    assert_rejected(decide(client, headers, agent), "Agent is not active")


def test_wrong_action(client, db):
    _, headers = register_and_login(client)
    agent = create_active_agent(client, db, headers)
    grant(client, headers, agent)
    assert_rejected(decide(client, headers, agent, action="cancel"), "Action not permitted")


def test_wrong_resource(client, db):
    _, headers = register_and_login(client)
    agent = create_active_agent(client, db, headers)
    grant(client, headers, agent)
    assert_rejected(decide(client, headers, agent, resource="hotel"), "Resource not permitted")


def test_wrong_currency(client, db):
    _, headers = register_and_login(client)
    agent = create_active_agent(client, db, headers)
    grant(client, headers, agent)
    assert_rejected(decide(client, headers, agent, currency="EUR"), "Currency does not match")


def test_missing_permission(client, db):
    _, headers = register_and_login(client)
    agent = create_active_agent(client, db, headers)
    assert_rejected(decide(client, headers, agent), "No permission found")


def test_another_users_permission_is_ignored(client, db):
    owner, owner_headers = register_and_login(client)
    agent = create_active_agent(client, db, owner_headers)
    other, _ = register_and_login(client)
    now = datetime.now(timezone.utc)
    db.add(Permission(
        owner_id=UUID(other["id"]),
        agent_id=UUID(agent["id"]),
        action="purchase",
        resource="flight",
        maximum_amount=Decimal("500"),
        currency="USD",
        valid_from=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=24),
    ))
    db.commit()
    assert owner["id"] != other["id"]
    assert_rejected(decide(client, owner_headers, agent), "No permission found")


def test_another_users_agent_is_not_exposed(client, db):
    _, first_headers = register_and_login(client)
    _, second_headers = register_and_login(client)
    agent = create_active_agent(client, db, second_headers)
    assert_rejected(decide(client, first_headers, agent), "Agent not found")


def test_permission_not_started(client, db):
    _, headers = register_and_login(client)
    agent = create_active_agent(client, db, headers)
    now = datetime.now(timezone.utc)
    grant(
        client,
        headers,
        agent,
        valid_from=(now + timedelta(hours=1)).isoformat(),
        expires_at=(now + timedelta(hours=2)).isoformat(),
    )
    assert_rejected(decide(client, headers, agent), "Permission has not started")


def test_missing_amount_cannot_bypass_a_limit(client, db):
    _, headers = register_and_login(client)
    agent = create_active_agent(client, db, headers)
    grant(client, headers, agent)
    assert_rejected(
        decide(client, headers, agent, amount=None, currency=None),
        "Amount is required for this permission",
    )


def test_non_monetary_permission_approves_only_non_monetary_request(client, db):
    _, headers = register_and_login(client)
    agent = create_active_agent(client, db, headers)
    grant(client, headers, agent, maximum_amount=None, currency=None)
    approved = decide(client, headers, agent, amount=None, currency=None)
    assert approved.json()["decision"] == "APPROVED"
    assert approved.json()["reason"] == "Permission valid"
    assert re.fullmatch(r"req_[0-9a-f]{24}", approved.json()["request_id"])
    assert_rejected(
        decide(client, headers, agent),
        "Permission does not allow an amount",
    )


def test_engine_does_not_combine_limits_from_different_permissions(client, db):
    _, headers = register_and_login(client)
    agent = create_active_agent(client, db, headers)
    grant(client, headers, agent, maximum_amount="500", currency="EUR")
    grant(client, headers, agent, maximum_amount="400", currency="USD")
    assert_rejected(
        decide(client, headers, agent, amount="420", currency="USD"),
        "Amount exceeds allowed limit",
    )


def test_authorize_requires_login(client):
    response = client.post("/authorize", json={
        "agent_id": "agt_" + "a" * 24,
        "action": "purchase",
        "resource": "flight",
        "amount": "420",
        "currency": "USD",
    })
    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials"}


@pytest.mark.parametrize(
    "updates",
    [
        {"amount": "-1"},
        {"amount": None},
        {"currency": None},
        {"currency": "US"},
        {"agent_id": "not-an-agent-id"},
        {"action": "purchase flight"},
        {"extra": "not-allowed"},
    ],
)
def test_invalid_authorization_request_returns_422(client, updates):
    _, headers = register_and_login(client)
    payload = {
        "agent_id": "agt_" + "a" * 24,
        "action": "purchase",
        "resource": "flight",
        "amount": "420",
        "currency": "USD",
    }
    payload.update(updates)
    response = client.post("/authorize", json=payload, headers=headers)
    assert response.status_code == 422
