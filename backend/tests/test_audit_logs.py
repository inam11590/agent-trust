"""Audit history tests against PostgreSQL; each test rolls back its rows."""

import os
import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.session import create_database_engine, get_db
from app.main import create_app
from app.models import Agent, AgentStatus, AuditDecision, AuditLog

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_DATABASE_TESTS") != "1",
    reason="Set RUN_DATABASE_TESTS=1 to test audit logs against migrated PostgreSQL.",
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
    with TestClient(app) as test_client:
        yield test_client


def register_and_login(client: TestClient, full_name: str = "Inam") -> tuple[dict, dict[str, str]]:
    credentials = {
        "email": f"audit-owner-{uuid4()}@example.com",
        "password": secrets.token_urlsafe(24),
        "full_name": full_name,
    }
    user = client.post("/auth/register", json=credentials)
    assert user.status_code == 201, user.text
    login = client.post(
        "/auth/login",
        json={"email": credentials["email"], "password": credentials["password"]},
    )
    assert login.status_code == 200, login.text
    return user.json(), {"Authorization": f"Bearer {login.json()['access_token']}"}


def create_travel_agent(client: TestClient, db: Session, headers: dict[str, str]) -> dict:
    response = client.post(
        "/agents", json={"name": "Travel Assistant"}, headers=headers,
    )
    assert response.status_code == 201, response.text
    agent = response.json()
    stored = db.get(Agent, UUID(agent["id"]))
    stored.status = AgentStatus.ACTIVE
    db.commit()
    return agent


def grant_flight_permission(client: TestClient, headers: dict[str, str], agent: dict) -> dict:
    now = datetime.now(timezone.utc)
    response = client.post("/permissions", headers=headers, json={
        "agent_id": agent["id"],
        "action": "purchase",
        "resource": "flight",
        "maximum_amount": "500",
        "currency": "USD",
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=24)).isoformat(),
    })
    assert response.status_code == 201, response.text
    return response.json()


def authorize(
    client: TestClient,
    headers: dict[str, str],
    agent: dict,
    amount: str = "420",
    **updates,
):
    payload = {
        "agent_id": agent["agent_identifier"],
        "action": "purchase",
        "resource": "flight",
        "amount": amount,
        "currency": "USD",
    }
    payload.update(updates)
    return client.post("/authorize", headers=headers, json=payload)


def setup_permission(client: TestClient, db: Session):
    user, headers = register_and_login(client)
    agent = create_travel_agent(client, db, headers)
    permission = grant_flight_permission(client, headers, agent)
    return user, headers, agent, permission


def test_approved_authorization_creates_complete_audit_log(client, db):
    user, headers, agent, permission = setup_permission(client, db)
    response = authorize(client, headers, agent)
    assert response.status_code == 200, response.text
    result = response.json()
    stored = db.scalar(select(AuditLog).where(AuditLog.request_id == result["request_id"]))

    assert result["decision"] == "APPROVED"
    assert result["reason"] == "Permission valid"
    assert stored is not None
    assert stored.user_id == UUID(user["id"])
    assert stored.agent_id == UUID(agent["id"])
    assert stored.agent_identifier == agent["agent_identifier"]
    assert stored.permission_id == UUID(permission["id"])
    assert stored.action == "purchase"
    assert stored.resource == "flight"
    assert stored.amount == Decimal("420")
    assert stored.currency == "USD"
    assert stored.decision == AuditDecision.APPROVED


def test_rejected_authorization_saves_exact_reason(client, db):
    _, headers, agent, permission = setup_permission(client, db)
    response = authorize(client, headers, agent, amount="700")
    result = response.json()
    stored = db.scalar(select(AuditLog).where(AuditLog.request_id == result["request_id"]))

    assert result["decision"] == "REJECTED"
    assert result["reason"] == "Amount exceeds allowed limit"
    assert stored.decision == AuditDecision.REJECTED
    assert stored.reason == "Amount exceeds allowed limit"
    assert stored.permission_id == UUID(permission["id"])
    assert stored.amount == Decimal("700")


def test_request_ids_are_unique(client, db):
    _, headers, agent, _ = setup_permission(client, db)
    request_ids = {authorize(client, headers, agent).json()["request_id"] for _ in range(10)}
    assert len(request_ids) == 10
    assert db.scalar(select(func.count()).select_from(AuditLog)) == 10


def test_user_reads_only_their_own_audit_logs(client, db):
    _, owner_headers, agent, _ = setup_permission(client, db)
    audit_id = authorize(client, owner_headers, agent).json()["request_id"]
    owner_list = client.get("/audit-logs", headers=owner_headers)
    stored_id = owner_list.json()["items"][0]["id"]
    assert owner_list.json()["total"] == 1
    assert owner_list.json()["items"][0]["request_id"] == audit_id
    assert client.get(f"/audit-logs/{stored_id}", headers=owner_headers).status_code == 200

    _, other_headers = register_and_login(client, "Other User")
    assert client.get("/audit-logs", headers=other_headers).json()["items"] == []
    assert client.get(f"/audit-logs/{stored_id}", headers=other_headers).status_code == 404
    assert client.get(
        f"/agents/{agent['agent_identifier']}/audit-logs", headers=other_headers,
    ).status_code == 404


@pytest.mark.parametrize("decision,expected", [("APPROVED", 1), ("REJECTED", 1)])
def test_decision_filter(client, db, decision, expected):
    _, headers, agent, _ = setup_permission(client, db)
    authorize(client, headers, agent, amount="420")
    authorize(client, headers, agent, amount="700")
    response = client.get(f"/audit-logs?decision={decision}", headers=headers)
    body = response.json()
    assert response.status_code == 200
    assert body["total"] == expected
    assert all(item["decision"] == decision for item in body["items"])


def test_agent_audit_history_and_basic_filters(client, db):
    _, headers, agent, _ = setup_permission(client, db)
    authorize(client, headers, agent)
    response = client.get(
        f"/agents/{agent['agent_identifier']}/audit-logs"
        "?action=PURCHASE&resource=FLIGHT",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["agent_identifier"] == agent["agent_identifier"]


def test_pagination_is_bounded_and_reports_totals(client, db):
    _, headers, agent, _ = setup_permission(client, db)
    for amount in ("100", "200", "300", "600", "700"):
        authorize(client, headers, agent, amount=amount)

    first = client.get("/audit-logs?page=1&page_size=2", headers=headers).json()
    second = client.get("/audit-logs?page=2&page_size=2", headers=headers).json()
    assert (first["page"], first["page_size"], first["total"], first["total_pages"]) == (1, 2, 5, 3)
    assert len(first["items"]) == len(second["items"]) == 2
    assert {item["id"] for item in first["items"]}.isdisjoint(
        item["id"] for item in second["items"]
    )
    assert client.get("/audit-logs?page_size=101", headers=headers).status_code == 422


def test_rejected_unknown_agent_is_still_audited(client, db):
    user, headers = register_and_login(client)
    identifier = "agt_" + "a" * 24
    response = client.post("/authorize", headers=headers, json={
        "agent_id": identifier,
        "action": "purchase",
        "resource": "flight",
        "amount": "420",
        "currency": "USD",
    })
    stored = db.scalar(select(AuditLog).where(
        AuditLog.request_id == response.json()["request_id"],
    ))
    assert response.json()["reason"] == "Agent not found"
    assert stored.user_id == UUID(user["id"])
    assert stored.agent_id is None
    assert stored.agent_identifier == identifier


def test_audit_logs_have_no_normal_write_or_delete_api(client, db):
    _, headers, agent, _ = setup_permission(client, db)
    authorize(client, headers, agent)
    audit = client.get("/audit-logs", headers=headers).json()["items"][0]

    assert client.patch(
        f"/audit-logs/{audit['id']}", headers=headers, json={"reason": "changed"},
    ).status_code == 405
    assert client.delete(f"/audit-logs/{audit['id']}", headers=headers).status_code == 405
    unchanged = client.get(f"/audit-logs/{audit['id']}", headers=headers).json()
    assert unchanged["reason"] == "Permission valid"


def test_audit_routes_require_login(client):
    assert client.get("/audit-logs").status_code == 401
    assert client.get(f"/audit-logs/{uuid4()}").status_code == 401
    assert client.get("/agents/agt_aaaaaaaaaaaaaaaaaaaaaaaa/audit-logs").status_code == 401
