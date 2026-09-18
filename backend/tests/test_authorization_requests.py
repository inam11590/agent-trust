"""Manual approval workflow tests against migrated PostgreSQL."""

import os
import secrets
from datetime import datetime, timedelta, timezone
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
    AuditDecision,
    AuditLog,
    AuthorizationRequestRecord,
    AuthorizationRequestStatus,
    Permission,
    PermissionStatus,
)

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_DATABASE_TESTS") != "1",
    reason="Set RUN_DATABASE_TESTS=1 to test manual approvals against PostgreSQL.",
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


def account(client: TestClient, name: str = "Inam") -> tuple[dict, dict[str, str]]:
    credentials = {
        "email": f"mobile-{uuid4()}@example.com",
        "password": secrets.token_urlsafe(24),
        "full_name": name,
    }
    user = client.post("/auth/register", json=credentials)
    login = client.post(
        "/auth/login",
        json={"email": credentials["email"], "password": credentials["password"]},
    )
    assert user.status_code == 201 and login.status_code == 200
    return user.json(), {"Authorization": f"Bearer {login.json()['access_token']}"}


def pending_setup(client: TestClient, db: Session):
    user, headers = account(client)
    agent_response = client.post("/agents", headers=headers, json={"name": "Travel Assistant"})
    agent = agent_response.json()
    stored_agent = db.get(Agent, UUID(agent["id"]))
    stored_agent.status = AgentStatus.ACTIVE
    db.commit()
    now = datetime.now(timezone.utc)
    permission_response = client.post("/permissions", headers=headers, json={
        "agent_id": agent["id"],
        "action": "purchase",
        "resource": "flight",
        "maximum_amount": "500",
        "currency": "USD",
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=24)).isoformat(),
        "requires_approval": True,
    })
    assert permission_response.status_code == 201, permission_response.text
    permission = permission_response.json()
    authorization = client.post("/authorize", headers=headers, json={
        "agent_id": agent["agent_identifier"],
        "action": "purchase",
        "resource": "flight",
        "amount": "420",
        "currency": "USD",
    })
    assert authorization.status_code == 200, authorization.text
    return user, headers, agent, permission, authorization.json()


def test_requires_approval_creates_pending_request_without_early_audit(client, db):
    user, _, agent, permission, result = pending_setup(client, db)
    assert result["decision"] == "PENDING"
    assert result["reason"] == "Awaiting user approval"
    record = db.scalar(select(AuthorizationRequestRecord).where(
        AuthorizationRequestRecord.request_id == result["request_id"],
    ))
    assert record.user_id == UUID(user["id"])
    assert record.agent_id == UUID(agent["id"])
    assert record.permission_id == UUID(permission["id"])
    assert record.status == AuthorizationRequestStatus.PENDING
    assert db.scalar(select(AuditLog).where(AuditLog.request_id == result["request_id"])) is None


def test_owner_can_list_and_open_pending_request(client, db):
    _, headers, agent, permission, result = pending_setup(client, db)
    listing = client.get("/authorization-requests?status=PENDING", headers=headers)
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    item = listing.json()["items"][0]
    assert item["request_id"] == result["request_id"]
    assert item["agent_name"] == "Travel Assistant"
    assert item["agent_identifier"] == agent["agent_identifier"]
    assert item["permission_id"] == permission["id"]
    detail = client.get(f"/authorization-requests/{item['id']}", headers=headers)
    assert detail.status_code == 200
    assert detail.json() == item


def test_approve_is_final_and_creates_audit_log(client, db):
    _, headers, _, _, result = pending_setup(client, db)
    item = client.get("/authorization-requests?status=PENDING", headers=headers).json()["items"][0]
    approved = client.post(f"/authorization-requests/{item['id']}/approve", headers=headers)
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "APPROVED"
    assert approved.json()["reason"] == "Approved by user"
    audit = db.scalar(select(AuditLog).where(AuditLog.request_id == result["request_id"]))
    assert audit.decision == AuditDecision.APPROVED
    assert audit.reason == "Approved by user"
    again = client.post(f"/authorization-requests/{item['id']}/approve", headers=headers)
    assert again.status_code == 409
    assert again.json() == {"detail": "Authorization request has already been decided"}


def test_reject_is_final_and_creates_audit_log(client, db):
    _, headers, _, _, result = pending_setup(client, db)
    item = client.get("/authorization-requests?status=PENDING", headers=headers).json()["items"][0]
    rejected = client.post(f"/authorization-requests/{item['id']}/reject", headers=headers)
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "REJECTED"
    assert rejected.json()["reason"] == "Rejected by user"
    audit = db.scalar(select(AuditLog).where(AuditLog.request_id == result["request_id"]))
    assert audit.decision == AuditDecision.REJECTED
    assert audit.reason == "Rejected by user"
    assert client.post(
        f"/authorization-requests/{item['id']}/reject", headers=headers,
    ).status_code == 409


def test_another_user_cannot_see_or_decide_request(client, db):
    _, owner_headers, _, _, _ = pending_setup(client, db)
    item = client.get("/authorization-requests", headers=owner_headers).json()["items"][0]
    _, other_headers = account(client, "Other User")
    assert client.get("/authorization-requests", headers=other_headers).json()["items"] == []
    assert client.get(f"/authorization-requests/{item['id']}", headers=other_headers).status_code == 404
    assert client.post(
        f"/authorization-requests/{item['id']}/approve", headers=other_headers,
    ).status_code == 404


def test_expired_request_cannot_be_approved_and_is_audited(client, db):
    _, headers, _, _, result = pending_setup(client, db)
    record = db.scalar(select(AuthorizationRequestRecord).where(
        AuthorizationRequestRecord.request_id == result["request_id"],
    ))
    record.created_at = datetime.now(timezone.utc) - timedelta(minutes=2)
    record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    response = client.post(f"/authorization-requests/{record.id}/approve", headers=headers)
    assert response.status_code == 409
    db.refresh(record)
    assert record.status == AuthorizationRequestStatus.EXPIRED
    audit = db.scalar(select(AuditLog).where(AuditLog.request_id == result["request_id"]))
    assert audit.decision == AuditDecision.REJECTED
    assert audit.reason == "Request expired"


@pytest.mark.parametrize(
    ("change", "reason"),
    [("permission", "Permission revoked"), ("agent", "Agent is not active")],
)
def test_approval_rechecks_current_security_state(client, db, change, reason):
    _, headers, agent, permission, result = pending_setup(client, db)
    if change == "permission":
        db.get(Permission, UUID(permission["id"])).status = PermissionStatus.REVOKED
    else:
        db.get(Agent, UUID(agent["id"])).status = AgentStatus.SUSPENDED
    db.commit()
    record = db.scalar(select(AuthorizationRequestRecord).where(
        AuthorizationRequestRecord.request_id == result["request_id"],
    ))
    response = client.post(f"/authorization-requests/{record.id}/approve", headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "REJECTED"
    assert response.json()["reason"] == reason
    audit = db.scalar(select(AuditLog).where(AuditLog.request_id == result["request_id"]))
    assert audit.reason == reason


def test_request_routes_require_login(client):
    request_id = uuid4()
    assert client.get("/authorization-requests").status_code == 401
    assert client.get(f"/authorization-requests/{request_id}").status_code == 401
    assert client.post(f"/authorization-requests/{request_id}/approve").status_code == 401
    assert client.post(f"/authorization-requests/{request_id}/reject").status_code == 401


def test_automatic_permission_keeps_existing_behavior(client, db):
    _, headers, agent, permission, _ = pending_setup(client, db)
    stored = db.get(Permission, UUID(permission["id"]))
    stored.requires_approval = False
    db.commit()
    response = client.post("/authorize", headers=headers, json={
        "agent_id": agent["agent_identifier"],
        "action": "purchase",
        "resource": "flight",
        "amount": "400",
        "currency": "USD",
    })
    assert response.status_code == 200
    assert response.json()["decision"] == "APPROVED"
