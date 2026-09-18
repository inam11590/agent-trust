"""Permission API tests against PostgreSQL; each test rolls back its rows."""

import os
import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.session import create_database_engine, get_db
from app.main import create_app
from app.models import Agent, Permission, PermissionStatus, User

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_DATABASE_TESTS") != "1",
    reason="Set RUN_DATABASE_TESTS=1 to test permissions against migrated PostgreSQL.",
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


def register_and_login(client: TestClient, name: str = "Inam") -> tuple[dict, dict[str, str]]:
    credentials = {
        "email": f"permission-owner-{uuid4()}@example.com",
        "password": secrets.token_urlsafe(24),
        "full_name": name,
    }
    registration = client.post("/auth/register", json=credentials)
    assert registration.status_code == 201, registration.text
    login = client.post(
        "/auth/login",
        json={"email": credentials["email"], "password": credentials["password"]},
    )
    assert login.status_code == 200, login.text
    return registration.json(), {"Authorization": f"Bearer {login.json()['access_token']}"}


def create_agent(client: TestClient, headers: dict[str, str], name: str = "Travel Assistant") -> dict:
    response = client.post("/agents", json={"name": name}, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def permission_payload(agent_id: str, **updates) -> dict:
    now = datetime.now(timezone.utc)
    payload = {
        "agent_id": agent_id,
        "action": "purchase",
        "resource": "flight",
        "maximum_amount": "500.00",
        "currency": "USD",
        "valid_from": now.isoformat(),
        "expires_at": (now + timedelta(hours=24)).isoformat(),
    }
    payload.update(updates)
    return payload


def grant_permission(client: TestClient, headers: dict[str, str], agent_id: str, **updates) -> dict:
    response = client.post(
        "/permissions",
        json=permission_payload(agent_id, **updates),
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_inam_grants_travel_assistant_500_usd_for_24_hours(client, db):
    user, headers = register_and_login(client)
    agent = create_agent(client, headers)
    creation = client.post(
        "/permissions",
        json=permission_payload(agent["id"]),
        headers=headers,
    )
    assert creation.status_code == 201, creation.text
    permission = creation.json()
    assert permission["owner_id"] == user["id"]
    assert permission["agent_id"] == agent["id"]
    assert permission["action"] == "purchase"
    assert permission["resource"] == "flight"
    assert Decimal(permission["maximum_amount"]) == Decimal("500")
    assert permission["currency"] == "USD"
    assert permission["status"] == "active"
    start = datetime.fromisoformat(permission["valid_from"])
    end = datetime.fromisoformat(permission["expires_at"])
    assert timedelta(hours=23, minutes=59) < end - start <= timedelta(hours=24)
    assert creation.headers["Location"] == f"/permissions/{permission['id']}"
    assert creation.headers["Cache-Control"] == "no-store"

    listing = client.get("/permissions", headers=headers)
    assert listing.status_code == 200
    assert listing.json() == [permission]
    detail = client.get(f"/permissions/{permission['id']}", headers=headers)
    assert detail.status_code == 200
    assert detail.json() == permission
    stored = db.get(Permission, UUID(permission["id"]))
    assert stored.is_usable(start + timedelta(hours=1))


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("post", "/permissions", {"agent_id": str(uuid4())}),
        ("get", "/permissions", None),
        ("get", f"/permissions/{uuid4()}", None),
        ("post", f"/permissions/{uuid4()}/revoke", None),
    ],
)
def test_permission_routes_require_login(client, method, path, body):
    response = client.request(method, path, json=body)
    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials"}


def test_only_owner_can_grant_read_or_revoke_permission(client):
    _, owner_headers = register_and_login(client, "Owner")
    agent = create_agent(client, owner_headers)
    permission = grant_permission(client, owner_headers, agent["id"])
    _, other_headers = register_and_login(client, "Other User")

    wrong_agent = client.post(
        "/permissions",
        json=permission_payload(agent["id"]),
        headers=other_headers,
    )
    assert wrong_agent.status_code == 404
    assert wrong_agent.json() == {"detail": "Agent not found"}
    assert client.get("/permissions", headers=other_headers).json() == []
    for method, path in (
        ("get", f"/permissions/{permission['id']}"),
        ("post", f"/permissions/{permission['id']}/revoke"),
    ):
        response = client.request(method, path, headers=other_headers)
        assert response.status_code == 404
        assert response.json() == {"detail": "Permission not found"}


def test_revoke_immediately_makes_permission_unusable_and_is_idempotent(client, db):
    _, headers = register_and_login(client)
    agent = create_agent(client, headers)
    permission = grant_permission(client, headers, agent["id"])
    stored = db.get(Permission, UUID(permission["id"]))
    assert stored.is_usable()

    first = client.post(f"/permissions/{permission['id']}/revoke", headers=headers)
    assert first.status_code == 200
    assert first.json()["status"] == "revoked"
    db.refresh(stored)
    assert not stored.is_usable()

    second = client.post(f"/permissions/{permission['id']}/revoke", headers=headers)
    assert second.status_code == 200
    assert second.json()["status"] == "revoked"


def test_expired_permission_is_marked_expired_and_cannot_be_used(client, db):
    user, headers = register_and_login(client)
    agent = create_agent(client, headers)
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
    db.refresh(permission)
    assert not permission.is_usable()

    response = client.get(f"/permissions/{permission.id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "expired"
    db.refresh(permission)
    assert permission.status == PermissionStatus.EXPIRED
    assert not permission.is_usable()


def test_future_permission_is_active_but_not_usable_before_valid_from(client, db):
    _, headers = register_and_login(client)
    agent = create_agent(client, headers)
    now = datetime.now(timezone.utc)
    permission = grant_permission(
        client,
        headers,
        agent["id"],
        valid_from=(now + timedelta(hours=1)).isoformat(),
        expires_at=(now + timedelta(hours=2)).isoformat(),
    )
    stored = db.get(Permission, UUID(permission["id"]))
    assert permission["status"] == "active"
    assert not stored.is_usable(now)
    assert stored.is_usable(now + timedelta(hours=1, minutes=30))


def test_permission_without_a_money_limit_is_supported(client):
    _, headers = register_and_login(client)
    agent = create_agent(client, headers)
    permission = grant_permission(
        client,
        headers,
        agent["id"],
        maximum_amount=None,
        currency=None,
    )
    assert permission["maximum_amount"] is None
    assert permission["currency"] is None


@pytest.mark.parametrize(
    "updates",
    [
        {"maximum_amount": "0"},
        {"maximum_amount": "-10"},
        {"maximum_amount": "1.00001"},
        {"maximum_amount": None},
        {"currency": None},
        {"currency": "US"},
        {"valid_from": "2026-09-13T00:00:00Z", "expires_at": "2026-09-12T00:00:00Z"},
        {"expires_at": "2020-01-01T00:00:00Z"},
        {"action": "purchase flight"},
        {"resource": ""},
        {"owner_id": str(uuid4())},
        {"status": "revoked"},
    ],
)
def test_invalid_permission_requests_are_rejected(client, db, updates):
    _, headers = register_and_login(client)
    agent = create_agent(client, headers)
    response = client.post(
        "/permissions",
        json=permission_payload(agent["id"], **updates),
        headers=headers,
    )
    assert response.status_code == 422
    assert db.scalar(select(func.count()).select_from(Permission)) == 0


def test_database_enforces_money_currency_and_date_constraints(client, db):
    user, headers = register_and_login(client)
    agent = create_agent(client, headers)
    now = datetime.now(timezone.utc)
    invalid_values = [
        {"maximum_amount": Decimal("0"), "currency": "USD", "valid_from": now, "expires_at": now + timedelta(hours=1)},
        {"maximum_amount": Decimal("10"), "currency": None, "valid_from": now, "expires_at": now + timedelta(hours=1)},
        {"maximum_amount": Decimal("10"), "currency": "usd", "valid_from": now, "expires_at": now + timedelta(hours=1)},
        {"maximum_amount": Decimal("10"), "currency": "USD", "valid_from": now, "expires_at": now},
    ]
    for values in invalid_values:
        with pytest.raises(IntegrityError):
            with db.begin_nested():
                db.add(Permission(
                    owner_id=UUID(user["id"]),
                    agent_id=UUID(agent["id"]),
                    action="purchase",
                    resource="flight",
                    **values,
                ))
                db.flush()


def test_agent_and_owner_with_permissions_cannot_be_deleted(client, db):
    user, headers = register_and_login(client)
    agent_data = create_agent(client, headers)
    grant_permission(client, headers, agent_data["id"])
    agent = db.get(Agent, UUID(agent_data["id"]))
    owner = db.get(User, UUID(user["id"]))
    for record in (agent, owner):
        with pytest.raises(IntegrityError):
            with db.begin_nested():
                db.delete(record)
                db.flush()


def test_permission_status_constraint_rejects_unknown_value(client, db):
    _, headers = register_and_login(client)
    agent = create_agent(client, headers)
    permission = grant_permission(client, headers, agent["id"])
    with pytest.raises(IntegrityError):
        with db.begin_nested():
            db.execute(
                text("UPDATE permissions SET status = 'unknown' WHERE id = :id"),
                {"id": UUID(permission["id"])},
            )
