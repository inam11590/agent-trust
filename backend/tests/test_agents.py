"""Protected agent API tests against PostgreSQL; each test rolls back its rows."""

import os
import re
import secrets
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.session import create_database_engine, get_db
from app.main import create_app
from app.models import Agent, AgentStatus, Organization, User
from app.services.agents import generate_agent_identifier

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_DATABASE_TESTS") != "1",
    reason="Set RUN_DATABASE_TESTS=1 to test agents against migrated PostgreSQL.",
)

AGENT_ID_PATTERN = re.compile(r"^agt_[0-9a-f]{24}$")


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


def account() -> dict[str, str]:
    return {
        "email": f"agent-owner-{uuid4()}@example.com",
        "password": secrets.token_urlsafe(24),
        "full_name": "Agent Owner",
    }


def register_and_login(client: TestClient) -> tuple[dict, dict[str, str]]:
    credentials = account()
    registration = client.post("/auth/register", json=credentials)
    assert registration.status_code == 201, registration.text
    login = client.post(
        "/auth/login",
        json={"email": credentials["email"], "password": credentials["password"]},
    )
    assert login.status_code == 200, login.text
    return registration.json(), {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_login_create_travel_assistant_and_read_it(client, db):
    user, headers = register_and_login(client)

    creation = client.post(
        "/agents",
        json={"name": "  Travel Assistant  ", "description": "  Books safe trips  "},
        headers=headers,
    )
    assert creation.status_code == 201, creation.text
    agent = creation.json()
    assert agent["name"] == "Travel Assistant"
    assert agent["description"] == "Books safe trips"
    assert AGENT_ID_PATTERN.fullmatch(agent["agent_identifier"])
    assert agent["owner_id"] == user["id"]
    assert agent["organization_id"] is None
    assert agent["status"] == "inactive"
    assert creation.headers["Location"] == f"/agents/{agent['agent_identifier']}"
    assert creation.headers["Cache-Control"] == "no-store"

    listing = client.get("/agents", headers=headers)
    assert listing.status_code == 200
    assert listing.json() == [agent]
    assert listing.headers["Cache-Control"] == "no-store"

    detail = client.get(f"/agents/{agent['agent_identifier']}", headers=headers)
    assert detail.status_code == 200
    assert detail.json() == agent
    assert detail.headers["Cache-Control"] == "no-store"
    assert db.get(Agent, UUID(agent["id"])).owner_id == UUID(user["id"])


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("post", "/agents", {"name": "Travel Assistant"}),
        ("get", "/agents", None),
        ("get", "/agents/agt_000000000000000000000000", None),
    ],
)
def test_agent_routes_require_login(client, method, path, body):
    response = client.request(method, path, json=body)
    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials"}
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_users_only_see_their_own_agents(client):
    first_user, first_headers = register_and_login(client)
    first = client.post("/agents", json={"name": "First Agent"}, headers=first_headers).json()
    second_user, second_headers = register_and_login(client)
    second = client.post("/agents", json={"name": "Second Agent"}, headers=second_headers).json()

    assert first["owner_id"] == first_user["id"]
    assert second["owner_id"] == second_user["id"]
    assert client.get("/agents", headers=first_headers).json() == [first]
    assert client.get("/agents", headers=second_headers).json() == [second]
    hidden = client.get(f"/agents/{first['agent_identifier']}", headers=second_headers)
    assert hidden.status_code == 404
    assert hidden.json() == {"detail": "Agent not found"}


def test_agent_can_use_only_an_organization_owned_by_the_user(client, db):
    user, headers = register_and_login(client)
    other_user, _ = register_and_login(client)
    own = Organization(name="Own Organization", owner_id=UUID(user["id"]))
    other = Organization(name="Other Organization", owner_id=UUID(other_user["id"]))
    db.add_all([own, other])
    db.commit()
    db.refresh(own)
    db.refresh(other)

    created = client.post(
        "/agents", json={"name": "Company Agent", "organization_id": str(own.id)}, headers=headers,
    )
    assert created.status_code == 201
    assert created.json()["organization_id"] == str(own.id)

    for organization_id in (other.id, uuid4()):
        rejected = client.post(
            "/agents",
            json={"name": "Wrong Organization", "organization_id": str(organization_id)},
            headers=headers,
        )
        assert rejected.status_code == 404
        assert rejected.json() == {"detail": "Organization not found"}


@pytest.mark.parametrize(
    "body",
    [
        {"name": ""},
        {"name": "   "},
        {"name": "a" * 201},
        {"name": "Agent", "description": "a" * 2001},
        {"name": "Agent", "owner_id": str(uuid4())},
        {"name": "Agent", "agent_identifier": "chosen-by-client"},
        {"name": "Agent", "status": "active"},
        {},
    ],
)
def test_agent_creation_rejects_invalid_or_server_owned_fields(client, db, body):
    _, headers = register_and_login(client)
    response = client.post("/agents", json=body, headers=headers)
    assert response.status_code == 422
    assert db.scalar(select(func.count()).select_from(Agent)) == 0


def test_identifier_generator_is_prefixed_random_and_unique():
    identifiers = {generate_agent_identifier() for _ in range(500)}
    assert len(identifiers) == 500
    assert all(AGENT_ID_PATTERN.fullmatch(identifier) for identifier in identifiers)


def test_identifier_collision_is_retried(client, db, monkeypatch):
    user, headers = register_and_login(client)
    collision = "agt_" + "0" * 24
    replacement = "agt_" + "1" * 24
    db.add(Agent(
        name="Existing",
        agent_identifier=collision,
        owner_id=UUID(user["id"]),
    ))
    db.commit()
    identifiers = iter([collision, replacement])
    monkeypatch.setattr("app.services.agents.generate_agent_identifier", lambda: next(identifiers))

    response = client.post("/agents", json={"name": "New Agent"}, headers=headers)
    assert response.status_code == 201, response.text
    assert response.json()["agent_identifier"] == replacement
    assert db.scalar(select(func.count()).select_from(Agent)) == 2


def test_inactive_user_cannot_access_agents(client, db):
    user, headers = register_and_login(client)
    stored = db.get(User, UUID(user["id"]))
    stored.is_active = False
    db.commit()
    assert client.get("/agents", headers=headers).status_code == 401


def test_owner_can_update_and_control_agent_lifecycle(client):
    _, headers = register_and_login(client)
    agent = client.post("/agents", json={"name": "Travel Assistant"}, headers=headers).json()

    active = client.patch(
        f"/agents/{agent['agent_identifier']}",
        json={"name": "Travel Guardian", "description": "Approved travel only", "status": "active"},
        headers=headers,
    )
    assert active.status_code == 200, active.text
    assert active.json()["name"] == "Travel Guardian"
    assert active.json()["description"] == "Approved travel only"
    assert active.json()["status"] == "active"

    revoked = client.patch(
        f"/agents/{agent['agent_identifier']}", json={"status": "revoked"}, headers=headers,
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    blocked = client.patch(
        f"/agents/{agent['agent_identifier']}", json={"status": "active"}, headers=headers,
    )
    assert blocked.status_code == 409


def test_user_cannot_update_another_users_agent(client):
    _, owner_headers = register_and_login(client)
    agent = client.post("/agents", json={"name": "Private"}, headers=owner_headers).json()
    _, other_headers = register_and_login(client)
    hidden = client.patch(
        f"/agents/{agent['agent_identifier']}", json={"status": "active"}, headers=other_headers,
    )
    assert hidden.status_code == 404
