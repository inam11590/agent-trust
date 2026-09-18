"""Opt-in tests against migrated PostgreSQL; every test rolls back its rows."""

import os
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.session import create_database_engine
from app.main import create_app
from app.models import Agent, AgentStatus, Organization, User

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_DATABASE_TESTS") != "1",
    reason="Set RUN_DATABASE_TESTS=1 to test a migrated local PostgreSQL database.",
)


@pytest.fixture
def session():
    engine = create_database_engine(Settings())
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                with Session(bind=connection, join_transaction_mode="create_savepoint") as db:
                    yield db
            finally:
                transaction.rollback()
    finally:
        engine.dispose()


def make_user() -> User:
    return User(
        email=f"test-{uuid4()}@example.invalid",
        # Unusable password marker, not a plaintext password or real account.
        hashed_password="!" + uuid4().hex,
        full_name="Database Test",
    )


def test_live_database_health():
    with TestClient(create_app()) as client:
        response = client.get("/health/database")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "PostgreSQL"}


def test_relationships_defaults_and_timestamps(session):
    user = make_user()
    organization = Organization(name="Test Organization", owner=user)
    agent = Agent(name="Test Agent", agent_identifier=str(uuid4()), owner=user, organization=organization)
    session.add_all([user, organization, agent])
    session.flush()
    session.expire_all()

    assert isinstance(agent.id, UUID)
    assert agent.owner == user
    assert agent.organization == organization
    assert organization.owner == user
    assert agent in user.agents
    assert organization in user.organizations
    assert agent.status == AgentStatus.INACTIVE
    assert user.is_active is True
    assert agent.created_at.tzinfo is not None

    original = datetime(2000, 1, 1, tzinfo=timezone.utc)
    agent.updated_at = original
    session.flush()
    agent.name = "Updated Agent"
    session.flush()
    assert agent.updated_at > original


def test_organization_is_optional_and_deletion_preserves_agent(session):
    user = make_user()
    organization = Organization(name="Temporary Organization", owner=user)
    agent = Agent(name="Agent", agent_identifier=str(uuid4()), owner=user, organization=organization)
    standalone = Agent(name="Standalone", agent_identifier=str(uuid4()), owner=user)
    session.add_all([user, organization, agent, standalone])
    session.flush()
    assert standalone.organization_id is None
    session.delete(organization)
    session.flush()
    session.refresh(agent)
    assert agent.organization_id is None
    assert agent.owner_id == user.id


def test_duplicate_email_is_rejected(session):
    user = make_user()
    session.add(user)
    session.flush()
    duplicate = make_user()
    duplicate.email = user.email
    with pytest.raises(IntegrityError):
        with session.begin_nested():
            session.add(duplicate)
            session.flush()


def test_duplicate_agent_identifier_is_rejected(session):
    user = make_user()
    agent = Agent(name="First", agent_identifier=str(uuid4()), owner=user)
    session.add_all([user, agent])
    session.flush()
    with pytest.raises(IntegrityError):
        with session.begin_nested():
            session.add(Agent(name="Duplicate", agent_identifier=agent.agent_identifier, owner_id=user.id))
            session.flush()


def test_nonexistent_owner_is_rejected(session):
    with pytest.raises(IntegrityError):
        with session.begin_nested():
            session.add(Agent(name="Orphan", agent_identifier=str(uuid4()), owner_id=uuid4()))
            session.flush()


def test_owner_deletion_is_restricted(session):
    user = make_user()
    agent = Agent(name="Agent", agent_identifier=str(uuid4()), owner=user)
    session.add_all([user, agent])
    session.flush()
    with pytest.raises(IntegrityError):
        with session.begin_nested():
            session.delete(user)
            session.flush()


def test_database_rejects_invalid_agent_status(session):
    user = make_user()
    agent = Agent(name="Agent", agent_identifier=str(uuid4()), owner=user)
    session.add_all([user, agent])
    session.flush()
    with pytest.raises(IntegrityError):
        with session.begin_nested():
            session.execute(text("UPDATE agents SET status = 'invalid' WHERE id = :id"), {"id": agent.id})
