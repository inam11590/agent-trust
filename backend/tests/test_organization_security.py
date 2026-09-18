"""Organization roles, tenant isolation, invitations, and security hardening."""

import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.session import create_database_engine, get_db
from app.main import create_app
from app.models import (
    APIKey,
    Agent,
    OrganizationInvitation,
    OrganizationMember,
    SecurityEvent,
    User,
)

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
        webhook_signing_key=secrets.token_urlsafe(48),
        postgres_user="",
        postgres_password="",
    )
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as value:
        yield value


def account(client: TestClient, email: str | None = None, name: str = "Member"):
    credentials = {
        "email": email or f"team-{uuid4()}@example.com",
        "password": secrets.token_urlsafe(24),
        "full_name": name,
    }
    user = client.post("/auth/register", json=credentials)
    assert user.status_code == 201, user.text
    login = client.post("/auth/login", json={
        "email": credentials["email"], "password": credentials["password"],
    })
    assert login.status_code == 200, login.text
    return user.json(), {"Authorization": f"Bearer {login.json()['access_token']}"}


def create_org(client: TestClient, headers: dict, name: str = "SkyTravel"):
    response = client.post("/organizations", headers=headers, json={"name": name})
    assert response.status_code == 201, response.text
    return response.json()


def org_headers(headers: dict, organization_id: str) -> dict:
    return {**headers, "X-Organization-ID": organization_id}


def invite_and_join(client: TestClient, owner_headers: dict, organization_id: str, role: str):
    email = f"{role}-{uuid4()}@example.com"
    invitation = client.post(
        f"/organizations/{organization_id}/invitations",
        headers=owner_headers,
        json={"email": email, "role": role},
    )
    assert invitation.status_code == 201, invitation.text
    token = parse_qs(urlsplit(invitation.json()["invitation_url"]).query)["token"][0]
    user, headers = account(client, email, role.title())
    accepted = client.post("/invitations/accept", headers=headers, json={"token": token})
    assert accepted.status_code == 200, accepted.text
    return user, org_headers(headers, organization_id), accepted.json(), token


def create_agent(client: TestClient, headers: dict, name: str):
    response = client.post("/agents", headers=headers, json={"name": name})
    assert response.status_code == 201, response.text
    return response.json()


def permission_payload(agent_id: str):
    now = datetime.now(timezone.utc)
    return {
        "agent_id": agent_id,
        "action": "purchase",
        "resource": "flight",
        "maximum_amount": 500,
        "currency": "USD",
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
    }


def test_owner_admin_developer_and_viewer_permissions(client, db):
    owner, owner_auth = account(client, name="Inam")
    organization = create_org(client, owner_auth)
    assert client.get("/organizations", headers=owner_auth).json()[0]["role"] == "owner"
    owner_headers = org_headers(owner_auth, organization["id"])
    _, admin_headers, admin_member, _ = invite_and_join(client, owner_auth, organization["id"], "admin")
    _, developer_headers, developer_member, _ = invite_and_join(client, owner_auth, organization["id"], "developer")
    _, viewer_headers, viewer_member, _ = invite_and_join(client, owner_auth, organization["id"], "viewer")

    agent = create_agent(client, admin_headers, "Admin Agent")
    assert client.post("/permissions", headers=admin_headers, json=permission_payload(agent["id"])).status_code == 201
    assert client.get("/agents", headers=viewer_headers).status_code == 200
    assert client.get("/permissions", headers=viewer_headers).status_code == 200
    assert client.post("/agents", headers=viewer_headers, json={"name": "Denied"}).status_code == 403
    assert client.post("/permissions", headers=developer_headers, json=permission_payload(agent["id"])).status_code == 403
    key = client.post("/developer/api-keys", headers=developer_headers, json={"name": "Developer Key"})
    assert key.status_code == 201
    assert client.delete(
        f"/organizations/{organization['id']}/members/{admin_member['id']}", headers=developer_headers,
    ).status_code == 403
    assert client.patch(
        f"/organizations/{organization['id']}/members/{developer_member['id']}",
        headers=viewer_headers, json={"role": "admin"},
    ).status_code == 403
    changed = client.patch(
        f"/organizations/{organization['id']}/members/{viewer_member['id']}",
        headers=admin_headers, json={"role": "developer"},
    )
    assert changed.status_code == 200 and changed.json()["role"] == "developer"


def test_company_data_and_api_keys_are_isolated(client, db):
    _, owner_headers = account(client)
    company_a = create_org(client, owner_headers, "Company A")
    company_b = create_org(client, owner_headers, "Company B")
    a_headers = org_headers(owner_headers, company_a["id"])
    b_headers = org_headers(owner_headers, company_b["id"])
    agent_a = create_agent(client, a_headers, "A Agent")
    agent_b = create_agent(client, b_headers, "B Agent")
    permission_a = client.post("/permissions", headers=a_headers, json=permission_payload(agent_a["id"])).json()
    permission_b = client.post("/permissions", headers=b_headers, json=permission_payload(agent_b["id"])).json()
    assert [item["id"] for item in client.get("/agents", headers=a_headers).json()] == [agent_a["id"]]
    assert client.get(f"/agents/{agent_b['agent_identifier']}", headers=a_headers).status_code == 404
    assert [item["id"] for item in client.get("/permissions", headers=a_headers).json()] == [permission_a["id"]]

    client.post("/authorize", headers=a_headers, json={
        "agent_id": agent_a["agent_identifier"], "action": "purchase", "resource": "flight",
        "amount": 420, "currency": "USD",
    })
    client.post("/authorize", headers=b_headers, json={
        "agent_id": agent_b["agent_identifier"], "action": "purchase", "resource": "flight",
        "amount": 420, "currency": "USD",
    })
    a_logs = client.get("/audit-logs", headers=a_headers).json()["items"]
    assert a_logs and {item["agent_id"] for item in a_logs} == {agent_a["id"]}
    assert permission_b["id"] not in {item["permission_id"] for item in a_logs}

    created_key = client.post("/developer/api-keys", headers=a_headers, json={"name": "A Key"}).json()
    denied = client.post("/api/v1/authorize", headers={"X-API-Key": created_key["api_key"]}, json={
        "agent_id": agent_b["agent_identifier"], "action": "purchase", "resource": "flight",
        "amount": 420, "currency": "USD",
    })
    assert denied.status_code == 200
    assert denied.json()["status"] == "REJECTED" and denied.json()["reason"] == "Agent not found"


def test_owner_cannot_be_removed_or_changed_by_admin_or_developer(client):
    _, owner_auth = account(client, name="Inam")
    organization = create_org(client, owner_auth)
    owner_member = client.get(f"/organizations/{organization['id']}/members", headers=owner_auth).json()[0]
    _, admin_headers, _, _ = invite_and_join(client, owner_auth, organization["id"], "admin")
    _, developer_headers, _, _ = invite_and_join(client, owner_auth, organization["id"], "developer")
    assert client.delete(
        f"/organizations/{organization['id']}/members/{owner_member['id']}", headers=admin_headers,
    ).status_code == 409
    assert client.patch(
        f"/organizations/{organization['id']}/members/{owner_member['id']}",
        headers=admin_headers, json={"role": "viewer"},
    ).status_code == 409
    assert client.delete(
        f"/organizations/{organization['id']}/members/{owner_member['id']}", headers=developer_headers,
    ).status_code == 403
    assert client.delete(
        f"/organizations/{organization['id']}/members/{owner_member['id']}", headers=owner_auth,
    ).status_code == 409


def test_invitation_expiry_reuse_revocation_and_email_binding(client, db):
    _, owner_headers = account(client)
    organization = create_org(client, owner_headers)
    invited_email = f"invite-{uuid4()}@example.com"
    response = client.post(f"/organizations/{organization['id']}/invitations", headers=owner_headers, json={
        "email": invited_email, "role": "developer",
    }).json()
    token = parse_qs(urlsplit(response["invitation_url"]).query)["token"][0]
    invitation = db.get(OrganizationInvitation, UUID(response["id"]))
    invitation.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    invited, invited_headers = account(client, invited_email)
    expired = client.post("/invitations/accept", headers=invited_headers, json={"token": token})
    assert expired.status_code == 410

    second_email = f"second-{uuid4()}@example.com"
    second = client.post(f"/organizations/{organization['id']}/invitations", headers=owner_headers, json={
        "email": second_email, "role": "viewer",
    }).json()
    second_token = parse_qs(urlsplit(second["invitation_url"]).query)["token"][0]
    _, wrong_headers = account(client)
    assert client.post("/invitations/accept", headers=wrong_headers, json={"token": second_token}).status_code == 400
    _, second_headers = account(client, second_email)
    assert client.post("/invitations/accept", headers=second_headers, json={"token": second_token}).status_code == 200
    assert client.post("/invitations/accept", headers=second_headers, json={"token": second_token}).status_code == 400

    third_email = f"third-{uuid4()}@example.com"
    third = client.post(f"/organizations/{organization['id']}/invitations", headers=owner_headers, json={
        "email": third_email, "role": "admin",
    }).json()
    third_token = parse_qs(urlsplit(third["invitation_url"]).query)["token"][0]
    assert client.post(
        f"/organizations/{organization['id']}/invitations/{third['id']}/revoke", headers=owner_headers,
    ).status_code == 200
    _, third_headers = account(client, third_email)
    assert client.post("/invitations/accept", headers=third_headers, json={"token": third_token}).status_code == 400
    assert invitation.token_hash != token


def test_removing_developer_stops_their_organization_key(client, db):
    _, owner_headers = account(client)
    organization = create_org(client, owner_headers)
    _, developer_headers, member, _ = invite_and_join(client, owner_headers, organization["id"], "developer")
    key_response = client.post("/developer/api-keys", headers=developer_headers, json={"name": "Temporary"})
    key = key_response.json()
    assert client.delete(
        f"/organizations/{organization['id']}/members/{member['id']}", headers=owner_headers,
    ).status_code == 204
    assert client.get(
        "/api/v1/authorization-requests/req_" + "a" * 24,
        headers={"X-API-Key": key["api_key"]},
    ).status_code == 401
    assert db.get(APIKey, UUID(key["id"])).status.value == "revoked"


def test_login_rate_limit_and_account_lock_foundation(client, db):
    credentials = {
        "email": f"locked-{uuid4()}@example.com",
        "password": secrets.token_urlsafe(24),
        "full_name": "Protected User",
    }
    user = client.post("/auth/register", json=credentials).json()
    client.app.state.settings.auth_login_rate_limit_per_minute = 20
    for _ in range(client.app.state.settings.account_lock_attempts):
        assert client.post("/auth/login", json={"email": credentials["email"], "password": "wrong-password"}).status_code == 401
    assert client.post("/auth/login", json={"email": credentials["email"], "password": credentials["password"]}).status_code == 401
    assert db.get(User, UUID(user["id"])).locked_until is not None

    client.app.state.settings.auth_login_rate_limit_per_minute = 2
    missing = f"missing-{uuid4()}@example.com"
    for expected in (401, 401, 429):
        assert client.post("/auth/login", json={"email": missing, "password": "wrong-password"}).status_code == expected


def test_security_events_and_headers_contain_no_secrets(client, db):
    _, owner_headers = account(client)
    organization = create_org(client, owner_headers)
    invitation = client.post(f"/organizations/{organization['id']}/invitations", headers=owner_headers, json={
        "email": f"audit-{uuid4()}@example.com", "role": "viewer",
    })
    workspace_headers = org_headers(owner_headers, organization["id"])
    agent = create_agent(client, workspace_headers, "Audited Agent")
    permission = client.post("/permissions", headers=workspace_headers, json=permission_payload(agent["id"])).json()
    key = client.post("/developer/api-keys", headers=workspace_headers, json={"name": "Audited Key"}).json()
    assert client.post(f"/permissions/{permission['id']}/revoke", headers=workspace_headers).status_code == 200
    assert client.patch(f"/agents/{agent['agent_identifier']}", headers=workspace_headers, json={"status": "revoked"}).status_code == 200
    assert client.post(f"/developer/api-keys/{key['id']}/revoke", headers=workspace_headers).status_code == 200
    events = client.get(f"/organizations/{organization['id']}/security-events", headers=owner_headers)
    assert events.status_code == 200
    assert {event["event_type"] for event in events.json()} >= {
        "organization.created", "member.invited", "api_key.created", "api_key.revoked",
        "permission.revoked", "agent.revoked",
    }
    assert "token=" not in events.text and "at_live_" not in events.text
    assert invitation.headers["X-Content-Type-Options"] == "nosniff"
    assert invitation.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in invitation.headers["Content-Security-Policy"]


def test_cors_allows_configured_origin_and_rejects_unlisted_origin(client):
    allowed = client.options("/auth/login", headers={
        "Origin": "http://127.0.0.1:3000",
        "Access-Control-Request-Method": "POST",
    })
    assert allowed.status_code == 200
    assert allowed.headers["Access-Control-Allow-Origin"] == "http://127.0.0.1:3000"
    denied = client.options("/auth/login", headers={
        "Origin": "https://attacker.example",
        "Access-Control-Request-Method": "POST",
    })
    assert denied.status_code == 400


def test_production_never_returns_invitation_link(client):
    _, owner_headers = account(client)
    organization = create_org(client, owner_headers)
    client.app.state.settings.app_env = "production"
    response = client.post(f"/organizations/{organization['id']}/invitations", headers=owner_headers, json={
        "email": f"production-{uuid4()}@example.com", "role": "viewer",
    })
    assert response.status_code == 201
    assert response.json()["invitation_url"] is None
