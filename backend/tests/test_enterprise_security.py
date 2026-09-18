"""Step 16 database-backed account security and organization-policy checks."""

import os
import secrets
import json
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4
from urllib.parse import parse_qs, urlsplit

import pyotp
import httpx
import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.session import create_database_engine, get_db
from app.main import create_app
from app.models import Agent, AgentStatus, AuthSession, AuthorizationRequestRecord, DeliveryChannel, MFACredential, MFARecoveryCode, Notification, NotificationDelivery, OrganizationMember, OrganizationRole, OrganizationSecurityPolicy, RiskAction, RiskLevel, SecurityEvent, SSOConnection
from app.services import sso
from app.services.organization_policy import evaluate_organization_policy
from app.services.risk_engine import RiskEvaluation
from app.schemas.authorization import AuthorizationRequest

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
    app.state.settings = Settings(_env_file=None, app_env="test", jwt_secret_key=secrets.token_urlsafe(48),
        mfa_encryption_key=Fernet.generate_key().decode(), postgres_user="", postgres_password="")
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as value:
        yield value


def account(client, name="Inam"):
    body = {"email": f"secure-{uuid4()}@example.com", "password": secrets.token_urlsafe(24), "full_name": name}
    result = client.post("/auth/register", json=body)
    assert result.status_code == 201, result.text
    login = client.post("/auth/login", json={"email": body["email"], "password": body["password"]})
    assert login.status_code == 200, login.text
    return result.json(), body, {"Authorization": f"Bearer {login.json()['access_token']}"}


def enable_mfa(client, headers):
    setup = client.post("/security/mfa/setup", headers=headers)
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    assert secret not in str(client.get("/users/me", headers=headers).json())
    code = pyotp.TOTP(secret).now()
    confirm = client.post("/security/mfa/confirm", headers=headers, json={"code": code})
    assert confirm.status_code == 200, confirm.text
    return secret, confirm.json()["recovery_codes"]


def test_mfa_setup_requires_valid_code_and_encrypts_secret(client, db):
    user, _, headers = account(client)
    setup = client.post("/security/mfa/setup", headers=headers)
    assert setup.status_code == 200 and setup.json()["otpauth_uri"].startswith("otpauth://")
    assert client.post("/security/mfa/confirm", headers=headers, json={"code": "000000"}).status_code == 400
    assert client.get("/security/mfa", headers=headers).json()["enabled"] is False
    secret = setup.json()["secret"]
    stored = db.get(MFACredential, UUID(user["id"]))
    assert secret not in stored.encrypted_secret
    codes = client.post("/security/mfa/confirm", headers=headers, json={"code": pyotp.TOTP(secret).now()}).json()["recovery_codes"]
    assert len(codes) == 10
    assert codes[0] not in str(db.scalars(select(MFARecoveryCode).where(MFARecoveryCode.user_id == UUID(user["id"]))).all())


def test_mfa_login_recovery_one_use_and_rate_limit(client, db):
    user, credentials, headers = account(client)
    secret, codes = enable_mfa(client, headers)
    first = client.post("/auth/login", json={"email": credentials["email"], "password": credentials["password"]}).json()
    assert first["status"] == "MFA_REQUIRED" and "access_token" not in first
    invalid = client.post("/auth/mfa/verify", json={"challenge_token": first["challenge_token"], "code": "000000"})
    assert invalid.status_code == 401
    approved = client.post("/auth/mfa/verify", json={"challenge_token": first["challenge_token"], "code": codes[0]})
    assert approved.status_code == 200, approved.text
    assert client.get("/users/me", headers={"Authorization": f"Bearer {approved.json()['access_token']}"}).status_code == 200
    second = client.post("/auth/login", json={"email": credentials["email"], "password": credentials["password"]}).json()
    reused = client.post("/auth/mfa/verify", json={"challenge_token": second["challenge_token"], "code": codes[0]})
    assert reused.status_code == 401
    for _ in range(4):
        client.post("/auth/mfa/verify", json={"challenge_token": second["challenge_token"], "code": "000000"})
    locked = client.post("/auth/login", json={"email": credentials["email"], "password": credentials["password"]}).json()
    assert client.post("/auth/mfa/verify", json={"challenge_token": locked["challenge_token"], "code": codes[1]}).status_code == 401
    assert db.scalar(select(SecurityEvent).where(SecurityEvent.actor_user_id == UUID(user["id"]), SecurityEvent.event_type == "mfa_failed")) is not None


def test_session_revocation_and_isolation(client, db):
    user, credentials, first_headers = account(client)
    second_login = client.post("/auth/login", json={"email": credentials["email"], "password": credentials["password"]}).json()
    second_headers = {"Authorization": f"Bearer {second_login['access_token']}"}
    sessions = client.get("/security/sessions", headers=second_headers).json()
    assert len(sessions) == 2 and any(item["current"] for item in sessions)
    other_session = next(item for item in sessions if not item["current"])
    stranger, _, stranger_headers = account(client)
    assert client.post(f"/security/sessions/{other_session['id']}/revoke", headers=stranger_headers).status_code == 404
    assert client.post("/security/sessions/revoke-others", headers=second_headers).json()["revoked"] == 1
    assert client.get("/users/me", headers=first_headers).status_code == 401
    assert client.get("/users/me", headers=second_headers).status_code == 200
    assert client.post("/auth/logout", headers=second_headers).status_code == 204
    assert client.get("/users/me", headers=second_headers).status_code == 401
    assert db.scalar(select(AuthSession).where(AuthSession.user_id == UUID(user["id"]), AuthSession.revoked_at.is_not(None))) is not None


def test_new_device_login_sends_one_security_alert(client, db):
    user, credentials, _ = account(client)
    for _ in range(2):
        result = client.post("/auth/login", headers={"User-Agent": "AgentTrust Android"},
            json={"email": credentials["email"], "password": credentials["password"]})
        assert result.status_code == 200, result.text
    notices = list(db.scalars(select(Notification).where(
        Notification.user_id == UUID(user["id"]), Notification.title == "New Sign-In Device")))
    assert len(notices) == 1


def test_expired_session_is_rejected(client, db):
    user, _, headers = account(client)
    session = db.scalar(select(AuthSession).where(AuthSession.user_id == UUID(user["id"])))
    session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    assert client.get("/users/me", headers=headers).status_code == 401


def test_password_change_requires_current_password_and_revokes_other_sessions(client, db):
    user, credentials, first_headers = account(client)
    second = client.post("/auth/login", json={"email": credentials["email"], "password": credentials["password"]}).json()
    second_headers = {"Authorization": f"Bearer {second['access_token']}"}
    invalid = client.post("/security/password", headers=second_headers,
        json={"current_password": "incorrect", "new_password": "a-very-different-secure-password"})
    assert invalid.status_code == 401
    changed = client.post("/security/password", headers=second_headers,
        json={"current_password": credentials["password"], "new_password": "a-very-different-secure-password"})
    assert changed.status_code == 204, changed.text
    assert client.get("/users/me", headers=first_headers).status_code == 401
    assert client.get("/users/me", headers=second_headers).status_code == 200
    assert client.post("/auth/login", json={"email": credentials["email"], "password": credentials["password"]}).status_code == 401
    assert client.post("/auth/login", json={"email": credentials["email"], "password": "a-very-different-secure-password"}).status_code == 200
    assert db.scalar(select(SecurityEvent).where(SecurityEvent.actor_user_id == UUID(user["id"]), SecurityEvent.event_type == "password_changed")) is not None


def test_totp_login_and_required_mfa_cannot_be_disabled(client, db):
    user, credentials, headers = account(client)
    secret, codes = enable_mfa(client, headers)
    future_step = int(datetime.now(timezone.utc).timestamp()) // 30 + 1
    code = pyotp.TOTP(secret).at(future_step * 30)
    challenge = client.post("/auth/login", json={"email": credentials["email"], "password": credentials["password"]}).json()
    result = client.post("/auth/mfa/verify", json={"challenge_token": challenge["challenge_token"], "code": code})
    assert result.status_code == 200, result.text
    org = client.post("/organizations", headers={"Authorization": f"Bearer {result.json()['access_token']}"}, json={"name": "Required MFA"}).json()
    policy = client.put(f"/organizations/{org['id']}/security-policy",
        headers={"Authorization": f"Bearer {result.json()['access_token']}"}, json={"require_mfa": True})
    assert policy.status_code == 200, policy.text
    denied = client.post("/security/mfa/disable", headers={"Authorization": f"Bearer {result.json()['access_token']}"},
        json={"password": credentials["password"], "code": codes[0]})
    assert denied.status_code == 403
    assert db.get(MFACredential, UUID(user["id"])).enabled_at is not None


def test_policy_owner_only_mfa_enforcement_and_security_events(client, db):
    owner, _, owner_headers = account(client)
    org = client.post("/organizations", headers=owner_headers, json={"name": "SkyTravel"}).json()
    other, _, other_headers = account(client)
    org_id = org["id"]
    assert client.put(f"/organizations/{org_id}/security-policy", headers=other_headers, json={"require_mfa": True}).status_code == 404
    current = client.get(f"/organizations/{org_id}/security-policy", headers=owner_headers)
    assert current.status_code == 200 and current.json()["require_mfa"] is False
    changed = client.put(f"/organizations/{org_id}/security-policy", headers=owner_headers, json={"require_mfa": True})
    assert changed.status_code == 200, changed.text
    assert client.get("/agents", headers={**owner_headers, "X-Organization-ID": org_id}).status_code == 403
    assert client.get("/security/mfa", headers=owner_headers).status_code == 200
    secret, _ = enable_mfa(client, owner_headers)
    own_events = client.get("/security/events", headers=owner_headers)
    assert own_events.status_code == 200
    assert any(item["actor_name"] == "Inam" for item in own_events.json()["items"])
    assert client.get("/security/events", headers=other_headers).json()["total"] >= 1
    assert db.get(OrganizationSecurityPolicy, UUID(org_id)).require_mfa is True


def test_high_value_policy_queues_without_overriding_permission_deny(client, db):
    _, _, headers = account(client)
    org = client.post("/organizations", headers=headers, json={"name": "SkyTravel"}).json()
    scoped = {**headers, "X-Organization-ID": org["id"]}
    agent = client.post("/agents", headers=scoped, json={"name": "Travel Assistant"}).json()
    db.get(Agent, UUID(agent["id"])).status = AgentStatus.ACTIVE
    db.commit()
    now = datetime.now(timezone.utc)
    permission = client.post("/permissions", headers=scoped, json={
        "agent_id": agent["id"], "action": "purchase", "resource": "flight",
        "maximum_amount": "5000", "currency": "USD",
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
    })
    assert permission.status_code == 201, permission.text
    policy = client.put(f"/organizations/{org['id']}/security-policy", headers=headers,
        json={"require_manual_approval_above_amount": "1000"})
    assert policy.status_code == 200, policy.text
    partial = client.put(f"/organizations/{org['id']}/security-policy", headers=headers, json={"require_mfa": False})
    assert partial.status_code == 200 and partial.json()["require_manual_approval_above_amount"] == "1000.0000"
    device = client.post("/devices", headers=headers,
        json={"push_token": secrets.token_urlsafe(32), "platform": "android"})
    assert device.status_code == 201, device.text
    def ask(amount):
        return client.post("/authorize", headers=scoped, json={"agent_id": agent["agent_identifier"],
            "action": "purchase", "resource": "flight", "amount": amount, "currency": "USD"})
    low = ask("500")
    assert low.status_code == 200 and low.json()["decision"] == "APPROVED", low.text
    high = ask("1500")
    assert high.status_code == 200 and high.json()["decision"] == "PENDING", high.text
    assert "Organization policy requires approval" in high.json()["reason"]
    pending = db.scalar(select(AuthorizationRequestRecord).where(AuthorizationRequestRecord.request_id == high.json()["request_id"]))
    assert pending.policy_reason == high.json()["reason"]
    assert db.scalar(select(Notification).where(Notification.related_request_id.is_not(None))) is not None
    assert db.scalar(select(NotificationDelivery).join(Notification,
        Notification.id == NotificationDelivery.notification_id).where(
            Notification.related_request_id == pending.id, NotificationDelivery.channel == DeliveryChannel.PUSH,
        )) is not None
    rejected = ask("7000")
    assert rejected.status_code == 200 and rejected.json()["decision"] == "REJECTED"
    assert rejected.json()["reason"] == "Amount exceeds allowed limit"
    approved = client.post(f"/authorization-requests/{pending.id}/approve", headers=scoped)
    assert approved.status_code == 200 and approved.json()["status"] == "APPROVED", approved.text
    assert approved.json()["policy_reason"] == high.json()["reason"]


def test_viewer_cannot_modify_policy_and_password_session_cannot_bypass_sso(client, db):
    owner, _, owner_headers = account(client)
    viewer, _, viewer_headers = account(client, "Viewer")
    org = client.post("/organizations", headers=owner_headers, json={"name": "Scoped Security"}).json()
    db.add(OrganizationMember(organization_id=UUID(org["id"]), user_id=UUID(viewer["id"]), role=OrganizationRole.VIEWER))
    db.commit()
    assert client.put(f"/organizations/{org['id']}/security-policy", headers=viewer_headers,
        json={"require_mfa": True}).status_code == 403
    settings = client.app.state.settings
    db.add(SSOConnection(organization_id=UUID(org["id"]), name="Mock", issuer="https://id.example.com",
        client_id="client", encrypted_client_secret=sso.encrypt_provider_secret(settings, "secret"),
        discovery_url="https://id.example.com/.well-known/openid-configuration", allowed_domains=[], status="active"))
    db.commit()
    assert client.put(f"/organizations/{org['id']}/security-policy", headers=owner_headers,
        json={"require_sso": True}).status_code == 200
    assert client.get("/agents", headers={**viewer_headers, "X-Organization-ID": org["id"]}).status_code == 403
    assert client.get("/agents", headers={**owner_headers, "X-Organization-ID": org["id"]}).status_code == 200


def test_organization_critical_deny_overrides_weak_risk_allow(client, db):
    _, _, headers = account(client)
    org = client.post("/organizations", headers=headers, json={"name": "Strict Risk"}).json()
    org_id = UUID(org["id"])
    db.add(OrganizationSecurityPolicy(organization_id=org_id, block_critical_risk=True,
        require_approval_for_high_risk=True, allowed_email_domains=[]))
    db.commit()
    request = AuthorizationRequest(agent_id="agt_" + "a" * 24, action="purchase", resource="flight", amount="500", currency="USD")
    critical = RiskEvaluation(score=95, level=RiskLevel.CRITICAL, recommendation=RiskAction.ALLOW, reasons=(), features={})
    high = RiskEvaluation(score=75, level=RiskLevel.HIGH, recommendation=RiskAction.ALLOW, reasons=(), features={})
    low = RiskEvaluation(score=5, level=RiskLevel.LOW, recommendation=RiskAction.ALLOW, reasons=(), features={})
    assert evaluate_organization_policy(db, org_id, request, critical)[0] == "DENY"
    assert evaluate_organization_policy(db, org_id, request, high)[0] == "REQUIRE_APPROVAL"
    assert evaluate_organization_policy(db, org_id, request, low)[0] == "ALLOW"
    policy = db.get(OrganizationSecurityPolicy, org_id)
    policy.require_manual_approval_above_amount = 1000
    policy.approval_threshold_currency = "USD"
    db.flush()
    different_currency = request.model_copy(update={"currency": "EUR"})
    assert evaluate_organization_policy(db, org_id, different_currency, low)[0] == "REQUIRE_APPROVAL"
    assert evaluate_organization_policy(db, org_id, request, low)[0] == "ALLOW"


def test_oidc_claims_reject_wrong_issuer_audience_nonce_expiry_and_signature():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    public["kid"] = "key-1"
    jwks = {"keys": [public]}
    connection = SSOConnection(issuer="https://id.example.com", client_id="agenttrust-client")
    now = int(datetime.now(timezone.utc).timestamp())
    claims = {"iss": connection.issuer, "aud": connection.client_id, "sub": "employee-1", "nonce": "fresh-nonce",
        "email": "inam@example.com", "email_verified": True, "iat": now, "exp": now + 300, "amr": ["mfa"]}
    def encoded(changes=None, signing_key=key):
        return jwt.encode({**claims, **(changes or {})}, signing_key, algorithm="RS256", headers={"kid": "key-1"})
    assert sso._validated_claims(encoded(), connection, "fresh-nonce", jwks)["email_verified"] is True
    for bad in ({"iss": "https://attacker.example"}, {"aud": "another-client"}, {"nonce": "wrong"},
                {"exp": now - 300}, {"email_verified": False}):
        with pytest.raises(sso.SSOError):
            sso._validated_claims(encoded(bad), connection, "fresh-nonce", jwks)
    with pytest.raises(sso.SSOError):
        sso._validated_claims(encoded(signing_key=other), connection, "fresh-nonce", jwks)


def test_mock_oidc_flow_checks_state_membership_and_one_use_ticket(client, db, monkeypatch):
    user, _, owner_headers = account(client)
    org = client.post("/organizations", headers=owner_headers, json={"name": "Mock Company"}).json()
    _, _, other_headers = account(client, "Other Owner")
    other_org = client.post("/organizations", headers=other_headers, json={"name": "Other Company"}).json()
    settings = client.app.state.settings
    connection = SSOConnection(organization_id=UUID(org["id"]), name="Mock OIDC",
        issuer="https://id.example.com", client_id="agenttrust-client",
        encrypted_client_secret=sso.encrypt_provider_secret(settings, "test-client-secret"),
        discovery_url="https://id.example.com/.well-known/openid-configuration",
        allowed_domains=["example.com"], status="active")
    db.add(connection); db.commit()
    other_connection = SSOConnection(organization_id=UUID(other_org["id"]), name="Other Mock OIDC",
        issuer=connection.issuer, client_id=connection.client_id,
        encrypted_client_secret=sso.encrypt_provider_secret(settings, "test-client-secret"),
        discovery_url=connection.discovery_url, allowed_domains=["example.com"], status="active")
    db.add(other_connection); db.commit()
    metadata = {"issuer": connection.issuer, "authorization_endpoint": "https://id.example.com/authorize",
        "token_endpoint": "https://id.example.com/token", "jwks_uri": "https://id.example.com/keys"}
    monkeypatch.setattr(sso, "fetch_discovery", lambda *_: metadata)
    location = sso.start_login(db, connection, settings)
    params = parse_qs(urlsplit(location).query)
    state = params["state"][0]
    assert params["code_challenge_method"] == ["S256"]
    with pytest.raises(sso.SSOError):
        sso.complete_login(db, "wrong-state", "mock-code", settings)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    public["kid"] = "mock-key"
    now = int(datetime.now(timezone.utc).timestamp())
    claims = {"iss": connection.issuer, "aud": connection.client_id, "sub": "mock-employee",
        "nonce": params["nonce"][0], "email": user["email"], "email_verified": True,
        "iat": now, "exp": now + 300, "amr": ["mfa"]}
    token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "mock-key"})
    original_client = httpx.Client
    def transport_handler(request):
        if request.url.path == "/token":
            assert b"code_verifier=" in request.content
            if metadata.get("token_endpoint_auth_methods_supported") == ["client_secret_post"]:
                assert b"client_secret=test-client-secret" in request.content
                assert "authorization" not in request.headers
            else:
                assert request.headers["authorization"].startswith("Basic ")
            return httpx.Response(200, json={"id_token": token})
        return httpx.Response(200, json={"keys": [public]})
    monkeypatch.setattr(sso.httpx, "Client", lambda **kwargs: original_client(transport=httpx.MockTransport(transport_handler)))
    ticket = sso.complete_login(db, state, "mock-code", settings)
    authenticated, factor = sso.redeem_ticket(db, ticket)
    assert str(authenticated.id) == user["id"] and factor is True
    with pytest.raises(sso.SSOError):
        sso.redeem_ticket(db, ticket)
    with pytest.raises(sso.SSOError):
        sso.complete_login(db, state, "mock-code", settings)
    other_location = sso.start_login(db, other_connection, settings)
    metadata["token_endpoint_auth_methods_supported"] = ["client_secret_post"]
    other_params = parse_qs(urlsplit(other_location).query)
    token = jwt.encode({**claims, "nonce": other_params["nonce"][0]}, key, algorithm="RS256", headers={"kid": "mock-key"})
    with pytest.raises(sso.SSOError, match="active organization member"):
        sso.complete_login(db, other_params["state"][0], "mock-code", settings)


def test_sso_secret_stays_hidden_and_disabled_connection_cannot_start(client, db):
    _, _, headers = account(client)
    org = client.post("/organizations", headers=headers, json={"name": "Private SSO"}).json()
    settings = client.app.state.settings
    connection = SSOConnection(organization_id=UUID(org["id"]), name="OIDC", issuer="https://id.example.com",
        client_id="client", encrypted_client_secret=sso.encrypt_provider_secret(settings, "hidden-secret"),
        discovery_url="https://id.example.com/.well-known/openid-configuration", allowed_domains=[], status="disabled")
    db.add(connection); db.commit()
    response = client.get(f"/organizations/{org['id']}/sso/connections", headers=headers)
    assert response.status_code == 200 and "hidden-secret" not in response.text and "encrypted_client_secret" not in response.text
    assert client.get(f"/auth/sso/{org['id']}/start").status_code == 404
