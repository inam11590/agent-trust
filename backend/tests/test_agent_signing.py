"""Step 17: public-key identity, exact bytes, replay safety, and tenant isolation."""

import base64
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.session import create_database_engine, get_db
from app.main import create_app
from app.models import Agent, AgentRequestNonce, AgentSigningKey, AgentStatus, AuditLog, AuthorizationRequestRecord, Notification, OrganizationMember, OrganizationRole, RiskAssessment, SecurityEvent
from app.services.agent_signing import SigningError, canonical_request, cleanup_expired_nonces, fingerprint, verify_request
from app.services.notification_delivery import process_signing_key_expiry_notifications

pytestmark = pytest.mark.skipif(os.getenv("RUN_DATABASE_TESTS") != "1", reason="Database tests disabled")
VECTOR = Path(__file__).resolve().parents[2] / "docs" / "test-vectors" / "agent-signing-v1.properties"


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
                                  postgres_user="", postgres_password="", redis_url="")
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as value:
        yield value


def account(client):
    body = {"email": f"sign-{uuid4()}@example.com", "password": secrets.token_urlsafe(24), "full_name": "Inam"}
    user = client.post("/auth/register", json=body).json()
    login = client.post("/auth/login", json={"email": body["email"], "password": body["password"]})
    assert login.status_code == 200, login.text
    return user, {"Authorization": f"Bearer {login.json()['access_token']}"}


def setup(client, db, *, organization_id=None, user_headers=None, maximum="5000"):
    if user_headers is None:
        _, user_headers = account(client)
    scope = {**user_headers, **({"X-Organization-ID": organization_id} if organization_id else {})}
    agent = client.post("/agents", headers=scope, json={"name": "Travel Assistant",
        **({"organization_id": organization_id} if organization_id else {})})
    assert agent.status_code == 201, agent.text
    agent = agent.json()
    db.get(Agent, UUID(agent["id"])).status = AgentStatus.ACTIVE
    db.commit()
    now = datetime.now(timezone.utc)
    permission = client.post("/permissions", headers=scope, json={
        "agent_id": agent["id"], "action": "purchase", "resource": "flight",
        "maximum_amount": maximum, "currency": "USD",
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
    })
    assert permission.status_code == 201, permission.text
    api_key = client.post("/developer/api-keys", headers=scope, json={"name": "Signer"})
    assert api_key.status_code == 201, api_key.text
    return agent, user_headers, {"X-API-Key": api_key.json()["api_key"]}


def key_pair(client, agent, headers, *, private=None, expires_at=None):
    private = private or Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    payload = {"algorithm": "Ed25519", "public_key": base64.b64encode(raw).decode()}
    if expires_at is not None:
        payload["expires_at"] = expires_at.isoformat()
    response = client.post(f"/agents/{agent['id']}/signing-keys", headers=headers, json=payload)
    assert response.status_code == 201, response.text
    return private, response.json()


def body_for(agent, amount=420, *, action="purchase", resource="flight"):
    return (f'{{"agent_id":"{agent["agent_identifier"]}","action":"{action}",'
            f'"resource":"{resource}","amount":{amount},"currency":"USD"}}').encode()


def signed(private, agent_id, key_id, body, *, timestamp=None, nonce=None, method="POST", path="/api/v1/authorize"):
    timestamp = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = nonce or f"nonce_{secrets.token_hex(16)}"
    return {"X-Agent-ID": agent_id, "X-Agent-Key-ID": key_id,
        "X-Agent-Timestamp": timestamp, "X-Agent-Nonce": nonce,
        "X-Agent-Signature": base64.b64encode(private.sign(canonical_request(
            method, path, agent_id, key_id, timestamp, nonce, body))).decode(),
        "X-Agent-Signature-Version": "v1"}


def send(client, api_headers, headers, body):
    return client.post("/api/v1/authorize", headers={**api_headers, **headers,
        "Content-Type": "application/json"}, content=body)


def test_valid_signed_request_audits_identity_and_permission_denial(client, db):
    agent, user_headers, api = setup(client, db)
    private, key = key_pair(client, agent, user_headers)
    raw = base64.b64decode(key["public_key"])
    assert key["fingerprint"] == hashlib.sha256(raw).hexdigest()
    assert "private_key" not in str(key).lower()
    assert not hasattr(db.get(AgentSigningKey, UUID(key["id"])), "private_key")
    body = body_for(agent)
    first = send(client, api, signed(private, agent["agent_identifier"], key["key_id"], body), body)
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "APPROVED"
    request_id = first.json()["request_id"]
    record = db.scalar(select(AuditLog).where(AuditLog.request_id == request_id)) or db.scalar(
        select(AuthorizationRequestRecord).where(AuthorizationRequestRecord.request_id == request_id))
    assert record.signature_verified is True
    assert record.signing_key_id == key["key_id"] and record.signature_version == "v1"
    assert db.scalar(select(RiskAssessment).where(RiskAssessment.request_id == request_id)) is not None
    denied_body = body_for(agent, action="delete")
    denied = send(client, api, signed(private, agent["agent_identifier"], key["key_id"], denied_body), denied_body)
    assert denied.status_code == 200 and denied.json()["status"] == "REJECTED"
    assert denied.json()["reason"] == "Action not permitted"


def test_modified_body_method_path_and_malformed_signature_fail_before_business(client, db):
    agent, headers, api = setup(client, db)
    private, key = key_pair(client, agent, headers)
    body = body_for(agent)
    base = signed(private, agent["agent_identifier"], key["key_id"], body)
    for changed_headers, changed_body in [
        (base, body_for(agent, 4200)),
        (signed(private, agent["agent_identifier"], key["key_id"], body, method="GET"), body),
        (signed(private, agent["agent_identifier"], key["key_id"], body, path="/api/v1/other"), body),
        ({**base, "X-Agent-Signature": "not-base64"}, body),
    ]:
        result = send(client, api, changed_headers, changed_body)
        assert result.status_code == 401 and result.json()["detail"] == "INVALID_AGENT_SIGNATURE", result.text
    assert db.scalar(select(AuditLog).where(AuditLog.agent_identifier == agent["agent_identifier"])) is None
    assert db.scalar(select(SecurityEvent).where(SecurityEvent.event_type == "agent_signature_failed")) is not None


def test_replay_timestamps_and_version(client, db):
    agent, headers, api = setup(client, db)
    private, key = key_pair(client, agent, headers)
    body = body_for(agent)
    signed_headers = signed(private, agent["agent_identifier"], key["key_id"], body)
    assert send(client, api, signed_headers, body).status_code == 200
    again = send(client, api, signed_headers, body)
    assert again.status_code == 409 and again.json()["detail"] == "REPLAY_DETECTED"
    assert db.scalar(select(SecurityEvent).where(SecurityEvent.event_type == "agent_replay_detected")) is not None
    for minutes in (-10, 10):
        timestamp = (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
        invalid = send(client, api, signed(private, agent["agent_identifier"], key["key_id"], body,
            timestamp=timestamp), body)
        assert invalid.status_code == 401 and invalid.json()["detail"] == "REQUEST_TIMESTAMP_INVALID"
    wrong_version = {**signed(private, agent["agent_identifier"], key["key_id"], body),
        "X-Agent-Signature-Version": "v2"}
    assert send(client, api, wrong_version, body).json()["detail"] == "UNKNOWN_AGENT_SIGNATURE_VERSION"


def test_wrong_key_agent_organization_and_expired_key(client, db):
    agent, headers, api = setup(client, db)
    private, key = key_pair(client, agent, headers)
    body = body_for(agent)
    other = Ed25519PrivateKey.generate()
    assert send(client, api, signed(other, agent["agent_identifier"], key["key_id"], body), body).status_code == 401
    other_agent = client.post("/agents", headers=headers, json={"name": "Other"}).json()
    wrong_body = body_for(other_agent)
    wrong_agent = send(client, api, signed(private, agent["agent_identifier"], key["key_id"], wrong_body), wrong_body)
    assert wrong_agent.status_code == 401
    org = client.post("/organizations", headers=headers, json={"name": "Other Company"}).json()
    org_api = client.post("/developer/api-keys", headers={**headers, "X-Organization-ID": org["id"]},
        json={"name": "Other Company Key"}).json()
    wrong_org = send(client, {"X-API-Key": org_api["api_key"]},
        signed(private, agent["agent_identifier"], key["key_id"], body), body)
    assert wrong_org.status_code == 401 and wrong_org.json()["detail"] == "INVALID_AGENT_SIGNATURE"
    stored = db.get(AgentSigningKey, UUID(key["id"]))
    stored.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    expired = send(client, api, signed(private, agent["agent_identifier"], key["key_id"], body), body)
    assert expired.status_code == 401 and expired.json()["detail"] == "SIGNING_KEY_EXPIRED"


def test_rotation_overlap_revocation_and_registration_validation(client, db):
    agent, headers, api = setup(client, db)
    malformed = client.post(f"/agents/{agent['id']}/signing-keys", headers=headers,
        json={"algorithm": "Ed25519", "public_key": "a" * 44})
    assert malformed.status_code == 422
    first_private, first = key_pair(client, agent, headers)
    assert client.post(f"/agents/{agent['id']}/signing-keys", headers=headers,
        json={"public_key": first["public_key"]}).status_code == 409
    second_private = Ed25519PrivateKey.generate()
    raw = second_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    rotated = client.post(f"/agents/{agent['id']}/signing-keys/{first['key_id']}/rotate", headers=headers,
        json={"public_key": base64.b64encode(raw).decode()})
    assert rotated.status_code == 201, rotated.text
    second = rotated.json()
    assert second["rotated_from_key_id"] == first["key_id"]
    body = body_for(agent)
    for private, key in [(first_private, first), (second_private, second)]:
        assert send(client, api, signed(private, agent["agent_identifier"], key["key_id"], body), body).status_code == 200
    revoked = client.post(f"/agents/{agent['id']}/signing-keys/{first['key_id']}/revoke", headers=headers)
    assert revoked.status_code == 200 and revoked.json()["status"] == "REVOKED"
    blocked = send(client, api, signed(first_private, agent["agent_identifier"], first["key_id"], body), body)
    assert blocked.status_code == 401 and blocked.json()["detail"] == "SIGNING_KEY_REVOKED"
    assert send(client, api, signed(second_private, agent["agent_identifier"], second["key_id"], body), body).status_code == 200
    assert db.scalar(select(SecurityEvent).where(SecurityEvent.event_type == "agent_signing_key_rotated")) is not None
    assert db.scalar(select(SecurityEvent).where(SecurityEvent.event_type == "agent_signing_key_revoked")) is not None


def test_unsigned_bypass_role_scope_body_limit_and_replay_outage(client, db):
    agent, headers, api = setup(client, db)
    private, key = key_pair(client, agent, headers)
    body = body_for(agent)
    assert send(client, api, {}, body).json()["detail"] == "AGENT_SIGNATURE_REQUIRED"
    assert send(client, api, {}, b"{" + b" " * 70000 + b"}").status_code == 413
    _, other_headers = account(client)
    assert client.get(f"/agents/{agent['id']}/signing-keys", headers=other_headers).status_code == 404
    assert client.post(f"/agents/{agent['id']}/signing-keys/{key['key_id']}/revoke", headers=other_headers).status_code == 404
    from pydantic import SecretStr
    client.app.state.settings.redis_url = SecretStr("redis://unavailable/0")
    class BrokenRedis:
        def set(self, *args, **kwargs):
            raise ConnectionError("test-only outage")
        def close(self):
            pass
    client.app.state.redis_client = BrokenRedis()
    outage = send(client, api, signed(private, agent["agent_identifier"], key["key_id"], body), body)
    assert outage.status_code == 503 and outage.json()["detail"] == "REPLAY_PROTECTION_UNAVAILABLE"
    assert db.scalar(select(AuditLog).where(AuditLog.agent_identifier == agent["agent_identifier"])) is None


def test_official_vector_matches_backend_canonicalization():
    properties = dict(line.split("=", 1) for line in VECTOR.read_text().splitlines() if line and not line.startswith("#"))
    body = base64.b64decode(properties["body_base64"])
    canonical = canonical_request(properties["method"], properties["path"], properties["agent_id"],
        properties["key_id"], properties["timestamp"], properties["nonce"], body)
    assert hashlib.sha256(body).hexdigest() == properties["body_sha256"]
    assert base64.b64encode(canonical).decode() == properties["canonical_base64"]
    assert fingerprint(base64.b64decode(properties["public_raw_base64"])) == hashlib.sha256(
        base64.b64decode(properties["public_raw_base64"])).hexdigest()
    private = serialization.load_der_private_key(base64.b64decode(properties["private_pkcs8_base64"]), password=None)
    assert base64.b64encode(private.sign(canonical)).decode() == properties["signature_base64"]
    private.public_key().verify(base64.b64decode(properties["signature_base64"]), canonical)


def test_python_sdk_signs_request_accepted_by_backend(client, db):
    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python" / "src"
    sys.path.insert(0, str(sdk_path))
    try:
        from agenttrust.signing import AgentSigner
        agent, headers, api = setup(client, db)
        private = Ed25519PrivateKey.generate()
        pem = private.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        _, key = key_pair(client, agent, headers, private=private)
        body = body_for(agent)
        with patch.object(Path, "read_bytes", return_value=pem):
            signer = AgentSigner(agent["agent_identifier"], key["key_id"], "test-only-agent-key.pem")
        sdk_headers = signer.headers(
            "POST", "/api/v1/authorize", body)
        result = send(client, api, sdk_headers, body)
        assert result.status_code == 200, result.text
        assert result.json()["status"] == "APPROVED"
    finally:
        sys.path.remove(str(sdk_path))


def test_redis_atomic_replay_and_expiry_notification(client, db):
    agent, headers, api = setup(client, db)
    private, key = key_pair(client, agent, headers,
        expires_at=datetime.now(timezone.utc) + timedelta(days=3))
    from pydantic import SecretStr
    client.app.state.settings.redis_url = SecretStr("redis://test-only/0")
    class FakeRedis:
        def __init__(self): self.values = set()
        def set(self, name, value, *, nx, ex):
            assert nx is True and ex >= 600
            if name in self.values: return None
            self.values.add(name); return True
        def close(self): pass
    client.app.state.redis_client = FakeRedis()
    body = body_for(agent)
    headers_signed = signed(private, agent["agent_identifier"], key["key_id"], body)
    assert send(client, api, headers_signed, body).status_code == 200
    assert send(client, api, headers_signed, body).json()["detail"] == "REPLAY_DETECTED"
    count = process_signing_key_expiry_notifications(db, client.app.state.settings)
    assert count == 1
    assert process_signing_key_expiry_notifications(db, client.app.state.settings) == 0
    assert db.scalar(select(Notification).where(Notification.deduplication_key ==
        f"agent-signing-key-expiring:{key['key_id']}")) is not None


def test_signature_failure_rate_limit_and_key_cap(client, db):
    agent, headers, api = setup(client, db)
    private, key = key_pair(client, agent, headers)
    client.app.state.settings.agent_signature_failure_limit_per_minute = 2
    body = body_for(agent)
    invalid = signed(Ed25519PrivateKey.generate(), agent["agent_identifier"], key["key_id"], body)
    assert send(client, api, invalid, body).status_code == 401
    assert send(client, api, invalid, body).status_code == 401
    assert send(client, api, invalid, body).status_code == 429
    for _ in range(2): key_pair(client, agent, headers)
    fourth = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    blocked = client.post(f"/agents/{agent['id']}/signing-keys", headers=headers,
        json={"public_key": base64.b64encode(fourth).decode()})
    assert blocked.status_code == 409 and blocked.json()["detail"] == "ACTIVE_KEY_LIMIT_REACHED"


def test_signed_agent_still_needs_api_key_and_organization_policy(client, db):
    _, owner_headers = account(client)
    org = client.post("/organizations", headers=owner_headers, json={"name": "SkyTravel"}).json()
    agent, headers, api = setup(client, db, organization_id=org["id"], user_headers=owner_headers)
    private, key = key_pair(client, agent, {**headers, "X-Organization-ID": org["id"]})
    body = body_for(agent, 1500)
    proof = signed(private, agent["agent_identifier"], key["key_id"], body)
    assert client.post("/api/v1/authorize", headers=proof, content=body).status_code == 401
    policy = client.put(f"/organizations/{org['id']}/security-policy", headers=headers,
        json={"require_manual_approval_above_amount": "1000", "approval_threshold_currency": "USD"})
    assert policy.status_code == 200, policy.text
    pending = send(client, api, proof, body)
    assert pending.status_code == 200 and pending.json()["status"] == "PENDING", pending.text
    record = db.scalar(select(AuthorizationRequestRecord).where(
        AuthorizationRequestRecord.request_id == pending.json()["request_id"]))
    assert record.signature_verified is True and record.signing_key_id == key["key_id"]
    assert db.scalar(select(Notification).where(Notification.related_request_id == record.id)) is not None
    approved = client.post(f"/authorization-requests/{record.id}/approve",
        headers={**headers, "X-Organization-ID": org["id"]})
    assert approved.status_code == 200, approved.text
    final_audit = db.scalar(select(AuditLog).where(AuditLog.request_id == pending.json()["request_id"]))
    assert final_audit.signature_verified is True and final_audit.signing_key_id == key["key_id"]


def test_organization_viewer_cannot_register_signing_key(client, db):
    owner, owner_headers = account(client)
    viewer, viewer_headers = account(client)
    org = client.post("/organizations", headers=owner_headers, json={"name": "Restricted"}).json()
    db.add(OrganizationMember(organization_id=UUID(org["id"]), user_id=UUID(viewer["id"]),
        role=OrganizationRole.VIEWER))
    db.commit()
    agent, _, _ = setup(client, db, organization_id=org["id"], user_headers=owner_headers)
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    viewer_scope = {**viewer_headers, "X-Organization-ID": org["id"]}
    assert client.get(f"/agents/{agent['id']}/signing-keys", headers=viewer_scope).status_code == 200
    forbidden = client.post(f"/agents/{agent['id']}/signing-keys", headers=viewer_scope,
        json={"public_key": base64.b64encode(raw).decode()})
    assert forbidden.status_code == 403


def test_duplicate_signed_headers_are_rejected_before_key_lookup():
    with pytest.raises(SigningError) as failure:
        verify_request(None, None, None, None, agent_id="agt_" + "a" * 24,
            headers={}, body=b"{}", method="POST", path="/api/v1/authorize",
            raw_headers=[(b"x-agent-id", b"first"), (b"X-Agent-ID", b"second")])
    assert failure.value.code == "INVALID_AGENT_SIGNATURE"


def test_expired_nonce_records_are_removed_in_bounded_batches(db):
    expired = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.add_all([AgentRequestNonce(key_id="key_ag_" + "a" * 24, nonce_hash=f"{number:064x}",
                                  expires_at=expired) for number in range(3)])
    db.commit()
    assert cleanup_expired_nonces(db, batch_size=2) == 2
    assert cleanup_expired_nonces(db, batch_size=2) == 1
    assert cleanup_expired_nonces(db, batch_size=2) == 0
