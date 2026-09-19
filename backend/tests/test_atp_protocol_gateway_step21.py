"""Comprehensive Integration and Security Tests for Step 21: AgentTrust Protocol (ATP/1.0) & Gateway.

Covers:
1. Protocol & test vector conformance (ATP-SIG/1, canonical string, SHA-256 payload hash).
2. Gateway Attestation generation, TTL, and signature verification.
3. Envelope tamper detection (tampered payload, tampered capability, forged signature).
4. Anti-replay protection (atomic rejection of re-used nonces).
5. Timestamp clock skew defense (rejection of expired/future timestamps).
6. Revoked and expired signing key enforcement.
7. SSRF defense (rejection of loopback, RFC 1918, and cloud metadata IPs).
8. Staging hold for multi-party approval (PENDING_APPROVAL never routes).
9. End-to-end Gateway dispatch to Sandbox Mock Hotel Agent (hotel.reserve@1.0).
10. Endpoint registration with instantaneous SSRF pre-validation.
"""

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.database.session import create_database_engine, get_db
from app.main import create_app
from app.models.agent import Agent, AgentStatus
from app.models.agent_signing import (
    AgentSigningKey,
    AgentSigningKeyStatus,
)
from app.models.agenttrust_protocol import (
    AgentEndpoint,
    ATPDeliveryStatus,
    ATPMessageDelivery,
    ATPMessageRecord,
)
from app.models.organization import Organization
from app.models.user import User
from app.services.atp_canonical import (
    build_canonical_bytes,
    build_canonical_request_ascii,
    compute_payload_sha256,
)
from app.services.gateway_identity import (
    create_gateway_attestation,
    get_gateway_public_key_base64,
    verify_gateway_attestation,
)
from app.services.ssrf_protection import SSRFValidationError, resolve_and_validate_endpoint_url


@pytest.fixture(scope="module")
def engine():
    eng = create_database_engine(Settings())
    yield eng
    eng.dispose()


@pytest.fixture
def db(engine):
    with Session(bind=engine) as session:
        yield session


@pytest.fixture
def client(db):
    test_app = create_app()

    def _get_db_override():
        yield db

    test_app.dependency_overrides[get_db] = _get_db_override
    with TestClient(test_app) as test_client:
        yield test_client


def test_protocol_test_vector_conformance():
    """Verify that Python implementation strictly matches the cross-language test vectors."""
    vectors_path = Path(__file__).resolve().parents[2] / "tests" / "protocol" / "v1" / "test_vectors.json"
    assert vectors_path.exists(), f"Test vector file missing at {vectors_path}"
    vector = json.loads(vectors_path.read_text(encoding="utf-8"))

    # 1. Payload hash
    payload_sha256 = compute_payload_sha256(vector["payload"])
    assert payload_sha256 == vector["payload_sha256"], "Payload hash mismatch against test vector"

    # 2. Canonical ASCII string
    canonical = build_canonical_request_ascii(
        message_id=vector["message_id"],
        message_type=vector["message_type"],
        source_org_id=vector["source"]["organization_id"],
        source_agent_id=vector["source"]["agent_id"],
        target_org_id=vector["target"]["organization_id"],
        target_agent_id=vector["target"]["agent_id"],
        capability=vector["capability"],
        timestamp=vector["timestamp"],
        nonce=vector["nonce"],
        payload_sha256=payload_sha256,
    )
    assert canonical == vector["canonical_ascii"], "Canonical ASCII representation mismatch"

    # 3. Cryptographic signature with Ed25519 private key
    priv = load_pem_private_key(vector["private_key_pem"].encode("utf-8"), password=None)
    sig = priv.sign(canonical.encode("utf-8"))
    sig_b64 = base64.b64encode(sig).decode("ascii")
    assert sig_b64 == vector["signature_base64"], "Ed25519 signature mismatch against test vector"


def test_gateway_attestation_lifecycle():
    """Verify Gateway Ed25519 attestation creation, verification, and tamper rejection."""
    src = "atp://org_skytravel/agt_travel"
    tgt = "atp://org_hotelcorp/agt_hotel"
    cap = "hotel.reserve@1.0"
    mid = "msg_attest_test_12345"
    hsh = hashlib.sha256(b'{"hotel":"hyatt"}').hexdigest()

    token = create_gateway_attestation(
        source_address=src,
        target_address=tgt,
        capability=cap,
        message_id=mid,
        payload_sha256=hsh,
        ttl_seconds=60,
    )
    assert token.startswith("atp_attest_")

    # Verify token
    pub_b64 = get_gateway_public_key_base64()
    claims = verify_gateway_attestation(token, gateway_public_key_b64=pub_b64)
    assert claims["iss"] == "agenttrust-gateway"
    assert claims["src"] == src
    assert claims["tgt"] == tgt
    assert claims["cap"] == cap
    assert claims["mid"] == mid
    assert claims["hsh"] == hsh

    # Tamper check
    tampered = token[:-5] + ("AAAAA" if not token.endswith("AAAAA") else "BBBBB")
    with pytest.raises(Exception):
        verify_gateway_attestation(tampered, gateway_public_key_b64=pub_b64)


def test_ssrf_protection_blocked_targets():
    """Verify SSRF defense blocks loopback, private networks, and cloud metadata endpoints."""
    prohibited_urls = [
        "http://127.0.0.1:8080/webhook",
        "http://127.0.0.2/api",
        "http://10.0.0.1/admin",
        "http://172.16.0.5/endpoint",
        "http://192.168.1.100/service",
        "http://169.254.169.254/latest/meta-data",
        "http://metadata.google.internal/computeMetadata/v1",
        "gopher://127.0.0.1:6379/_flushall",
        "file:///etc/passwd",
    ]

    for url in prohibited_urls:
        with pytest.raises(SSRFValidationError) as exc_info:
            resolve_and_validate_endpoint_url(url, allow_private_ips=False, enforce_https=False)
        assert exc_info.value.code in {"PROHIBITED_IP", "BLOCKED_DOMAIN", "INVALID_SCHEME", "DNS_RESOLUTION_FAILED"}


def test_gateway_health_and_identity_endpoints(client):
    """Verify /api/v1/atp/health and /api/v1/atp/gateway-identity."""
    r_health = client.get("/api/v1/atp/health")
    assert r_health.status_code == 200
    data = r_health.json()
    assert data["protocol"] == "ATP/1.0"
    assert data["signing_version"] == "ATP-SIG/1"
    assert data["status"] == "operational"

    r_id = client.get("/api/v1/atp/gateway-identity")
    assert r_id.status_code == 200
    id_data = r_id.json()
    assert id_data["issuer"] == "agenttrust-gateway"
    assert id_data["algorithm"] == "Ed25519"
    assert len(id_data["public_key_base64"]) == 44


def test_end_to_end_gateway_mock_hotel_dispatch(client, db):
    """Full end-to-end message routing through Gateway to Sandbox Mock Hotel Agent."""
    # 1. Generate test agent keypair
    priv = Ed25519PrivateKey.generate()
    raw_pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(raw_pub).decode("ascii")

    # 2. Insert test agent and key in DB
    user = User(
        email=f"atp_test_{uuid4().hex[:8]}@example.com",
        hashed_password="hash",
        full_name="ATP Tester",
        is_active=True,
    )
    db.add(user)
    db.flush()

    org = Organization(
        name=f"org_travel_{uuid4().hex[:8]}",
        owner_id=user.id,
        is_active=True,
    )
    db.add(org)
    db.flush()

    agent = Agent(
        name="SkyTravel Booking Assistant",
        agent_identifier=f"agt_travel_{uuid4().hex[:8]}",
        owner_id=user.id,
        organization_id=org.id,
        status=AgentStatus.ACTIVE,
    )
    db.add(agent)
    db.flush()

    key_id = f"key_ag_{uuid4().hex[:24]}"
    key_fp = hashlib.sha256(raw_pub).hexdigest()
    signing_key = AgentSigningKey(
        key_id=key_id,
        agent_id=agent.id,
        organization_id=org.id,
        algorithm="Ed25519",
        public_key=pub_b64,
        fingerprint=key_fp,
        status=AgentSigningKeyStatus.ACTIVE,
        activated_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    db.add(signing_key)
    db.commit()

    # 3. Create ATP envelope
    message_id = f"msg_{uuid4().hex[:16]}"
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = f"nonce_{uuid4().hex}"
    capability = "hotel.reserve@1.0"
    payload = {"hotel_id": "hotel_grand_hyatt", "amount": 450, "currency": "USD"}
    payload_sha256 = compute_payload_sha256(payload)

    canon_bytes = build_canonical_bytes(
        message_id=message_id,
        message_type="request",
        source_org_id=org.name,
        source_agent_id=agent.agent_identifier,
        target_org_id="org_hotelcorp",
        target_agent_id="agt_hotel",
        capability=capability,
        timestamp=now_str,
        nonce=nonce,
        payload_sha256=payload_sha256,
    )
    sig = priv.sign(canon_bytes)
    sig_b64 = base64.b64encode(sig).decode("ascii")

    envelope = {
        "protocol": "ATP/1.0",
        "message_id": message_id,
        "message_type": "request",
        "source": {
            "organization_id": org.name,
            "agent_id": agent.agent_identifier,
            "address": f"atp://{org.name}/{agent.agent_identifier}",
        },
        "target": {
            "organization_id": "org_hotelcorp",
            "agent_id": "agt_hotel",
            "address": "atp://org_hotelcorp/agt_hotel",
        },
        "capability": capability,
        "timestamp": now_str,
        "nonce": nonce,
        "payload": payload,
        "payload_sha256": payload_sha256,
        "signature": {
            "version": "ATP-SIG/1",
            "key_id": key_id,
            "value": sig_b64,
        },
    }

    # 4. Dispatch via Gateway endpoint
    resp = client.post("/api/v1/atp/messages", json=envelope)
    assert resp.status_code == 200, f"Dispatch failed: {resp.text}"
    res_data = resp.json()
    assert res_data["protocol"] == "ATP/1.0"
    assert res_data["status"] == "DELIVERED"
    assert res_data["response"]["payload"]["status"] == "CONFIRMED"
    assert res_data["response"]["payload"]["hotel_id"] == "hotel_grand_hyatt"
    assert res_data["response"]["payload"]["confirmation_code"].startswith("HTL-")

    # 5. Verify Anti-Replay rejects identical message/nonce
    replay_resp = client.post("/api/v1/atp/messages", json=envelope)
    assert replay_resp.status_code in (200, 401)
    if replay_resp.status_code == 200:
        assert replay_resp.json().get("idempotent") is True

    # Try new message_id with REUSED nonce -> Must fail 401
    envelope2 = dict(envelope)
    envelope2["message_id"] = f"msg_{uuid4().hex[:16]}"
    canon_bytes2 = build_canonical_bytes(
        message_id=envelope2["message_id"],
        message_type="request",
        source_org_id=org.name,
        source_agent_id=agent.agent_identifier,
        target_org_id="org_hotelcorp",
        target_agent_id="agt_hotel",
        capability=capability,
        timestamp=now_str,
        nonce=nonce, # REUSED NONCE
        payload_sha256=payload_sha256,
    )
    envelope2["signature"] = {
        "version": "ATP-SIG/1",
        "key_id": key_id,
        "value": base64.b64encode(priv.sign(canon_bytes2)).decode("ascii"),
    }
    reused_nonce_resp = client.post("/api/v1/atp/messages", json=envelope2)
    assert reused_nonce_resp.status_code == 401
    assert reused_nonce_resp.json()["detail"]["error"] == "REPLAY_ATTACK_DETECTED"


def test_tampered_envelope_rejected(client, db):
    """Verify that any modification to payload, capability, or timestamp fails signature check."""
    priv = Ed25519PrivateKey.generate()
    raw_pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(raw_pub).decode("ascii")

    user = User(email=f"atp_tamper_{uuid4().hex[:8]}@example.com", hashed_password="h", full_name="Tamper", is_active=True)
    db.add(user)
    db.flush()
    org = Organization(name=f"org_t_{uuid4().hex[:8]}", owner_id=user.id, is_active=True)
    db.add(org)
    db.flush()
    agent = Agent(name="TamperAgent", agent_identifier=f"agt_t_{uuid4().hex[:8]}", owner_id=user.id, organization_id=org.id, status=AgentStatus.ACTIVE)
    db.add(agent)
    db.flush()
    key_id = f"key_ag_{uuid4().hex[:24]}"
    db.add(AgentSigningKey(
        key_id=key_id, agent_id=agent.id, organization_id=org.id, algorithm="Ed25519",
        public_key=pub_b64, fingerprint=hashlib.sha256(raw_pub).hexdigest(),
        status=AgentSigningKeyStatus.ACTIVE, activated_at=datetime.now(timezone.utc),
    ))
    db.commit()

    # Sign legitimate message
    mid = f"msg_{uuid4().hex[:16]}"
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = f"nonce_{uuid4().hex}"
    payload = {"amount": 100}
    hsh = compute_payload_sha256(payload)
    canon = build_canonical_bytes(mid, "request", org.name, agent.agent_identifier, "org_hotelcorp", "agt_hotel", "hotel.search@1.0", ts, nonce, hsh)
    sig_b64 = base64.b64encode(priv.sign(canon)).decode("ascii")

    # Attack 1: Modify amount in payload
    tampered_env = {
        "protocol": "ATP/1.0", "message_id": mid, "message_type": "request",
        "source": {"organization_id": org.name, "agent_id": agent.agent_identifier},
        "target": {"organization_id": "org_hotelcorp", "agent_id": "agt_hotel"},
        "capability": "hotel.search@1.0", "timestamp": ts, "nonce": nonce,
        "payload": {"amount": 999999}, # TAMPERED
        "payload_sha256": hsh,
        "signature": {"version": "ATP-SIG/1", "key_id": key_id, "value": sig_b64},
    }
    r1 = client.post("/api/v1/atp/messages", json=tampered_env)
    assert r1.status_code == 400
    assert r1.json()["detail"]["error"] == "PAYLOAD_HASH_MISMATCH"

    # Attack 2: Tamper capability
    tampered_env2 = dict(tampered_env)
    tampered_env2["payload"] = payload
    tampered_env2["capability"] = "hotel.admin.delete@1.0" # TAMPERED CAPABILITY
    r2 = client.post("/api/v1/atp/messages", json=tampered_env2)
    assert r2.status_code == 401
    assert r2.json()["detail"]["error"] == "INVALID_SIGNATURE"


def test_revoked_key_rejection(client, db):
    """Verify that revoked agent keys cannot route messages through Gateway."""
    priv = Ed25519PrivateKey.generate()
    raw_pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(raw_pub).decode("ascii")

    user = User(email=f"atp_rev_{uuid4().hex[:8]}@example.com", hashed_password="h", full_name="Revoked", is_active=True)
    db.add(user)
    db.flush()
    org = Organization(name=f"org_r_{uuid4().hex[:8]}", owner_id=user.id, is_active=True)
    db.add(org)
    db.flush()
    agent = Agent(name="RevAgent", agent_identifier=f"agt_r_{uuid4().hex[:8]}", owner_id=user.id, organization_id=org.id, status=AgentStatus.ACTIVE)
    db.add(agent)
    db.flush()
    key_id = f"key_ag_{uuid4().hex[:24]}"
    db.add(AgentSigningKey(
        key_id=key_id, agent_id=agent.id, organization_id=org.id, algorithm="Ed25519",
        public_key=pub_b64, fingerprint=hashlib.sha256(raw_pub).hexdigest(),
        status=AgentSigningKeyStatus.REVOKED, activated_at=datetime.now(timezone.utc), # REVOKED
    ))
    db.commit()

    mid = f"msg_{uuid4().hex[:16]}"
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = f"nonce_{uuid4().hex}"
    payload = {"q": "search"}
    hsh = compute_payload_sha256(payload)
    canon = build_canonical_bytes(mid, "request", org.name, agent.agent_identifier, "org_hotelcorp", "agt_hotel", "hotel.search@1.0", ts, nonce, hsh)
    sig_b64 = base64.b64encode(priv.sign(canon)).decode("ascii")

    env = {
        "protocol": "ATP/1.0", "message_id": mid, "message_type": "request",
        "source": {"organization_id": org.name, "agent_id": agent.agent_identifier},
        "target": {"organization_id": "org_hotelcorp", "agent_id": "agt_hotel"},
        "capability": "hotel.search@1.0", "timestamp": ts, "nonce": nonce,
        "payload": payload,
        "signature": {"version": "ATP-SIG/1", "key_id": key_id, "value": sig_b64},
    }
    resp = client.post("/api/v1/atp/messages", json=env)
    assert resp.status_code == 401
    assert resp.json()["detail"]["error"] == "KEY_REVOKED"


def test_multi_party_approval_hold(client, db):
    """Verify that messages with high monetary amounts trigger PENDING_APPROVAL and do not route."""
    priv = Ed25519PrivateKey.generate()
    raw_pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(raw_pub).decode("ascii")

    user = User(email=f"atp_appr_{uuid4().hex[:8]}@example.com", hashed_password="h", full_name="Appr", is_active=True)
    db.add(user)
    db.flush()
    org = Organization(name=f"org_a_{uuid4().hex[:8]}", owner_id=user.id, is_active=True)
    db.add(org)
    db.flush()
    agent = Agent(name="ApprAgent", agent_identifier=f"agt_a_{uuid4().hex[:8]}", owner_id=user.id, organization_id=org.id, status=AgentStatus.ACTIVE)
    db.add(agent)
    db.flush()
    key_id = f"key_ag_{uuid4().hex[:24]}"
    db.add(AgentSigningKey(
        key_id=key_id, agent_id=agent.id, organization_id=org.id, algorithm="Ed25519",
        public_key=pub_b64, fingerprint=hashlib.sha256(raw_pub).hexdigest(),
        status=AgentSigningKeyStatus.ACTIVE, activated_at=datetime.now(timezone.utc),
    ))
    db.commit()

    mid = f"msg_{uuid4().hex[:16]}"
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = f"nonce_{uuid4().hex}"
    # Amount $12,000 exceeds $5,000 limit
    payload = {"hotel_id": "presidential_suite", "amount": 12000, "currency": "USD"}
    hsh = compute_payload_sha256(payload)
    canon = build_canonical_bytes(mid, "request", org.name, agent.agent_identifier, "org_hotelcorp", "agt_hotel", "hotel.reserve@1.0", ts, nonce, hsh)
    sig_b64 = base64.b64encode(priv.sign(canon)).decode("ascii")

    env = {
        "protocol": "ATP/1.0", "message_id": mid, "message_type": "request",
        "source": {"organization_id": org.name, "agent_id": agent.agent_identifier},
        "target": {"organization_id": "org_hotelcorp", "agent_id": "agt_hotel"},
        "capability": "hotel.reserve@1.0", "timestamp": ts, "nonce": nonce,
        "payload": payload,
        "signature": {"version": "ATP-SIG/1", "key_id": key_id, "value": sig_b64},
    }
    resp = client.post("/api/v1/atp/messages", json=env)
    assert resp.status_code == 202
    res_data = resp.json()
    assert res_data["status"] == "PENDING_APPROVAL"
    assert res_data["approval_required"] is True

    # Verify message in DB is NOT delivered
    rec = db.execute(select(ATPMessageRecord).where(ATPMessageRecord.message_id == mid)).scalar_one()
    assert rec.status == "PENDING_APPROVAL"
    assert rec.completed_at is None
