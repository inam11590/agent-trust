"""Comprehensive Integration and Security Tests for Step 22: Trust Registry & Verifiable Credentials.

Covers:
1. Test vector conformance (ATC-SIG/1, canonical string, claims SHA-256).
2. Tampering detection (modifying claims invalidates signature).
3. Subject swap detection (presenting another agent's credential rejected).
4. Organization swap detection (presenting another org's credential rejected).
5. Temporal bounds: expired and not-yet-valid credentials rejected.
6. Immediate revocation: revoked credentials immediately fail verification.
7. Key rotation and key compromise: rotated key preserves existing credentials, revoked key invalidates credentials.
8. Sandbox crossing: sandbox credentials rejected in production verification context.
9. End-to-end ATP Gateway integration with credential presentation.
10. Required credential policy enforcement: target policy requiring credentials blocks missing credentials.
11. Core Security Invariant: Valid credential NEVER bypasses authorization/permissions.
12. Core Security Invariant: Valid credential NEVER bypasses organization trust.
13. Core Security Invariant: Valid credential with invalid ATP request signature is rejected.
"""

import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.session import create_database_engine, get_db
from app.main import create_app
from app.models.agent import Agent, AgentStatus
from app.models.agent_signing import AgentSigningKey, AgentSigningKeyStatus
from app.models.agenttrust_protocol import AgentCapability
from app.models.cross_organization_trust import (
    OrganizationTrustRelationship,
    TargetOrganizationPolicy,
    TrustStatus,
)
from app.models.organization import Organization
from app.models.permission import Permission, PermissionStatus
from app.models.trust_registry import (
    AgentCredential,
    CredentialIssuer,
    CredentialStatus,
    IssuerKeyStatus,
    IssuerSigningKey,
    IssuerStatus,
)
from app.models.user import User
from app.services.atc_canonical import (
    ATC_SIGNING_VERSION,
    ATC_VERSION,
    build_atc_canonical_bytes,
    compute_claims_sha256,
)
from app.services.atp_canonical import (
    build_canonical_bytes,
    compute_payload_sha256,
    format_agent_address,
)
from app.services.credential_service import (
    CredentialVerificationError,
    create_credential_issuer,
    issue_agent_credential,
    revoke_agent_credential,
    rotate_issuer_signing_key,
    verify_agent_credential,
)
from app.services.gateway_pipeline import GatewayPipelineError, process_atp_message


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


def _setup_org_and_agent(db: Session, prefix: str = "test"):
    unique = secrets.token_hex(4)
    user = User(
        email=f"user_{prefix}_{unique}@example.com",
        hashed_password="hash",
        full_name=f"{prefix} User",
    )
    db.add(user)
    db.flush()

    org = Organization(
        name=f"Org_{prefix}_{unique}",
        owner_id=user.id,
        is_active=True,
    )
    db.add(org)
    db.flush()

    agent = Agent(
        organization_id=org.id,
        owner_id=user.id,
        name=f"Agent {prefix}",
        agent_identifier=f"agt_{prefix}_{unique}",
        status=AgentStatus.ACTIVE,
    )
    db.add(agent)
    db.flush()

    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")

    fingerprint = hashlib.sha256(pub_bytes).hexdigest()

    signing_key = AgentSigningKey(
        agent_id=agent.id,
        organization_id=org.id,
        key_id=f"key_{unique}",
        algorithm="Ed25519",
        public_key=pub_b64,
        fingerprint=fingerprint,
        status=AgentSigningKeyStatus.ACTIVE,
        activated_at=datetime.now(timezone.utc),
    )
    db.add(signing_key)
    db.commit()
    db.refresh(org)
    db.refresh(agent)
    db.refresh(signing_key)
    return org, agent, signing_key, priv


def test_protocol_test_vector_conformance():
    """Verify that Python implementation strictly matches the cross-language test vectors."""
    vectors_path = Path(__file__).resolve().parents[2] / "tests" / "credentials" / "v1" / "test_vectors.json"
    assert vectors_path.exists(), f"Test vector file missing at {vectors_path}"
    vector = json.loads(vectors_path.read_text(encoding="utf-8"))

    cred = vector["credential"]
    subj = cred["subject"]

    # 1. Claims SHA256
    computed_claims_sha = compute_claims_sha256(cred["claims"])
    assert computed_claims_sha == vector["claims_sha256"]

    # 2. Canonical Bytes
    canon_bytes = build_atc_canonical_bytes(
        credential_version=cred["credential_version"],
        credential_id=cred["credential_id"],
        issuer_id=cred["issuer"],
        subject_org_id=subj["organization_id"],
        subject_agent_id=subj["agent_id"],
        credential_type=cred["credential_type"],
        issued_at=cred["issued_at"],
        not_before=cred.get("not_before"),
        expires_at=cred["expires_at"],
        environment=cred["environment"],
        claims_sha256=computed_claims_sha,
    )
    assert canon_bytes.decode("ascii") == vector["canonical_ascii"]


def test_tampering_detection(db: Session):
    """Test requirement 69: changing claims invalidates signature with CREDENTIAL_SIGNATURE_INVALID."""
    org, agent, _, _ = _setup_org_and_agent(db, prefix="tamper")
    issuer, _ = create_credential_issuer(db, org.id, f"{org.name} Issuer")

    # Register capability first
    cap = AgentCapability(
        organization_id=org.id,
        agent_id=agent.id,
        name="hotel.search",
        version="1.0",
        is_active=True,
    )
    db.add(cap)
    db.commit()

    cred = issue_agent_credential(
        db=db,
        issuer_id_str=issuer.issuer_id,
        subject_agent_id_str=agent.agent_identifier,
        credential_type="AgentCapabilityCredential",
        claims={"capabilities": ["hotel.search@1.0"]},
    )

    # Tamper with the claims: change hotel.search to hotel.reserve
    tampered_cred = json.loads(json.dumps(cred))
    tampered_cred["claims"]["capabilities"] = ["hotel.reserve@1.0"]

    with pytest.raises(CredentialVerificationError) as exc_info:
        verify_agent_credential(db=db, credential=tampered_cred)

    assert exc_info.value.code == "CREDENTIAL_SIGNATURE_INVALID"


def test_subject_swap_detection(db: Session):
    """Test requirement 70: presenting credential with wrong agent is rejected with CREDENTIAL_SUBJECT_INVALID."""
    org, hotel_agent, hotel_key, hotel_priv = _setup_org_and_agent(db, prefix="hotel")
    _, payment_agent, payment_key, payment_priv = _setup_org_and_agent(db, prefix="pay")
    issuer, _ = create_credential_issuer(db, org.id, f"{org.name} Issuer")

    cred = issue_agent_credential(
        db=db,
        issuer_id_str=issuer.issuer_id,
        subject_agent_id_str=hotel_agent.agent_identifier,
        credential_type="AgentIdentityCredential",
    )

    # Present hotel_agent credential in payment_agent request
    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = f"nonce_{secrets.token_hex(16)}"
    msg_id = f"msg_{secrets.token_hex(8)}"
    payload = {"query": "test"}
    sha = compute_payload_sha256(payload)

    canon = build_canonical_bytes(
        message_id=msg_id,
        message_type="request",
        source_org_id=org.name,
        source_agent_id=payment_agent.agent_identifier,
        target_org_id="hotelcorp",
        target_agent_id="agt_hotel",
        capability="hotel.search@1.0",
        timestamp=now_ts,
        nonce=nonce,
        payload_sha256=sha,
    )
    sig = base64.b64encode(payment_priv.sign(canon)).decode("ascii")

    envelope = {
        "protocol": "ATP/1.0",
        "message_id": msg_id,
        "message_type": "request",
        "source": {
            "organization_id": org.name,
            "agent_id": payment_agent.agent_identifier,
            "address": format_agent_address(org.name, payment_agent.agent_identifier),
        },
        "target": {
            "organization_id": "hotelcorp",
            "agent_id": "agt_hotel",
            "address": "atp://org_hotelcorp/agt_hotel",
        },
        "capability": "hotel.search@1.0",
        "timestamp": now_ts,
        "nonce": nonce,
        "payload": payload,
        "signature": {
            "version": "ATP-SIG/1",
            "key_id": payment_key.key_id,
            "value": sig,
        },
        "credentials": [cred],  # Mismatch: belongs to hotel_agent!
    }

    with pytest.raises(GatewayPipelineError) as exc_info:
        process_atp_message(db, envelope, allow_private_ips=True, enforce_https=False)

    assert exc_info.value.code == "CREDENTIAL_SUBJECT_INVALID"


def test_organization_swap_detection(db: Session):
    """Test requirement 71: presenting credential across org boundaries fails with CREDENTIAL_CLAIM_INVALID."""
    org_a, agent_a, _, _ = _setup_org_and_agent(db, prefix="orga")
    org_b, agent_b, _, _ = _setup_org_and_agent(db, prefix="orgb")
    issuer_a, _ = create_credential_issuer(db, org_a.id, f"{org_a.name} Issuer")

    # Issuer A cannot issue credential for agent in Org B
    with pytest.raises(CredentialVerificationError) as exc_info:
        issue_agent_credential(
            db=db,
            issuer_id_str=issuer_a.issuer_id,
            subject_agent_id_str=agent_b.agent_identifier,
            credential_type="AgentIdentityCredential",
        )

    assert exc_info.value.code == "CREDENTIAL_CLAIM_INVALID"


def test_temporal_bounds_expired_and_not_yet_valid(db: Session):
    """Test requirements 72 & 73: expired and not yet valid credentials rejected."""
    org, agent, _, _ = _setup_org_and_agent(db, prefix="temporal")
    issuer, _ = create_credential_issuer(db, org.id, f"{org.name} Issuer")

    # 1. Expired credential
    cred = issue_agent_credential(
        db=db,
        issuer_id_str=issuer.issuer_id,
        subject_agent_id_str=agent.agent_identifier,
        credential_type="AgentIdentityCredential",
    )
    # Manually expire in DB
    db_cred = db.execute(select(AgentCredential).where(AgentCredential.credential_id == cred["credential_id"])).scalar_one()
    db_cred.expires_at = datetime.now(timezone.utc) - timedelta(days=2)
    db.commit()

    # Expire in envelope as well
    cred_expired = json.loads(json.dumps(cred))
    cred_expired["expires_at"] = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

    with pytest.raises(CredentialVerificationError) as exc_info:
        verify_agent_credential(db=db, credential=cred_expired)
    assert exc_info.value.code == "CREDENTIAL_EXPIRED"

    # 2. Not yet valid credential
    cred_future = json.loads(json.dumps(cred))
    cred_future["not_before"] = (datetime.now(timezone.utc) + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with pytest.raises(CredentialVerificationError) as exc_info:
        verify_agent_credential(db=db, credential=cred_future)
    assert exc_info.value.code == "CREDENTIAL_NOT_YET_VALID"


def test_immediate_revocation(db: Session):
    """Test requirement 74: credential revocation immediately fails verification with CREDENTIAL_REVOKED."""
    org, agent, _, _ = _setup_org_and_agent(db, prefix="revoke")
    issuer, _ = create_credential_issuer(db, org.id, f"{org.name} Issuer")

    cred = issue_agent_credential(
        db=db,
        issuer_id_str=issuer.issuer_id,
        subject_agent_id_str=agent.agent_identifier,
        credential_type="AgentIdentityCredential",
    )

    # Pre-check: valid
    ver = verify_agent_credential(db=db, credential=cred)
    assert ver["verified"] is True

    # Revoke
    revoke_agent_credential(db=db, credential_id=cred["credential_id"], reason_code="KEY_COMPROMISED")

    # Post-check: fails
    with pytest.raises(CredentialVerificationError) as exc_info:
        verify_agent_credential(db=db, credential=cred)
    assert exc_info.value.code == "CREDENTIAL_REVOKED"


def test_issuer_key_rotation_and_revocation(db: Session):
    """Test requirements 75 & 28: key rotation preserves existing creds; revoked key invalidates creds."""
    org, agent, _, _ = _setup_org_and_agent(db, prefix="keyrot")
    issuer, orig_key = create_credential_issuer(db, org.id, f"{org.name} Issuer")

    cred = issue_agent_credential(
        db=db,
        issuer_id_str=issuer.issuer_id,
        subject_agent_id_str=agent.agent_identifier,
        credential_type="AgentIdentityCredential",
    )

    # 1. Rotate key (old key is ROTATED, not revoked)
    new_key = rotate_issuer_signing_key(db=db, issuer_id=issuer.issuer_id, revoke_old_key=False)
    assert new_key.key_id != orig_key.key_id

    # Existing credential remains valid
    ver = verify_agent_credential(db=db, credential=cred)
    assert ver["verified"] is True

    # 2. Revoke original key (simulating key compromise)
    orig_key_db = db.execute(select(IssuerSigningKey).where(IssuerSigningKey.key_id == orig_key.key_id)).scalar_one()
    orig_key_db.status = IssuerKeyStatus.REVOKED.value
    db.commit()

    with pytest.raises(CredentialVerificationError) as exc_info:
        verify_agent_credential(db=db, credential=cred)
    assert exc_info.value.code == "CREDENTIAL_SIGNING_KEY_REVOKED"


def test_sandbox_crossing(db: Session):
    """Test requirement 76: sandbox credentials rejected in production context."""
    org, agent, _, _ = _setup_org_and_agent(db, prefix="sandbox")
    issuer, _ = create_credential_issuer(db, org.id, f"{org.name} Issuer")

    cred = issue_agent_credential(
        db=db,
        issuer_id_str=issuer.issuer_id,
        subject_agent_id_str=agent.agent_identifier,
        credential_type="AgentIdentityCredential",
        environment="sandbox",
    )

    with pytest.raises(CredentialVerificationError) as exc_info:
        verify_agent_credential(db=db, credential=cred, expected_environment="production")

    assert exc_info.value.code == "SANDBOX_CREDENTIAL_IN_PRODUCTION"


def test_credential_with_atp_gateway(db: Session):
    """Test requirement 77: valid credential presented in ATP message passes Gateway routing."""
    org, agent, key, priv = _setup_org_and_agent(db, prefix="atp_cred")
    issuer, _ = create_credential_issuer(db, org.id, f"{org.name} Issuer")

    cred = issue_agent_credential(
        db=db,
        issuer_id_str=issuer.issuer_id,
        subject_agent_id_str=agent.agent_identifier,
        credential_type="AgentIdentityCredential",
    )

    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = f"nonce_{secrets.token_hex(16)}"
    msg_id = f"msg_{secrets.token_hex(8)}"
    payload = {"hotel_id": "grand_hyatt_sf", "nights": 2}
    sha = compute_payload_sha256(payload)

    canon = build_canonical_bytes(
        message_id=msg_id,
        message_type="request",
        source_org_id=org.name,
        source_agent_id=agent.agent_identifier,
        target_org_id="org_hotelcorp",
        target_agent_id="agt_hotel",
        capability="hotel.reserve@1.0",
        timestamp=now_ts,
        nonce=nonce,
        payload_sha256=sha,
    )
    sig = base64.b64encode(priv.sign(canon)).decode("ascii")

    envelope = {
        "protocol": "ATP/1.0",
        "message_id": msg_id,
        "message_type": "request",
        "source": {
            "organization_id": org.name,
            "agent_id": agent.agent_identifier,
            "address": format_agent_address(org.name, agent.agent_identifier),
        },
        "target": {
            "organization_id": "org_hotelcorp",
            "agent_id": "agt_hotel",
            "address": "atp://org_hotelcorp/agt_hotel",
        },
        "capability": "hotel.reserve@1.0",
        "timestamp": now_ts,
        "nonce": nonce,
        "payload": payload,
        "signature": {
            "version": "ATP-SIG/1",
            "key_id": key.key_id,
            "value": sig,
        },
        "credentials": [cred],
    }

    result = process_atp_message(db, envelope, allow_private_ips=True, enforce_https=False)
    assert result["status"] == "DELIVERED"


def test_missing_required_credential(db: Session):
    """Test requirement 78: target policy requiring AgentIdentityCredential rejects requests without it."""
    src_org, src_agent, src_key, src_priv = _setup_org_and_agent(db, prefix="req_src")
    dst_org, dst_agent, _, _ = _setup_org_and_agent(db, prefix="req_dst")

    # Set required_credential_types on target organization policy
    dst_policy = TargetOrganizationPolicy(
        organization_id=dst_org.id,
        allowed_actions=["book"],
        allowed_resources=["*"],
        required_credential_types=["AgentIdentityCredential"],
    )
    db.add(dst_policy)
    db.commit()

    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = f"nonce_{secrets.token_hex(16)}"
    msg_id = f"msg_{secrets.token_hex(8)}"
    payload = {"test": 1}
    sha = compute_payload_sha256(payload)

    canon = build_canonical_bytes(
        message_id=msg_id,
        message_type="request",
        source_org_id=src_org.name,
        source_agent_id=src_agent.agent_identifier,
        target_org_id=dst_org.name,
        target_agent_id=dst_agent.agent_identifier,
        capability="test.action@1.0",
        timestamp=now_ts,
        nonce=nonce,
        payload_sha256=sha,
    )
    sig = base64.b64encode(src_priv.sign(canon)).decode("ascii")

    envelope = {
        "protocol": "ATP/1.0",
        "message_id": msg_id,
        "message_type": "request",
        "source": {
            "organization_id": src_org.name,
            "agent_id": src_agent.agent_identifier,
            "address": format_agent_address(src_org.name, src_agent.agent_identifier),
        },
        "target": {
            "organization_id": dst_org.name,
            "agent_id": dst_agent.agent_identifier,
            "address": format_agent_address(dst_org.name, dst_agent.agent_identifier),
        },
        "capability": "test.action@1.0",
        "timestamp": now_ts,
        "nonce": nonce,
        "payload": payload,
        "signature": {
            "version": "ATP-SIG/1",
            "key_id": src_key.key_id,
            "value": sig,
        },
        "credentials": [],  # Missing required credential!
    }

    with pytest.raises(GatewayPipelineError) as exc_info:
        process_atp_message(db, envelope, allow_private_ips=True, enforce_https=False)

    assert exc_info.value.code == "REQUIRED_CREDENTIAL_MISSING"


def test_valid_credential_but_no_permission(db: Session):
    """Test requirement 79: valid credential NEVER bypasses authorization."""
    org, agent, key, priv = _setup_org_and_agent(db, prefix="perm_denied")
    issuer, _ = create_credential_issuer(db, org.id, f"{org.name} Issuer")

    cred = issue_agent_credential(
        db=db,
        issuer_id_str=issuer.issuer_id,
        subject_agent_id_str=agent.agent_identifier,
        credential_type="AgentIdentityCredential",
    )

    # Request high-risk administrative capability: triggers multi-party approval hold
    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = f"nonce_{secrets.token_hex(16)}"
    msg_id = f"msg_{secrets.token_hex(8)}"
    payload = {"action": "delete_all"}
    sha = compute_payload_sha256(payload)

    canon = build_canonical_bytes(
        message_id=msg_id,
        message_type="request",
        source_org_id=org.name,
        source_agent_id=agent.agent_identifier,
        target_org_id="org_hotelcorp",
        target_agent_id="agt_hotel",
        capability="system.delete",
        timestamp=now_ts,
        nonce=nonce,
        payload_sha256=sha,
    )
    sig = base64.b64encode(priv.sign(canon)).decode("ascii")

    envelope = {
        "protocol": "ATP/1.0",
        "message_id": msg_id,
        "message_type": "request",
        "source": {
            "organization_id": org.name,
            "agent_id": agent.agent_identifier,
            "address": format_agent_address(org.name, agent.agent_identifier),
        },
        "target": {
            "organization_id": "org_hotelcorp",
            "agent_id": "agt_hotel",
            "address": "atp://org_hotelcorp/agt_hotel",
        },
        "capability": "system.delete",
        "timestamp": now_ts,
        "nonce": nonce,
        "payload": payload,
        "signature": {
            "version": "ATP-SIG/1",
            "key_id": key.key_id,
            "value": sig,
        },
        "credentials": [cred],
    }

    res = process_atp_message(db, envelope, allow_private_ips=True, enforce_https=False)
    # Must be on hold: credential did NOT bypass approval
    assert res["status"] == "PENDING_APPROVAL"
    assert res["approval_required"] is True


def test_valid_credential_plus_revoked_trust(db: Session):
    """Test requirement 80: valid credential NEVER bypasses organization trust."""
    src_org, src_agent, src_key, src_priv = _setup_org_and_agent(db, prefix="trust_src")
    dst_org, dst_agent, _, _ = _setup_org_and_agent(db, prefix="trust_dst")
    issuer, _ = create_credential_issuer(db, src_org.id, f"{src_org.name} Issuer")

    cred = issue_agent_credential(
        db=db,
        issuer_id_str=issuer.issuer_id,
        subject_agent_id_str=src_agent.agent_identifier,
        credential_type="AgentIdentityCredential",
    )

    # Set revoked trust relationship
    trust = OrganizationTrustRelationship(
        source_organization_id=src_org.id,
        target_organization_id=dst_org.id,
        created_by_user_id=src_org.owner_id,
        status=TrustStatus.REVOKED,
    )
    db.add(trust)
    db.commit()

    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = f"nonce_{secrets.token_hex(16)}"
    msg_id = f"msg_{secrets.token_hex(8)}"
    payload = {"data": 123}
    sha = compute_payload_sha256(payload)

    canon = build_canonical_bytes(
        message_id=msg_id,
        message_type="request",
        source_org_id=src_org.name,
        source_agent_id=src_agent.agent_identifier,
        target_org_id=dst_org.name,
        target_agent_id=dst_agent.agent_identifier,
        capability="data.read@1.0",
        timestamp=now_ts,
        nonce=nonce,
        payload_sha256=sha,
    )
    sig = base64.b64encode(src_priv.sign(canon)).decode("ascii")

    envelope = {
        "protocol": "ATP/1.0",
        "message_id": msg_id,
        "message_type": "request",
        "source": {
            "organization_id": src_org.name,
            "agent_id": src_agent.agent_identifier,
            "address": format_agent_address(src_org.name, src_agent.agent_identifier),
        },
        "target": {
            "organization_id": dst_org.name,
            "agent_id": dst_agent.agent_identifier,
            "address": format_agent_address(dst_org.name, dst_agent.agent_identifier),
        },
        "capability": "data.read@1.0",
        "timestamp": now_ts,
        "nonce": nonce,
        "payload": payload,
        "signature": {
            "version": "ATP-SIG/1",
            "key_id": src_key.key_id,
            "value": sig,
        },
        "credentials": [cred],
    }

    with pytest.raises(GatewayPipelineError) as exc_info:
        process_atp_message(db, envelope, allow_private_ips=True, enforce_https=False)

    assert exc_info.value.code == "CROSS_ORG_TRUST_REQUIRED"


def test_valid_credential_plus_invalid_atp_signature(db: Session):
    """Test requirement 81: valid credential cannot substitute for valid ATP agent request signature."""
    org, agent, key, _ = _setup_org_and_agent(db, prefix="bad_sig")
    issuer, _ = create_credential_issuer(db, org.id, f"{org.name} Issuer")

    cred = issue_agent_credential(
        db=db,
        issuer_id_str=issuer.issuer_id,
        subject_agent_id_str=agent.agent_identifier,
        credential_type="AgentIdentityCredential",
    )

    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = f"nonce_{secrets.token_hex(16)}"
    payload = {"test": "val"}

    envelope = {
        "protocol": "ATP/1.0",
        "message_id": f"msg_{secrets.token_hex(8)}",
        "message_type": "request",
        "source": {
            "organization_id": org.name,
            "agent_id": agent.agent_identifier,
            "address": format_agent_address(org.name, agent.agent_identifier),
        },
        "target": {
            "organization_id": "org_hotelcorp",
            "agent_id": "agt_hotel",
            "address": "atp://org_hotelcorp/agt_hotel",
        },
        "capability": "hotel.search@1.0",
        "timestamp": now_ts,
        "nonce": nonce,
        "payload": payload,
        "signature": {
            "version": "ATP-SIG/1",
            "key_id": key.key_id,
            "value": base64.b64encode(b"invalid_signature_bytes_32_bytes!").decode("ascii"),
        },
        "credentials": [cred],
    }

    with pytest.raises(GatewayPipelineError) as exc_info:
        process_atp_message(db, envelope, allow_private_ips=True, enforce_https=False)

    assert exc_info.value.code == "INVALID_SIGNATURE"
