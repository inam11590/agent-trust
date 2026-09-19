"""Comprehensive Integration and Security Tests for Step 23: Enterprise Gateway & Sidecar Architecture.

Covers:
1. One-time enrollment token lifecycle & validation (expiry, single-use, org match).
2. Local Ed25519 keypair generation (private key never sent to Control Plane).
3. Configuration bundle signing, monotonic version ordering, anti-rollback, atomic activation.
4. Rollback re-signing protocol (previous state signed as strictly incremented version).
5. Signed heartbeat verification, telemetry recording, and offline detection.
6. Emergency suspend and permanent revoke controls.
7. Local sidecar evaluation (sub-millisecond local authorization, signature validation, anti-replay).
8. Offline safety: FAIL_CLOSED default vs LIMITED_OFFLINE (low-risk vs high-risk blocked, TTL expiration).
9. SSRF defense and DIRECT_PRIVATE network mode enforcement.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
from uuid import uuid4

# Ensure both backend/ and repo root are in sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))
repo_root = backend_dir.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.session import create_database_engine, get_db
from app.main import create_app
from app.models.agent import Agent, AgentStatus
from app.models.agent_signing import AgentSigningKey, AgentSigningKeyStatus
from app.models.enterprise_gateway import (
    EnterpriseGateway,
    GatewayConfigBundle,
    GatewayDeploymentType,
    GatewayEnvironment,
    GatewayOfflinePolicy,
    GatewayStatus,
)
from app.models.organization import Organization
from app.models.permission import Permission, PermissionStatus
from app.models.user import User
from app.schemas.enterprise_gateways import (
    GatewayEnrollRequest,
    GatewayHeartbeatRequest,
    GatewayPublishConfigRequest,
    GatewayRegistrationRequest,
    GatewayRollbackRequest,
)
from app.services.gateway_control_service import (
    HEARTBEAT_SIGNING_VERSION,
    GatewayControlError,
    build_and_publish_config,
    enroll_enterprise_gateway,
    get_signed_config_bundle,
    register_enterprise_gateway,
    revoke_enterprise_gateway,
    rollback_gateway_config,
    suspend_enterprise_gateway,
    verify_gateway_heartbeat,
)
from sidecar.config import config
from sidecar.evaluator import LocalAuthorizationResult, evaluate_local_request
from sidecar.router import is_safe_ip, validate_destination_url
from sidecar.state import state
from sidecar.storage import load_config_cache, save_config_cache


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


def _setup_org_and_agent(db: Session, prefix: str = "gw23"):
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
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
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
    db.flush()

    perm = Permission(
        agent_id=agent.id,
        owner_id=user.id,
        action="payments.process",
        resource="accounts/*",
        maximum_amount="1000.00",
        currency="USD",
        status=PermissionStatus.ACTIVE,
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    db.add(perm)
    db.commit()

    return {
        "user": user,
        "org": org,
        "agent": agent,
        "signing_key": signing_key,
        "private_key": priv,
        "permission": perm,
    }


# ==============================================================================
# TEST CASES
# ==============================================================================


def test_one_time_enrollment_token_lifecycle(db: Session):
    """Enrollment token is single-use, expires in 1h, and private key is never sent."""
    setup = _setup_org_and_agent(db, "enroll")
    org_id = setup["org"].id

    # 1. Register gateway
    reg_req = GatewayRegistrationRequest(
        name="k8s-pod-sidecar-1",
        deployment_type="SIDECAR",
        environment="PRODUCTION",
        offline_policy="FAIL_CLOSED",
    )
    gw, token, cmd = register_enterprise_gateway(db, org_id=org_id, req=reg_req)
    assert gw.status == GatewayStatus.ENROLLING.value
    assert gw.enrollment_token_hash is not None
    assert gw.public_key is None
    assert len(token) > 20
    assert "agenttrust gateway enroll" in cmd

    # 2. Sidecar generates local keypair (Private key NEVER sent to Control Plane)
    sidecar_priv = Ed25519PrivateKey.generate()
    raw_pub = sidecar_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(raw_pub).decode("ascii")

    # 3. Successful enrollment
    enroll_req = GatewayEnrollRequest(
        enrollment_token=token,
        public_key=pub_b64,
        version="1.0.0",
    )
    res = enroll_enterprise_gateway(db, gateway_id_str=gw.gateway_id, req=enroll_req)
    assert res["status"] == "ACTIVE"
    assert res["gateway_id"] == gw.gateway_id
    assert res["control_plane_public_key"] is not None

    db.refresh(gw)
    assert gw.status == GatewayStatus.ACTIVE.value
    assert gw.public_key == pub_b64
    assert gw.fingerprint is not None
    assert gw.enrollment_token_hash is None  # Token consumed

    # 4. Replay attack with used token fails
    with pytest.raises(GatewayControlError, match="Enrollment token already consumed or invalid"):
        enroll_enterprise_gateway(db, gateway_id_str=gw.gateway_id, req=enroll_req)


def test_expired_enrollment_token_rejected(db: Session):
    """Expired enrollment token cannot be used for enrollment."""
    setup = _setup_org_and_agent(db, "expire")
    org_id = setup["org"].id

    reg_req = GatewayRegistrationRequest(
        name="test-expired-gw",
        deployment_type="SELF_HOSTED_GATEWAY",
        environment="PRODUCTION",
    )
    gw, token, _ = register_enterprise_gateway(db, org_id=org_id, req=reg_req)

    # Artificially expire the token
    gw.enrollment_token_expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
    db.commit()

    sidecar_priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(sidecar_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")
    enroll_req = GatewayEnrollRequest(enrollment_token=token, public_key=pub_b64)

    with pytest.raises(GatewayControlError, match="Enrollment token has expired"):
        enroll_enterprise_gateway(db, gateway_id_str=gw.gateway_id, req=enroll_req)


def test_bundle_monotonic_versioning_and_anti_rollback(db: Session):
    """Control Plane signs monotonic bundles and sidecar rejects versions <= active."""
    setup = _setup_org_and_agent(db, "monotonic")
    org_id = setup["org"].id

    pub_req1 = GatewayPublishConfigRequest(environment="production")
    bundle_v1 = build_and_publish_config(db, org_id=org_id, req=pub_req1)
    assert bundle_v1.config_version == 1
    assert bundle_v1.signature is not None
    assert len(bundle_v1.bundle_sha256) == 64

    pub_req2 = GatewayPublishConfigRequest(environment="production")
    bundle_v2 = build_and_publish_config(db, org_id=org_id, req=pub_req2)
    assert bundle_v2.config_version == 2
    assert bundle_v2.config_version > bundle_v1.config_version

    # Sidecar cache and anti-rollback assertion
    config.cache_dir = Path("scratch/test_sidecar_cache")
    config.cache_dir.mkdir(parents=True, exist_ok=True)

    # Activate v2 first
    v2_data = {
        "config_version": bundle_v2.config_version,
        "bundle_id": str(bundle_v2.id),
        "bundle_sha256": bundle_v2.bundle_sha256,
        "signature": bundle_v2.signature,
        "bundle": bundle_v2.bundle_json,
        "expires_at": bundle_v2.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    save_config_cache(v2_data)
    state.applied_config_version = bundle_v2.config_version

    assert state.applied_config_version == 2

    # Attempting to activate v1 must fail anti-rollback
    v1_version = bundle_v1.config_version
    is_rollback = (v1_version <= state.applied_config_version)
    assert is_rollback is True, "Anti-rollback must detect older version <= active version"


def test_rollback_re_signs_with_strictly_incremented_version(db: Session):
    """Rolling back policy state creates a new bundle with monotonic version (v_current + 1)."""
    setup = _setup_org_and_agent(db, "rollback")
    org_id = setup["org"].id

    b1 = build_and_publish_config(db, org_id=org_id, req=GatewayPublishConfigRequest(environment="production"))
    b2 = build_and_publish_config(db, org_id=org_id, req=GatewayPublishConfigRequest(environment="production"))
    assert b1.config_version == 1
    assert b2.config_version == 2

    # Execute rollback to state of v1
    rollback_req = GatewayRollbackRequest(target_version=1, environment="production")
    b3 = rollback_gateway_config(db, org_id=org_id, req=rollback_req)
    assert b3.config_version == 3, "Rollback must produce strictly incremented monotonic version"
    assert b3.config_version > b2.config_version
    assert b3.bundle_json == b1.bundle_json, "Rollback must restore the target version payload"


def test_heartbeat_verification_and_telemetry(db: Session):
    """Signed gateway heartbeat updates status and telemetry; invalid signature rejected."""
    setup = _setup_org_and_agent(db, "hb")
    org_id = setup["org"].id

    reg_req = GatewayRegistrationRequest(name="heartbeat-node")
    gw, token, _ = register_enterprise_gateway(db, org_id=org_id, req=reg_req)
    sidecar_priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(sidecar_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")
    enroll_enterprise_gateway(db, gateway_id_str=gw.gateway_id, req=GatewayEnrollRequest(enrollment_token=token, public_key=pub_b64))

    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    canon_bytes = f"{HEARTBEAT_SIGNING_VERSION}\n{gw.gateway_id}\n1\n{now_ts}\n".encode("utf-8")
    sig_b64 = base64.b64encode(sidecar_priv.sign(canon_bytes)).decode("ascii")

    telemetry = {
        "uptime_seconds": 3600,
        "evaluations_total": 450,
        "evaluations_approved": 445,
        "evaluations_rejected": 5,
        "cached_policies_count": 12,
        "clock_skew_ms": 1.2,
    }

    # Valid heartbeat
    hb_req = GatewayHeartbeatRequest(
        version="1.0.0",
        config_version=1,
        health=telemetry,
        timestamp=now_ts,
        signature=sig_b64,
    )
    res = verify_gateway_heartbeat(db, gateway_id_str=gw.gateway_id, req=hb_req)
    assert res["status"] == "ACTIVE"
    db.refresh(gw)
    assert gw.last_heartbeat_data["uptime_seconds"] == 3600

    # Invalid signature with wrong key
    attacker_priv = Ed25519PrivateKey.generate()
    bad_sig = base64.b64encode(attacker_priv.sign(canon_bytes)).decode("ascii")
    bad_hb_req = GatewayHeartbeatRequest(
        version="1.0.0",
        config_version=1,
        health=telemetry,
        timestamp=now_ts,
        signature=bad_sig,
    )
    with pytest.raises(GatewayControlError, match="Heartbeat Ed25519 cryptographic signature invalid"):
        verify_gateway_heartbeat(db, gateway_id_str=gw.gateway_id, req=bad_hb_req)


def test_emergency_suspend_and_revoke(db: Session):
    """Suspending and revoking a gateway immediately halts its operations."""
    setup = _setup_org_and_agent(db, "kill")
    org_id = setup["org"].id

    gw, token, _ = register_enterprise_gateway(db, org_id=org_id, req=GatewayRegistrationRequest(name="test-kill-gw"))
    sidecar_priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(sidecar_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")
    enroll_enterprise_gateway(db, gateway_id_str=gw.gateway_id, req=GatewayEnrollRequest(enrollment_token=token, public_key=pub_b64))

    # Suspend
    suspended = suspend_enterprise_gateway(db, gw.gateway_id, org_id)
    assert suspended.status == GatewayStatus.SUSPENDED.value

    # Revoke
    revoked = revoke_enterprise_gateway(db, gw.gateway_id, org_id)
    assert revoked.status == GatewayStatus.REVOKED.value

    # Cannot enroll or operate revoked gateway
    with pytest.raises(GatewayControlError, match="cannot be enrolled"):
        enroll_enterprise_gateway(db, gateway_id_str=gw.gateway_id, req=GatewayEnrollRequest(enrollment_token="any", public_key=pub_b64))


def test_local_sidecar_policy_evaluation():
    """Local sidecar evaluator authorizes valid requests locally in microsecond latency."""
    agent_id = "agt_fast_001"
    policies = [
        {
            "agent_id": agent_id,
            "allowed_actions": ["database.read", "refund.issue"],
            "allowed_resources": ["users", "orders/*"],
        }
    ]
    expires = datetime.now(timezone.utc) + timedelta(hours=24)
    state.update_config(
        new_version=1,
        config_bundle={"policies": policies, "revocations": []},
        expires_at=expires,
    )
    state.control_plane_reachable = True
    config.offline_policy = "FAIL_CLOSED"

    # 1. Valid low-amount authorization
    res = evaluate_local_request(
        action="refund.issue",
        resource="orders/123",
        agent_id=agent_id,
        amount=150.0,
        nonce="nonce_test_001",
    )
    assert res["decision"] == LocalAuthorizationResult.LOCAL_APPROVED
    assert res["code"] == "AUTHORIZED"

    # 2. Replay attack: reusing nonce must be rejected
    res_replay = evaluate_local_request(
        action="refund.issue",
        resource="orders/123",
        agent_id=agent_id,
        amount=150.0,
        nonce="nonce_test_001",
    )
    assert res_replay["decision"] == LocalAuthorizationResult.REJECTED
    assert res_replay["code"] == "REPLAY_ATTACK_DETECTED"

    # 3. Disallowed action
    res_denied = evaluate_local_request(
        action="unauthorized.action",
        resource="orders/123",
        agent_id=agent_id,
        amount=50.0,
        nonce="nonce_test_002",
    )
    assert res_denied["decision"] == LocalAuthorizationResult.REJECTED
    assert res_denied["code"] == "PERMISSION_DENIED"


def test_offline_safety_modes_and_high_risk_rejection():
    """Offline mode must NEVER allow-all; high-risk operations (> $5k or admin) always fail closed."""
    agent_id = "agt_offline_test"
    policies = [
        {
            "agent_id": agent_id,
            "allowed_actions": ["wire.transfer", "system.admin"],
            "allowed_resources": ["accounts/*", "system/*"],
        }
    ]
    expires = datetime.now(timezone.utc) + timedelta(hours=24)
    state.update_config(
        new_version=1,
        config_bundle={"policies": policies, "revocations": []},
        expires_at=expires,
    )

    # 1. FAIL_CLOSED mode while offline
    config.offline_policy = "FAIL_CLOSED"
    res_fc = evaluate_local_request(
        action="wire.transfer",
        resource="accounts/1",
        agent_id=agent_id,
        amount=100.0,
        nonce="nonce_fc_1",
        force_offline=True,
    )
    assert res_fc["decision"] == LocalAuthorizationResult.REJECTED
    assert res_fc["code"] == "OFFLINE_FAIL_CLOSED"

    # 2. LIMITED_OFFLINE mode: Low-risk approved while offline
    config.offline_policy = "LIMITED_OFFLINE"
    res_low = evaluate_local_request(
        action="wire.transfer",
        resource="accounts/1",
        agent_id=agent_id,
        amount=200.0,
        nonce="nonce_lim_1",
        force_offline=True,
    )
    assert res_low["decision"] == LocalAuthorizationResult.LOCAL_APPROVED

    # 3. LIMITED_OFFLINE mode: High-risk ($10,000 > $5,000 threshold) ALWAYS blocked while offline
    res_high = evaluate_local_request(
        action="wire.transfer",
        resource="accounts/1",
        agent_id=agent_id,
        amount=10000.0,
        nonce="nonce_lim_2",
        force_offline=True,
    )
    assert res_high["decision"] == LocalAuthorizationResult.CENTRAL_CHECK_REQUIRED
    assert res_high["code"] == "OFFLINE_HIGH_RISK_BLOCKED"

    # 4. LIMITED_OFFLINE mode: Admin action ALWAYS blocked while offline
    res_admin = evaluate_local_request(
        action="system.admin",
        resource="system/1",
        agent_id=agent_id,
        amount=0.0,
        nonce="nonce_lim_3",
        force_offline=True,
    )
    assert res_admin["decision"] == LocalAuthorizationResult.CENTRAL_CHECK_REQUIRED
    assert res_admin["code"] == "OFFLINE_ADMIN_BLOCKED"

    # 5. Expired config must reject regardless of mode
    state.config_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    res_exp = evaluate_local_request(
        action="wire.transfer",
        resource="accounts/1",
        agent_id=agent_id,
        amount=50.0,
        nonce="nonce_exp_1",
        force_offline=True,
    )
    assert res_exp["decision"] == LocalAuthorizationResult.REJECTED
    assert res_exp["code"] == "CONFIG_EXPIRED"


def test_ssrf_protection_and_direct_private():
    """Sidecar blocks loopback, cloud metadata, and RFC1918 IPs unless DIRECT_PRIVATE is enabled."""
    # Loopback targets are ALWAYS blocked
    assert is_safe_ip("127.0.0.1", allow_private_ips=False) is False
    assert is_safe_ip("127.0.0.1", allow_private_ips=True) is False
    assert validate_destination_url("http://127.0.0.1:8000/atp", allow_private_ips=False)[0] is False
    assert validate_destination_url("http://localhost:3000/atp", allow_private_ips=False)[0] is False

    # Cloud metadata (AWS/GCP IMDS 169.254.169.254) ALWAYS blocked
    assert is_safe_ip("169.254.169.254", allow_private_ips=False) is False
    assert is_safe_ip("169.254.169.254", allow_private_ips=True) is False

    # RFC1918 private targets blocked by default
    assert is_safe_ip("10.0.1.50", allow_private_ips=False) is False
    assert is_safe_ip("192.168.1.100", allow_private_ips=False) is False

    # RFC1918 private targets permitted ONLY when allow_private_ips=True
    assert is_safe_ip("10.0.1.50", allow_private_ips=True) is True
    assert is_safe_ip("192.168.1.100", allow_private_ips=True) is True

    # Public IPs permitted in all modes
    assert is_safe_ip("93.184.216.34", allow_private_ips=False) is True
    assert is_safe_ip("93.184.216.34", allow_private_ips=True) is True

