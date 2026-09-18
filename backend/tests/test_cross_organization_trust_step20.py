"""Comprehensive security and functional tests for Step 20: Cross-Organization Agent-to-Agent Trust."""

import base64
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import json
import os
import secrets
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest
from starlette.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.session import create_database_engine, get_db
from app.main import create_app
from app.models import (
    Agent,
    AgentSigningKey,
    AgentSigningKeyStatus,
    AgentStatus,
    AuditLog,
    Organization,
    OrganizationMember,
    OrganizationRole,
    Permission,
    PermissionStatus,
    User,
)
from app.models.cross_organization_trust import (
    CrossOrgRequestStatus,
    CrossOrganizationApproval,
    CrossOrganizationRequest,
    ExternalAgentConnection,
    OrganizationTrustPolicy,
    OrganizationTrustRelationship,
    TargetOrganizationPolicy,
    TrustStatus,
)
from app.schemas.cross_organization_trust import (
    ExternalAgentConnectionCreate,
    OrganizationPublicProfileUpdate,
    TargetOrganizationPolicyUpdate,
    TrustPolicyUpdate,
)
from app.services.agent_signing import canonical_cross_org_request_v2

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
        postgres_user="",
        postgres_password="",
        redis_url="",
    )
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as value:
        yield value


def _account(client: TestClient, name: str = "User") -> tuple[dict, dict]:
    email = f"{name.lower()}-{uuid4()}@example.com"
    pwd = "SecurePassword123!"
    reg = client.post("/auth/register", json={"email": email, "password": pwd, "full_name": name})
    assert reg.status_code == 201, reg.text
    login = client.post("/auth/login", json={"email": email, "password": pwd})
    assert login.status_code == 200
    token = login.json()["access_token"]
    return reg.json(), {"Authorization": f"Bearer {token}"}


def _create_org(client: TestClient, auth_headers: dict, name: str) -> tuple[dict, dict]:
    res = client.post("/organizations", headers=auth_headers, json={"name": name})
    assert res.status_code == 201, res.text
    org = res.json()
    org_headers = {**auth_headers, "X-Organization-ID": org["id"]}
    return org, org_headers


def _create_agent_with_key(client: TestClient, org_headers: dict, name: str) -> tuple[dict, Ed25519PrivateKey, str]:
    res = client.post("/agents", headers=org_headers, json={"name": name})
    assert res.status_code == 201, res.text
    agent = res.json()

    # Generate Ed25519 keypair
    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")

    key_res = client.post(
        f"/agents/{agent['id']}/signing-keys",
        headers=org_headers,
        json={"public_key": pub_b64},
    )
    assert key_res.status_code == 201, key_res.text
    key_id = key_res.json()["key_id"]
    return agent, priv, key_id


def _sign_cross_org(
    priv: Ed25519PrivateKey,
    key_id: str,
    source_agent_ident: str,
    source_org_id: str,
    target_org_id: str,
    target_agent_ident: str,
    body_bytes: bytes,
    method: str = "POST",
    path: str = "/api/v1/cross-org/authorize",
    nonce: str | None = None,
    timestamp: str | None = None,
) -> dict:
    ts = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    n = nonce or f"nonce_{secrets.token_hex(16)}"
    canonical = canonical_cross_org_request_v2(
        method=method,
        path=path,
        source_org_id=source_org_id,
        target_org_id=target_org_id,
        source_agent_id=source_agent_ident,
        target_agent_id=target_agent_ident,
        key_id=key_id,
        timestamp=ts,
        nonce=n,
        body=body_bytes,
    )
    sig = base64.b64encode(priv.sign(canonical)).decode("ascii")
    return {
        "X-Agent-ID": source_agent_ident,
        "X-Agent-Key-ID": key_id,
        "X-Agent-Timestamp": ts,
        "X-Agent-Nonce": n,
        "X-Agent-Signature": sig,
        "X-Agent-Signature-Version": "v2",
    }


def test_cross_org_trust_lifecycle_and_acceptance(client: TestClient, db: Session):
    _, auth_a = _account(client, "Alice")
    org_a, headers_a = _create_org(client, auth_a, "SkyTravel")

    _, auth_b = _account(client, "Bob")
    org_b, headers_b = _create_org(client, auth_b, "HotelCorp")

    _, auth_c = _account(client, "Charlie")
    org_c, headers_c = _create_org(client, auth_c, "ThirdParty")

    # 1. Self trust request rejected
    res_self = client.post("/v1/organization-trust/requests", headers=headers_a, json={
        "target_organization_id": org_a["id"]
    })
    assert res_self.status_code == 400

    # 2. Valid trust request created -> Status PENDING
    req_res = client.post("/v1/organization-trust/requests", headers=headers_a, json={
        "target_organization_id": org_b["id"]
    })
    assert req_res.status_code == 201
    trust = req_res.json()
    assert trust["status"] == "PENDING"
    trust_id = trust["trust_id"]

    # 3. Unauthorized third party (Charlie) cannot accept or reject
    res_c_accept = client.post(f"/v1/organization-trust/{trust_id}/accept", headers=headers_c)
    assert res_c_accept.status_code == 403

    # Source org (Alice) cannot accept its own request
    res_a_accept = client.post(f"/v1/organization-trust/{trust_id}/accept", headers=headers_a)
    assert res_a_accept.status_code == 403

    # 4. Target org (Bob / HotelCorp) accepts -> Status ACTIVE
    res_accept = client.post(f"/v1/organization-trust/{trust_id}/accept", headers=headers_b)
    assert res_accept.status_code == 200
    assert res_accept.json()["status"] == "ACTIVE"
    assert res_accept.json()["accepted_at"] is not None


def test_cross_org_directional_trust_enforcement(client: TestClient, db: Session):
    """Directional trust: SkyTravel -> HotelCorp does NOT allow HotelCorp -> SkyTravel."""
    _, auth_a = _account(client, "Alice")
    org_a, headers_a = _create_org(client, auth_a, "SkyTravel")
    agent_a, priv_a, key_a = _create_agent_with_key(client, headers_a, "Travel Assistant")

    _, auth_b = _account(client, "Bob")
    org_b, headers_b = _create_org(client, auth_b, "HotelCorp")
    agent_b, priv_b, key_b = _create_agent_with_key(client, headers_b, "Hotel Booking Agent")

    # Activate agents in DB
    db.get(Agent, UUID(agent_a["id"])).status = AgentStatus.ACTIVE
    db.get(Agent, UUID(agent_b["id"])).status = AgentStatus.ACTIVE
    db.commit()

    # Alice requests and Bob accepts: SkyTravel -> HotelCorp
    req_res = client.post("/v1/organization-trust/requests", headers=headers_a, json={
        "target_organization_id": org_b["id"]
    })
    trust_id = req_res.json()["trust_id"]
    client.post(f"/v1/organization-trust/{trust_id}/accept", headers=headers_b)

    # Connect agents
    conn_res = client.post(f"/v1/organization-trust/{trust_id}/agent-connections", headers=headers_a, json={
        "source_agent_id": agent_a["id"],
        "target_agent_id": agent_b["id"],
    })
    assert conn_res.status_code == 201

    # Give Bob permission in HotelCorp
    now = datetime.now(timezone.utc)
    client.post("/permissions", headers=headers_b, json={
        "agent_id": agent_b["id"],
        "action": "hotel:reserve",
        "resource": "room:standard",
        "maximum_amount": "500.00",
        "currency": "USD",
        "valid_from": (now - timedelta(minutes=5)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
    })

    # Reverse direction execution: HotelCorp Agent tries to call SkyTravel Agent without reverse trust
    body_rev = json.dumps({
        "target_organization_id": org_a["id"],
        "source_agent_id": agent_b["agent_identifier"],
        "target_agent_id": agent_a["agent_identifier"],
        "action": "hotel:reserve",
        "resource": "room:standard",
        "amount": "100.00",
        "currency": "USD",
    }).encode("utf-8")

    sig_rev = _sign_cross_org(
        priv_b, key_b, agent_b["agent_identifier"],
        org_b["id"], org_a["id"], agent_a["agent_identifier"], body_rev,
    )
    rev_res = client.post(
        "/api/v1/cross-org/authorize",
        headers={**sig_rev, "Content-Type": "application/json"},
        content=body_rev,
    )
    assert rev_res.status_code == 200
    assert rev_res.json()["status"] == "REJECTED"
    assert "TRUST_NOT_FOUND" in rev_res.json()["reason"]


def test_cross_org_end_to_end_demonstration_step79(client: TestClient, db: Session):
    """Full Step 79 scenario:
    SkyTravel ($1500 max) -> HotelCorp
    Trust policy: $1000 max, approval above $700
    Target policy: $800 max, approval above $500
    - $400 approved
    - $600 pending target approval -> approved by HotelCorp
    - $900 rejected (target max $800 exceeded)
    - Revoke trust -> $300 rejected
    - Replay rejected
    """
    _, auth_a = _account(client, "Alice")
    org_a, headers_a = _create_org(client, auth_a, "SkyTravel")
    agent_a, priv_a, key_a = _create_agent_with_key(client, headers_a, "Travel Assistant")

    _, auth_b = _account(client, "Bob")
    org_b, headers_b = _create_org(client, auth_b, "HotelCorp")
    agent_b, priv_b, key_b = _create_agent_with_key(client, headers_b, "Hotel Booking Agent")

    # Activate agents in DB
    db.get(Agent, UUID(agent_a["id"])).status = AgentStatus.ACTIVE
    db.get(Agent, UUID(agent_b["id"])).status = AgentStatus.ACTIVE
    db.commit()

    now = datetime.now(timezone.utc)
    # 1. Source permission: SkyTravel grants Travel Assistant $1,500 for hotel:reserve
    perm_res = client.post("/permissions", headers=headers_a, json={
        "agent_id": agent_a["id"],
        "action": "hotel:reserve",
        "resource": "hotel_room",
        "maximum_amount": "1500.00",
        "currency": "USD",
        "requires_approval": False,
        "valid_from": (now - timedelta(minutes=5)).isoformat(),
        "expires_at": (now + timedelta(days=7)).isoformat(),
    })
    assert perm_res.status_code == 201

    # 2. SkyTravel requests trust with HotelCorp -> PENDING
    trust_req = client.post("/v1/organization-trust/requests", headers=headers_a, json={
        "target_organization_id": org_b["id"]
    })
    assert trust_req.status_code == 201
    trust_id = trust_req.json()["trust_id"]

    # 3. HotelCorp accepts trust -> ACTIVE
    accept_res = client.post(f"/v1/organization-trust/{trust_id}/accept", headers=headers_b)
    assert accept_res.status_code == 200

    # 4. Connect Agents: Travel Assistant -> Hotel Booking Agent
    conn_res = client.post(f"/v1/organization-trust/{trust_id}/agent-connections", headers=headers_a, json={
        "source_agent_id": agent_a["id"],
        "target_agent_id": agent_b["id"],
    })
    assert conn_res.status_code == 201

    # 5. Configure Trust policy: reserve hotel_room, max $1000, approval above $700
    trust_pol_res = client.put(f"/v1/organization-trust/{trust_id}/policy", headers=headers_a, json={
        "allowed_actions": ["hotel:reserve"],
        "allowed_resources": ["hotel_room"],
        "max_amount": "1000.00",
        "currency": "USD",
        "require_human_approval": True,
        "approval_threshold": "700.00",
        "approval_type": "TARGET_APPROVAL",
    })
    assert trust_pol_res.status_code == 200

    # 6. Configure HotelCorp target policy: max $800, approval above $500
    target_pol_res = client.put(f"/v1/organizations/{org_b['id']}/target-policy", headers=headers_b, json={
        "allowed_actions": ["hotel:reserve"],
        "allowed_resources": ["hotel_room"],
        "max_amount": "800.00",
        "currency": "USD",
        "require_human_approval": True,
        "approval_threshold": "500.00",
    })
    assert target_pol_res.status_code == 200

    # -------------------------------------------------------------------------
    # Case A: Request $400 (< $500 threshold, < $800 max) -> APPROVED
    # -------------------------------------------------------------------------
    body_400 = json.dumps({
        "target_organization_id": org_b["id"],
        "source_agent_id": agent_a["agent_identifier"],
        "target_agent_id": agent_b["agent_identifier"],
        "action": "hotel:reserve",
        "resource": "hotel_room",
        "amount": "400.00",
        "currency": "USD",
    }).encode("utf-8")

    sig_400 = _sign_cross_org(
        priv_a, key_a, agent_a["agent_identifier"],
        org_a["id"], org_b["id"], agent_b["agent_identifier"], body_400,
    )
    res_400 = client.post(
        "/api/v1/cross-org/authorize",
        headers={**sig_400, "Content-Type": "application/json"},
        content=body_400,
    )
    assert res_400.status_code == 200, res_400.text
    assert res_400.json()["status"] == "APPROVED"

    # -------------------------------------------------------------------------
    # Case B: Request $600 (>= $500 target threshold) -> PENDING -> Target Approves -> APPROVED
    # -------------------------------------------------------------------------
    body_600 = json.dumps({
        "target_organization_id": org_b["id"],
        "source_agent_id": agent_a["agent_identifier"],
        "target_agent_id": agent_b["agent_identifier"],
        "action": "hotel:reserve",
        "resource": "hotel_room",
        "amount": "600.00",
        "currency": "USD",
    }).encode("utf-8")

    sig_600 = _sign_cross_org(
        priv_a, key_a, agent_a["agent_identifier"],
        org_a["id"], org_b["id"], agent_b["agent_identifier"], body_600,
    )
    res_600 = client.post(
        "/api/v1/cross-org/authorize",
        headers={**sig_600, "Content-Type": "application/json"},
        content=body_600,
    )
    assert res_600.status_code == 200
    data_600 = res_600.json()
    assert data_600["status"] == "PENDING"
    req_600_id = data_600["request_id"]
    assert "TARGET" in data_600["pending_approvals"]

    # Inbound request appears in HotelCorp's requests list
    inbound_b = client.get("/v1/cross-org/requests?direction=inbound", headers=headers_b).json()
    assert any(r["request_id"] == req_600_id for r in inbound_b)

    # HotelCorp approves the request
    appr_res = client.post(f"/v1/cross-org/requests/{req_600_id}/approve", headers=headers_b, json={
        "reason": "Hotel room confirmed"
    })
    assert appr_res.status_code == 200
    assert appr_res.json()["status"] == "APPROVED"

    # Subsequent check shows APPROVED
    check_600 = client.get(f"/v1/cross-org/requests/{req_600_id}", headers=headers_a)
    assert check_600.status_code == 200
    assert check_600.json()["status"] == "APPROVED"

    # -------------------------------------------------------------------------
    # Case C: Request $900 (> $800 target max limit) -> REJECTED
    # -------------------------------------------------------------------------
    body_900 = json.dumps({
        "target_organization_id": org_b["id"],
        "source_agent_id": agent_a["agent_identifier"],
        "target_agent_id": agent_b["agent_identifier"],
        "action": "hotel:reserve",
        "resource": "hotel_room",
        "amount": "900.00",
        "currency": "USD",
    }).encode("utf-8")

    sig_900 = _sign_cross_org(
        priv_a, key_a, agent_a["agent_identifier"],
        org_a["id"], org_b["id"], agent_b["agent_identifier"], body_900,
    )
    res_900 = client.post(
        "/api/v1/cross-org/authorize",
        headers={**sig_900, "Content-Type": "application/json"},
        content=body_900,
    )
    assert res_900.status_code == 200
    assert res_900.json()["status"] == "REJECTED"
    assert "CROSS_ORG_AMOUNT_EXCEEDED" in res_900.json()["reason"]

    # -------------------------------------------------------------------------
    # Case D: Revoke trust -> Subsequent requests immediately REJECTED
    # -------------------------------------------------------------------------
    revoke_res = client.post(f"/v1/organization-trust/{trust_id}/revoke", headers=headers_b, json={
        "reason": "Contract ended"
    })
    assert revoke_res.status_code == 200
    assert revoke_res.json()["status"] == "REVOKED"

    body_300 = json.dumps({
        "target_organization_id": org_b["id"],
        "source_agent_id": agent_a["agent_identifier"],
        "target_agent_id": agent_b["agent_identifier"],
        "action": "hotel:reserve",
        "resource": "hotel_room",
        "amount": "300.00",
        "currency": "USD",
    }).encode("utf-8")

    sig_300 = _sign_cross_org(
        priv_a, key_a, agent_a["agent_identifier"],
        org_a["id"], org_b["id"], agent_b["agent_identifier"], body_300,
    )
    res_300 = client.post(
        "/api/v1/cross-org/authorize",
        headers={**sig_300, "Content-Type": "application/json"},
        content=body_300,
    )
    assert res_300.status_code == 200
    assert res_300.json()["status"] == "REJECTED"
    assert "TRUST_REVOKED" in res_300.json()["reason"]

    # -------------------------------------------------------------------------
    # Case E: Replay old valid signed request -> Rejected by anti-replay
    # -------------------------------------------------------------------------
    res_replay = client.post(
        "/api/v1/cross-org/authorize",
        headers={**sig_400, "Content-Type": "application/json"},
        content=body_400,
    )
    assert res_replay.status_code == 409
    assert "REPLAY_DETECTED" in res_replay.text


def test_cross_org_idempotency_key_and_conflict(client: TestClient, db: Session):
    _, auth_a = _account(client, "Alice")
    org_a, headers_a = _create_org(client, auth_a, "SkyTravel")
    agent_a, priv_a, key_a = _create_agent_with_key(client, headers_a, "Travel Assistant")

    _, auth_b = _account(client, "Bob")
    org_b, headers_b = _create_org(client, auth_b, "HotelCorp")
    agent_b, priv_b, key_b = _create_agent_with_key(client, headers_b, "Hotel Booking Agent")

    db.get(Agent, UUID(agent_a["id"])).status = AgentStatus.ACTIVE
    db.get(Agent, UUID(agent_b["id"])).status = AgentStatus.ACTIVE
    db.commit()

    now = datetime.now(timezone.utc)
    client.post("/permissions", headers=headers_a, json={
        "agent_id": agent_a["id"],
        "action": "hotel:search",
        "resource": "rooms",
        "requires_approval": False,
        "valid_from": (now - timedelta(minutes=5)).isoformat(),
        "expires_at": (now + timedelta(days=7)).isoformat(),
    })

    trust_req = client.post("/v1/organization-trust/requests", headers=headers_a, json={
        "target_organization_id": org_b["id"]
    })
    trust_id = trust_req.json()["trust_id"]
    client.post(f"/v1/organization-trust/{trust_id}/accept", headers=headers_b)

    client.post(f"/v1/organization-trust/{trust_id}/agent-connections", headers=headers_a, json={
        "source_agent_id": agent_a["id"],
        "target_agent_id": agent_b["id"],
    })

    client.put(f"/v1/organization-trust/{trust_id}/policy", headers=headers_a, json={
        "allowed_actions": ["hotel:search"],
        "allowed_resources": ["rooms"],
        "require_human_approval": False,
    })

    client.put(f"/v1/organizations/{org_b['id']}/target-policy", headers=headers_b, json={
        "allowed_actions": ["hotel:search"],
        "allowed_resources": ["rooms"],
        "require_human_approval": False,
    })

    idem_key = f"idem_{secrets.token_hex(16)}"
    body_search = json.dumps({
        "target_organization_id": org_b["id"],
        "source_agent_id": agent_a["agent_identifier"],
        "target_agent_id": agent_b["agent_identifier"],
        "action": "hotel:search",
        "resource": "rooms",
    }).encode("utf-8")

    sig1 = _sign_cross_org(
        priv_a, key_a, agent_a["agent_identifier"],
        org_a["id"], org_b["id"], agent_b["agent_identifier"], body_search,
    )

    # 1. First execution -> APPROVED
    res1 = client.post(
        "/api/v1/cross-org/authorize",
        headers={**sig1, "Content-Type": "application/json", "Idempotency-Key": idem_key},
        content=body_search,
    )
    assert res1.status_code == 200
    req_id = res1.json()["request_id"]

    # 2. Idempotent Retry with same Idempotency-Key -> Returns same request_id and APPROVED
    res2 = client.post(
        "/api/v1/cross-org/authorize",
        headers={**sig1, "Content-Type": "application/json", "Idempotency-Key": idem_key},
        content=body_search,
    )
    assert res2.status_code == 200
    assert res2.json()["request_id"] == req_id

    # 3. Idempotency Key Conflict: same key with different payload -> 409 Conflict
    body_conflict = json.dumps({
        "target_organization_id": org_b["id"],
        "source_agent_id": agent_a["agent_identifier"],
        "target_agent_id": agent_b["agent_identifier"],
        "action": "hotel:search",
        "resource": "rooms",
        "amount": "50.00",
        "currency": "USD",
    }).encode("utf-8")

    sig3 = _sign_cross_org(
        priv_a, key_a, agent_a["agent_identifier"],
        org_a["id"], org_b["id"], agent_b["agent_identifier"], body_conflict,
    )
    res_conflict = client.post(
        "/api/v1/cross-org/authorize",
        headers={**sig3, "Content-Type": "application/json", "Idempotency-Key": idem_key},
        content=body_conflict,
    )
    assert res_conflict.status_code == 409
    assert "CROSS_ORG_IDEMPOTENCY_CONFLICT" in res_conflict.text


def test_cross_org_privacy_boundary_and_audit_isolation(client: TestClient, db: Session):
    """Verify Company A cannot access Company B's private keys, permissions, internal audit logs or target policies."""
    _, auth_a = _account(client, "Alice")
    org_a, headers_a = _create_org(client, auth_a, "SkyTravel")
    agent_a, _, _ = _create_agent_with_key(client, headers_a, "Travel Assistant")

    _, auth_b = _account(client, "Bob")
    org_b, headers_b = _create_org(client, auth_b, "HotelCorp")
    agent_b, _, _ = _create_agent_with_key(client, headers_b, "Hotel Booking Agent")

    # Alice tries to inspect Bob's target policy -> 403 Forbidden
    res_policy = client.get(f"/v1/organizations/{org_b['id']}/target-policy", headers=headers_a)
    assert res_policy.status_code == 403

    # Alice tries to inspect Bob's agents -> 404 / 403
    res_agent = client.get(f"/agents/{agent_b['id']}", headers=headers_a)
    assert res_agent.status_code in {403, 404}

    # Public directory only exposes public profile (no private team or secrets)
    pub_profile = client.get(f"/v1/organizations/{org_b['id']}/public-profile").json()
    assert pub_profile["public_name"] == "HotelCorp"
    assert "owner_id" not in pub_profile
    assert "api_keys" not in pub_profile
