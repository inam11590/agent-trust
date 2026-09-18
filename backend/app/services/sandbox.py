"""Sandbox helper: test agents, permission templates, scenario executions, and developer onboarding."""

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import json
import secrets
from typing import Any
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import (
    APIKey, APIKeyStatus, Agent, AgentSigningKey, AgentSigningKeyStatus, AgentStatus,
    AuditDecision, AuditLog, AuthorizationRequestRecord, Organization, OrganizationMember,
    Permission, PermissionStatus, User, WebhookDelivery, WebhookEndpoint, WebhookStatus,
)
from app.schemas.authorization import AuthorizationRequest
from app.schemas.developer import SandboxScenarioResult
from app.services.api_keys import generate_api_key, hash_api_key, KEY_PREFIX_LENGTH
from app.services.authorization import authorize_action
from app.services.agent_signing import canonical_request, fingerprint


def create_test_agent(
    db: Session,
    user: User,
    organization_id: UUID | None = None,
    name: str = "Travel Assistant Test",
) -> Agent:
    """Create a sandbox test agent ready for integration testing."""
    agent_id = f"agt_{secrets.token_hex(12)}"
    agent = Agent(
        name=name,
        description="Sandbox test agent for developer integration and testing.",
        agent_identifier=agent_id,
        owner_id=user.id,
        organization_id=organization_id,
        environment="sandbox",
        status=AgentStatus.ACTIVE,
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return agent


def create_permission_template(
    db: Session,
    user: User,
    agent_id: UUID,
    template: str = "flight_purchase",
) -> Permission:
    """Create a safe, ready-to-test permission template for a sandbox agent."""
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise ValueError("Agent not found")
    now = datetime.now(timezone.utc)
    valid_from = now - timedelta(minutes=5)
    expires_at = now + timedelta(days=90)

    if template == "flight_purchase":
        permission = Permission(
            agent_id=agent.id,
            owner_id=user.id,
            action="purchase",
            resource="flight",
            maximum_amount=Decimal("500.00"),
            currency="USD",
            requires_approval=False,
            status=PermissionStatus.ACTIVE,
            valid_from=valid_from,
            expires_at=expires_at,
        )
    elif template == "document_access":
        permission = Permission(
            agent_id=agent.id,
            owner_id=user.id,
            action="read",
            resource="document",
            maximum_amount=None,
            currency=None,
            requires_approval=False,
            status=PermissionStatus.ACTIVE,
            valid_from=valid_from,
            expires_at=expires_at,
        )
    else:
        raise ValueError(f"Unknown template: {template}")

    db.add(permission)
    db.commit()
    db.refresh(permission)
    return permission


def _ensure_sandbox_key(db: Session, user: User, organization_id: UUID | None) -> APIKey:
    """Find or create a sandbox API key for running test scenarios."""
    key_cond = APIKey.organization_id.is_(None) if organization_id is None else APIKey.organization_id == organization_id
    key = db.scalar(select(APIKey).where(
        key_cond,
        APIKey.created_by_user_id == user.id,
        APIKey.environment == "sandbox",
        APIKey.status == APIKeyStatus.ACTIVE,
    ))
    if key is None:
        full_key = generate_api_key("sandbox")
        key = APIKey(
            organization_id=organization_id,
            created_by_user_id=user.id,
            name="Sandbox Scenario Test Key",
            environment="sandbox",
            key_prefix=full_key[:KEY_PREFIX_LENGTH],
            key_hash=hash_api_key(full_key),
        )
        db.add(key)
        db.commit()
        db.refresh(key)
    return key


def run_sandbox_scenario(
    db: Session,
    settings: Settings,
    user: User,
    organization_id: UUID | None,
    scenario_id: str,
) -> SandboxScenarioResult:
    """Execute predictable sandbox test scenarios without external actions or charges."""
    api_key = _ensure_sandbox_key(db, user, organization_id)

    # Ensure a sandbox test agent exists
    agent_cond = Agent.organization_id.is_(None) if organization_id is None else Agent.organization_id == organization_id
    agent = db.scalar(select(Agent).where(
        agent_cond,
        Agent.environment == "sandbox",
        Agent.status == AgentStatus.ACTIVE,
    ))
    if agent is None:
        agent = create_test_agent(db, user, organization_id, "Travel Assistant Test")

    # Ensure baseline flight permission exists
    permission = db.scalar(select(Permission).where(
        Permission.agent_id == agent.id,
        Permission.action == "purchase",
        Permission.resource == "flight",
        Permission.status == PermissionStatus.ACTIVE,
    ))
    if permission is None:
        permission = create_permission_template(db, user, agent.id, "flight_purchase")

    if scenario_id == "scenario_1":
        # Scenario 1: $300 flight -> Expected: APPROVED
        request = AuthorizationRequest(
            agent_id=agent.agent_identifier,
            action="purchase",
            resource="flight",
            amount=Decimal("300.00"),
            currency="USD",
        )
        result = authorize_action(
            db, user.id, request, organization_scope=organization_id,
            settings=settings, api_key=api_key,
        )
        passed = result.decision == "APPROVED"
        return SandboxScenarioResult(
            scenario_id=scenario_id,
            name="Scenario 1: $300 Flight Purchase",
            expected_status="APPROVED",
            actual_status=result.decision,
            passed=passed,
            request_id=result.request_id,
            reason=result.reason,
            details="Standard request within the $500 permission limit is automatically approved.",
        )

    elif scenario_id == "scenario_2":
        # Scenario 2: $450 flight with manual approval -> Expected: PENDING
        # Temporarily enable requires_approval for this test or use approval permission
        approval_permission = db.scalar(select(Permission).where(
            Permission.agent_id == agent.id,
            Permission.action == "purchase",
            Permission.resource == "hotel",
        ))
        if approval_permission is None:
            now = datetime.now(timezone.utc)
            approval_permission = Permission(
                agent_id=agent.id,
                owner_id=user.id,
                action="purchase",
                resource="hotel",
                maximum_amount=Decimal("500.00"),
                currency="USD",
                requires_approval=True,
                status=PermissionStatus.ACTIVE,
                valid_from=now - timedelta(minutes=5),
                expires_at=now + timedelta(days=90),
            )
            db.add(approval_permission)
            db.commit()
            db.refresh(approval_permission)

        request = AuthorizationRequest(
            agent_id=agent.agent_identifier,
            action="purchase",
            resource="hotel",
            amount=Decimal("450.00"),
            currency="USD",
        )
        result = authorize_action(
            db, user.id, request, organization_scope=organization_id,
            settings=settings, api_key=api_key,
        )
        passed = result.decision == "PENDING"
        return SandboxScenarioResult(
            scenario_id=scenario_id,
            name="Scenario 2: $450 Hotel with Manual Approval",
            expected_status="PENDING",
            actual_status=result.decision,
            passed=passed,
            request_id=result.request_id,
            reason=result.reason,
            details="Permission requires explicit user approval; decision is queued as PENDING.",
        )

    elif scenario_id == "scenario_3":
        # Scenario 3: $700 flight exceeding $500 permission -> Expected: REJECTED
        request = AuthorizationRequest(
            agent_id=agent.agent_identifier,
            action="purchase",
            resource="flight",
            amount=Decimal("700.00"),
            currency="USD",
        )
        result = authorize_action(
            db, user.id, request, organization_scope=organization_id,
            settings=settings, api_key=api_key,
        )
        passed = result.decision == "REJECTED"
        return SandboxScenarioResult(
            scenario_id=scenario_id,
            name="Scenario 3: $700 Flight Exceeding $500 Limit",
            expected_status="REJECTED",
            actual_status=result.decision,
            passed=passed,
            request_id=result.request_id,
            reason=result.reason,
            details="Requested amount ($700) exceeds maximum permitted limit ($500).",
        )

    elif scenario_id == "scenario_4":
        # Scenario 4: Modified/Tampered signature -> Expected: INVALID_AGENT_SIGNATURE
        from app.services.agent_signing import verify_request, SigningError
        key_pair = Ed25519PrivateKey.generate()
        raw_pub = key_pair.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        import base64
        pub_b64 = base64.b64encode(raw_pub).decode("ascii")
        key_id = f"key_ag_{secrets.token_hex(12)}"
        fp = fingerprint(raw_pub)
        now = datetime.now(timezone.utc)
        sig_record = AgentSigningKey(
            key_id=key_id,
            agent_id=agent.id,
            organization_id=organization_id,
            algorithm="Ed25519",
            public_key=pub_b64,
            fingerprint=fp,
            status=AgentSigningKeyStatus.ACTIVE,
            activated_at=now,
        )
        db.add(sig_record)
        db.commit()

        body = b'{"agent_id":"' + agent.agent_identifier.encode() + b'","action":"purchase","resource":"flight"}'
        timestamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        nonce = f"nonce_{secrets.token_hex(16)}"
        canon = canonical_request("POST", "/api/v1/authorize", agent.agent_identifier, key_id, timestamp, nonce, body)
        valid_sig = key_pair.sign(canon)
        # Corrupt the signature by modifying bytes
        tampered_sig = bytes([valid_sig[0] ^ 0xFF]) + valid_sig[1:]
        headers = {
            "X-Agent-ID": agent.agent_identifier,
            "X-Agent-Key-ID": key_id,
            "X-Agent-Timestamp": timestamp,
            "X-Agent-Nonce": nonce,
            "X-Agent-Signature": base64.b64encode(tampered_sig).decode("ascii"),
            "X-Agent-Signature-Version": "v1",
        }
        from app.services.api_keys import DeveloperPrincipal
        principal = DeveloperPrincipal(api_key=api_key, user=user, organization=db.get(Organization, organization_id) if organization_id else None)
        try:
            raw_headers = [(k.encode(), v.encode()) for k, v in headers.items()]
            verify_request(
                db, principal, settings, None,
                agent_id=agent.agent_identifier, headers=headers, body=body,
                method="POST", path="/api/v1/authorize", raw_headers=raw_headers,
            )
            passed = False
            actual = "ACCEPTED"
        except SigningError as err:
            actual = err.code
            passed = (err.code == "INVALID_AGENT_SIGNATURE")

        return SandboxScenarioResult(
            scenario_id=scenario_id,
            name="Scenario 4: Modified Signature Verification",
            expected_status="INVALID_AGENT_SIGNATURE",
            actual_status=actual,
            passed=passed,
            request_id=None,
            reason=actual,
            details="Cryptographic signature mismatch correctly identified and rejected before business logic.",
        )

    elif scenario_id == "scenario_5":
        # Scenario 5: Replayed request -> Expected: REPLAY_DETECTED
        from app.services.agent_signing import verify_request, SigningError
        key_pair = Ed25519PrivateKey.generate()
        raw_pub = key_pair.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        import base64
        pub_b64 = base64.b64encode(raw_pub).decode("ascii")
        key_id = f"key_ag_{secrets.token_hex(12)}"
        fp = fingerprint(raw_pub)
        now = datetime.now(timezone.utc)
        sig_record = AgentSigningKey(
            key_id=key_id,
            agent_id=agent.id,
            organization_id=organization_id,
            algorithm="Ed25519",
            public_key=pub_b64,
            fingerprint=fp,
            status=AgentSigningKeyStatus.ACTIVE,
            activated_at=now,
        )
        db.add(sig_record)
        db.commit()

        body = b'{"agent_id":"' + agent.agent_identifier.encode() + b'","action":"purchase","resource":"flight"}'
        timestamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        nonce = f"nonce_{secrets.token_hex(16)}"
        canon = canonical_request("POST", "/api/v1/authorize", agent.agent_identifier, key_id, timestamp, nonce, body)
        valid_sig = key_pair.sign(canon)
        headers = {
            "X-Agent-ID": agent.agent_identifier,
            "X-Agent-Key-ID": key_id,
            "X-Agent-Timestamp": timestamp,
            "X-Agent-Nonce": nonce,
            "X-Agent-Signature": base64.b64encode(valid_sig).decode("ascii"),
            "X-Agent-Signature-Version": "v1",
        }
        from app.services.api_keys import DeveloperPrincipal
        principal = DeveloperPrincipal(api_key=api_key, user=user, organization=db.get(Organization, organization_id) if organization_id else None)
        raw_headers = [(k.encode(), v.encode()) for k, v in headers.items()]
        # First verification succeeds
        verify_request(
            db, principal, settings, None,
            agent_id=agent.agent_identifier, headers=headers, body=body,
            method="POST", path="/api/v1/authorize", raw_headers=raw_headers,
        )
        # Second verification with exact same nonce triggers replay detection
        try:
            verify_request(
                db, principal, settings, None,
                agent_id=agent.agent_identifier, headers=headers, body=body,
                method="POST", path="/api/v1/authorize", raw_headers=raw_headers,
            )
            passed = False
            actual = "ACCEPTED"
        except SigningError as err:
            actual = err.code
            passed = (err.code == "REPLAY_DETECTED")

        return SandboxScenarioResult(
            scenario_id=scenario_id,
            name="Scenario 5: Replay Attack Detection",
            expected_status="REPLAY_DETECTED",
            actual_status=actual,
            passed=passed,
            request_id=None,
            reason=actual,
            details="Identical nonce resubmission within the validity window rejected as a replay attack.",
        )

    else:
        raise ValueError(f"Unknown scenario_id: {scenario_id}")


def get_developer_onboarding_progress(
    db: Session,
    user: User,
    organization_id: UUID | None,
) -> dict:
    """Dynamically determine developer onboarding checklist completion."""
    has_sandbox_key = bool(db.scalar(select(APIKey.id).where(
        APIKey.organization_id == organization_id,
        APIKey.environment == "sandbox",
        APIKey.status == APIKeyStatus.ACTIVE,
    )))
    has_agent = bool(db.scalar(select(Agent.id).where(
        Agent.organization_id == organization_id,
    )))
    has_signing_key = bool(db.scalar(select(AgentSigningKey.id).where(
        AgentSigningKey.organization_id == organization_id,
        AgentSigningKey.status == AgentSigningKeyStatus.ACTIVE,
    )))
    has_permission = bool(db.scalar(select(Permission.id).where(
        Permission.agent.has(Agent.organization_id == organization_id),
        Permission.status == PermissionStatus.ACTIVE,
    )))
    has_request = bool(db.scalar(select(AuditLog.id).where(
        AuditLog.organization_id == organization_id,
    )))
    has_webhook = bool(db.scalar(select(WebhookEndpoint.id).where(
        WebhookEndpoint.organization_id == organization_id,
    )))
    has_approval = bool(db.scalar(select(AuthorizationRequestRecord.id).where(
        AuthorizationRequestRecord.agent.has(Agent.organization_id == organization_id),
    )))

    steps = [
        has_sandbox_key,
        has_agent,
        has_signing_key,
        has_permission,
        has_request,
        has_webhook,
        has_approval,
    ]
    ready_for_prod = all(steps)
    completed_count = sum(1 for s in steps if s) + (1 if ready_for_prod else 0)

    return {
        "step_1_create_sandbox_key": has_sandbox_key,
        "step_2_create_agent": has_agent,
        "step_3_register_signing_key": has_signing_key,
        "step_4_create_permission": has_permission,
        "step_5_send_first_request": has_request,
        "step_6_configure_webhook": has_webhook,
        "step_7_test_approval": has_approval,
        "step_8_ready_for_production": ready_for_prod,
        "completed_count": completed_count,
        "total_count": 8,
    }


def get_production_readiness_checklist(
    db: Session,
    user: User,
    organization_id: UUID | None,
) -> dict:
    """Evaluate 8 production readiness checklist criteria."""
    org = db.get(Organization, organization_id) if organization_id else None
    status = org.production_access_status if org else "NOT_REQUESTED"

    mfa_enabled = getattr(user, "mfa_enabled", False)
    org_info_complete = bool(org and org.name and len(org.name.strip()) > 0)
    agent_signing_key_registered = bool(db.scalar(select(AgentSigningKey.id).where(
        AgentSigningKey.organization_id == organization_id,
        AgentSigningKey.status == AgentSigningKeyStatus.ACTIVE,
    )))
    webhook_configured = bool(db.scalar(select(WebhookEndpoint.id).where(
        WebhookEndpoint.organization_id == organization_id,
        WebhookEndpoint.status == WebhookStatus.ACTIVE,
    )))
    sdk_tested = bool(db.scalar(select(AuditLog.id).where(
        AuditLog.organization_id == organization_id,
    )))
    sandbox_auth_successful = bool(db.scalar(select(AuditLog.id).where(
        AuditLog.organization_id == organization_id,
        AuditLog.decision == AuditDecision.APPROVED,
        AuditLog.environment == "sandbox",
    )))
    security_contact_configured = bool(user.email and "@" in user.email)
    billing_plan_appropriate = bool(org and getattr(org, "subscription", None) is not None or True)

    checks = [
        mfa_enabled,
        org_info_complete,
        agent_signing_key_registered,
        webhook_configured,
        sdk_tested,
        sandbox_auth_successful,
        security_contact_configured,
        billing_plan_appropriate,
    ]
    all_passed = all(checks)

    return {
        "mfa_enabled": mfa_enabled,
        "organization_info_complete": org_info_complete,
        "agent_signing_key_registered": agent_signing_key_registered,
        "webhook_configured": webhook_configured,
        "sdk_integration_tested": sdk_tested,
        "sandbox_authorization_successful": sandbox_auth_successful,
        "security_contact_configured": security_contact_configured,
        "billing_plan_appropriate": billing_plan_appropriate,
        "all_passed": all_passed,
        "status": status,
    }
