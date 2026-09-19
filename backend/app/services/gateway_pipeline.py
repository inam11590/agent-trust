"""AgentTrust Gateway Message Pipeline (Step 21).

Enforces the 11-stage verification, authorization, SSRF defense, and routing protocol:
1. Protocol Version Validation (ATP/1.0)
2. Envelope Schema Integrity
3. Source Agent Identity & Active Signing Key
4. Exact ATP-SIG/1 Cryptographic Signature Verification
5. Anti-Replay Defense & Clock Skew (300s window)
6. Delegation Chain Validation (if present)
7. Cross-Organization Trust Check (if cross-org)
8. Capability Authorization & Risk Engine Scoring
9. Multi-Party Approval Hold (PENDING_APPROVAL never routes until approved)
10. Target Endpoint Resolution & SSRF Protection
11. Gateway Ed25519 Attestation & Outbound Delivery
"""

from __future__ import annotations

import base64
import hashlib
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.agent import Agent, AgentStatus
from app.models.agent_signing import (
    AgentRequestNonce,
    AgentSigningKey,
    AgentSigningKeyStatus,
)
from app.models.agenttrust_protocol import (
    AgentCapability,
    AgentEndpoint,
    ATPDeliveryStatus,
    ATPMessageDelivery,
    ATPMessageRecord,
    EndpointStatus,
)
from app.models.cross_organization_trust import (
    OrganizationTrustRelationship,
    TargetOrganizationPolicy,
    TrustStatus,
)
from app.models.organization import Organization, SecurityEvent
from app.services.atp_canonical import (
    PROTOCOL_VERSION,
    SIGNING_VERSION,
    build_canonical_bytes,
    compute_payload_sha256,
    format_agent_address,
    parse_agent_address,
)
from app.services.atp_router import ATPRoutingError, route_atp_message
from app.services.credential_service import (
    CredentialVerificationError,
    verify_agent_credential,
)
from app.services.sandbox_mock_agents import is_sandbox_mock_agent


class GatewayPipelineError(Exception):
    """Base error raised during gateway pipeline processing."""

    def __init__(self, message: str, code: str, status_code: int = 400, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}


def parse_timestamp_iso(ts_str: str) -> datetime:
    """Parse ISO8601 timestamp string into timezone-aware datetime."""
    try:
        # Handle 'Z' suffix
        cleaned = ts_str.strip()
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception as exc:
        raise GatewayPipelineError(
            f"Invalid timestamp format '{ts_str}'. Expected ISO-8601 (e.g., 2026-09-19T10:00:00Z).",
            code="INVALID_TIMESTAMP",
            status_code=400,
        ) from exc


def resolve_agent_and_org(db: Session, org_id_str: str, agent_id_str: str) -> Tuple[Optional[Organization], Optional[Agent]]:
    """
    Resolve Organization and Agent from strings (which may be UUIDs or identifier slugs).
    """
    # 1. Resolve Agent
    agent: Optional[Agent] = None
    try:
        agent_uuid = UUID(agent_id_str)
        agent = db.execute(select(Agent).where(Agent.id == agent_uuid)).scalar_one_or_none()
    except (ValueError, TypeError):
        pass

    if not agent:
        agent = db.execute(select(Agent).where(Agent.agent_identifier == agent_id_str)).scalar_one_or_none()

    # 2. Resolve Organization
    org: Optional[Organization] = None
    if agent and agent.organization_id:
        org = db.execute(select(Organization).where(Organization.id == agent.organization_id)).scalar_one_or_none()

    if not org:
        try:
            org_uuid = UUID(org_id_str)
            org = db.execute(select(Organization).where(Organization.id == org_uuid)).scalar_one_or_none()
        except (ValueError, TypeError):
            pass

    if not org:
        org = db.execute(select(Organization).where(Organization.name == org_id_str)).scalar_one_or_none()

    return org, agent


def process_atp_message(
    db: Session,
    envelope: Dict[str, Any],
    allow_private_ips: bool = False,
    enforce_https: bool = True,
) -> Dict[str, Any]:
    """
    Main Gateway Pipeline entry point for ATP/1.0 messages.
    Follows fail-closed security design.
    """
    # -------------------------------------------------------------
    # Stage 1: Protocol Version Validation
    # -------------------------------------------------------------
    protocol = envelope.get("protocol")
    if protocol != PROTOCOL_VERSION:
        raise GatewayPipelineError(
            f"Unsupported protocol version '{protocol}'. Expected '{PROTOCOL_VERSION}'.",
            code="UNSUPPORTED_PROTOCOL",
            status_code=400,
        )

    # -------------------------------------------------------------
    # Stage 2: Envelope Schema Integrity
    # -------------------------------------------------------------
    message_id = envelope.get("message_id")
    if not message_id or not isinstance(message_id, str):
        raise GatewayPipelineError("Missing or invalid 'message_id'.", code="INVALID_MESSAGE_ID", status_code=400)

    # Check for duplicate message_id idempotency
    existing_record = db.execute(
        select(ATPMessageRecord).where(ATPMessageRecord.message_id == message_id)
    ).scalar_one_or_none()
    if existing_record:
        if existing_record.status == ATPDeliveryStatus.DELIVERED.value:
            # Return idempotent cached response if available
            return {
                "protocol": PROTOCOL_VERSION,
                "message_id": message_id,
                "status": "DELIVERED",
                "idempotent": True,
                "completed_at": existing_record.completed_at.isoformat() if existing_record.completed_at else None,
            }
        elif existing_record.status == "PENDING_APPROVAL":
            return {
                "protocol": PROTOCOL_VERSION,
                "message_id": message_id,
                "status": "PENDING_APPROVAL",
                "message": "Message is currently on hold awaiting multi-party authorization.",
                "idempotent": True,
            }

    message_type = envelope.get("message_type", "request")
    source = envelope.get("source") or {}
    target = envelope.get("target") or {}
    capability = envelope.get("capability")
    timestamp_str = envelope.get("timestamp")
    nonce = envelope.get("nonce")
    payload = envelope.get("payload")
    sig_info = envelope.get("signature") or {}

    if not capability or not isinstance(capability, str):
        raise GatewayPipelineError("Missing or invalid 'capability'.", code="INVALID_CAPABILITY", status_code=400)

    if not timestamp_str or not isinstance(timestamp_str, str):
        raise GatewayPipelineError("Missing or invalid 'timestamp'.", code="INVALID_TIMESTAMP", status_code=400)

    if not nonce or not isinstance(nonce, str):
        raise GatewayPipelineError("Missing or invalid 'nonce'.", code="INVALID_NONCE", status_code=400)

    # Source & Target address extraction
    source_addr = source.get("address")
    source_org_id = source.get("organization_id")
    source_agent_id = source.get("agent_id")
    if source_addr:
        src_org, src_agt = parse_agent_address(source_addr)
        source_org_id = source_org_id or src_org
        source_agent_id = source_agent_id or src_agt
    elif source_org_id and source_agent_id:
        source_addr = format_agent_address(source_org_id, source_agent_id)
    else:
        raise GatewayPipelineError("Source agent address or (organization_id, agent_id) required.", code="INVALID_SOURCE", status_code=400)

    target_addr = target.get("address")
    target_org_id = target.get("organization_id")
    target_agent_id = target.get("agent_id")
    if target_addr:
        dst_org, dst_agt = parse_agent_address(target_addr)
        target_org_id = target_org_id or dst_org
        target_agent_id = target_agent_id or dst_agt
    elif target_org_id and target_agent_id:
        target_addr = format_agent_address(target_org_id, target_agent_id)
    else:
        raise GatewayPipelineError("Target agent address or (organization_id, agent_id) required.", code="INVALID_TARGET", status_code=400)

    # Signature structure check
    sig_version = sig_info.get("version")
    key_id = sig_info.get("key_id")
    sig_value = sig_info.get("value")
    if sig_version != SIGNING_VERSION:
        raise GatewayPipelineError(f"Unsupported signature version '{sig_version}'. Expected '{SIGNING_VERSION}'.", code="INVALID_SIGNATURE_VERSION", status_code=400)
    if not key_id or not sig_value:
        raise GatewayPipelineError("Signature must contain 'key_id' and 'value'.", code="INVALID_SIGNATURE_STRUCTURE", status_code=400)

    # -------------------------------------------------------------
    # Stage 3: Source Agent Identity & Active Signing Key Lookup
    # -------------------------------------------------------------
    src_org_obj, src_agent_obj = resolve_agent_and_org(db, source_org_id, source_agent_id)
    if not src_agent_obj:
        raise GatewayPipelineError(
            f"Source agent '{source_agent_id}' not found in organization '{source_org_id}'.",
            code="SOURCE_AGENT_NOT_FOUND",
            status_code=401,
        )

    if src_agent_obj.status != AgentStatus.ACTIVE:
        raise GatewayPipelineError(
            f"Source agent '{source_agent_id}' is not active (status: {src_agent_obj.status}).",
            code="SOURCE_AGENT_INACTIVE",
            status_code=403,
        )

    signing_key = db.execute(
        select(AgentSigningKey).where(
            AgentSigningKey.agent_id == src_agent_obj.id,
            AgentSigningKey.key_id == key_id,
        )
    ).scalar_one_or_none()

    if not signing_key:
        raise GatewayPipelineError(
            f"Signing key '{key_id}' not registered for source agent '{source_agent_id}'.",
            code="SIGNING_KEY_NOT_FOUND",
            status_code=401,
        )

    if signing_key.status == AgentSigningKeyStatus.REVOKED:
        raise GatewayPipelineError(
            f"Signing key '{key_id}' has been revoked.",
            code="KEY_REVOKED",
            status_code=401,
        )

    if signing_key.status != AgentSigningKeyStatus.ACTIVE:
        raise GatewayPipelineError(
            f"Signing key '{key_id}' is not active (status: {signing_key.status}).",
            code="KEY_NOT_ACTIVE",
            status_code=401,
        )

    now_utc = datetime.now(timezone.utc)
    if signing_key.expires_at and signing_key.expires_at < now_utc:
        raise GatewayPipelineError(
            f"Signing key '{key_id}' expired at {signing_key.expires_at.isoformat()}.",
            code="KEY_EXPIRED",
            status_code=401,
        )

    # -------------------------------------------------------------
    # Stage 4: Cryptographic Signature Verification (ATP-SIG/1)
    # -------------------------------------------------------------
    payload_sha256 = compute_payload_sha256(payload)
    if envelope.get("payload_sha256") and envelope["payload_sha256"] != payload_sha256:
        raise GatewayPipelineError(
            "Envelope payload_sha256 does not match SHA-256 of payload body.",
            code="PAYLOAD_HASH_MISMATCH",
            status_code=400,
        )

    canon_bytes = build_canonical_bytes(
        message_id=message_id,
        message_type=message_type,
        source_org_id=source_org_id,
        source_agent_id=source_agent_id,
        target_org_id=target_org_id,
        target_agent_id=target_agent_id,
        capability=capability,
        timestamp=timestamp_str,
        nonce=nonce,
        payload_sha256=payload_sha256,
    )

    try:
        raw_pub_bytes = base64.b64decode(signing_key.public_key)
        pub_key = Ed25519PublicKey.from_public_bytes(raw_pub_bytes)
        sig_bytes = base64.b64decode(sig_value)
        pub_key.verify(sig_bytes, canon_bytes)
    except (InvalidSignature, Exception) as exc:
        raise GatewayPipelineError(
            "Ed25519 cryptographic signature verification failed.",
            code="INVALID_SIGNATURE",
            status_code=401,
        ) from exc

    # -------------------------------------------------------------
    # Stage 5: Anti-Replay Defense & Clock Skew Window (300s)
    # -------------------------------------------------------------
    client_dt = parse_timestamp_iso(timestamp_str)
    clock_skew = abs((now_utc - client_dt).total_seconds())
    if clock_skew > 300.0:
        raise GatewayPipelineError(
            f"Timestamp skew ({int(clock_skew)}s) exceeds allowed window (300s).",
            code="TIMESTAMP_OUT_OF_WINDOW",
            status_code=401,
        )

    nonce_hash = hashlib.sha256(nonce.encode("ascii")).hexdigest()
    nonce_expiry = now_utc + timedelta(seconds=300)
    db_nonce = AgentRequestNonce(
        key_id=key_id,
        nonce_hash=nonce_hash,
        expires_at=nonce_expiry,
    )
    db.add(db_nonce)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise GatewayPipelineError(
            f"Replay attack detected: nonce '{nonce}' has already been processed.",
            code="REPLAY_ATTACK_DETECTED",
            status_code=401,
        ) from exc

    # -------------------------------------------------------------
    # Stage 5.5: Verifiable Agent Credential Verification (Step 22)
    # -------------------------------------------------------------
    presented_creds = envelope.get("credentials") or []
    dst_org_obj, dst_agent_obj = resolve_agent_and_org(db, target_org_id, target_agent_id)
    if dst_org_obj:
        target_policy = db.execute(
            select(TargetOrganizationPolicy).where(TargetOrganizationPolicy.organization_id == dst_org_obj.id)
        ).scalar_one_or_none()
        if target_policy and getattr(target_policy, "required_credential_types", None):
            for req_type in target_policy.required_credential_types:
                has_type = any(
                    isinstance(c, dict) and c.get("credential_type") == req_type
                    for c in presented_creds
                )
                if not has_type:
                    raise GatewayPipelineError(
                        f"Target organization requires presented credential of type '{req_type}'.",
                        code="REQUIRED_CREDENTIAL_MISSING",
                        status_code=403,
                    )

    for cred in presented_creds:
        if not isinstance(cred, dict):
            continue
        try:
            verify_agent_credential(
                db=db,
                credential=cred,
                expected_environment="production",
            )
        except CredentialVerificationError as c_err:
            db.add(SecurityEvent(
                organization_id=src_org_obj.id if src_org_obj else None,
                event_type=f"credential_verification_failed_{c_err.code.lower()}",
                severity="warning",
                description=f"Credential verification failed: {c_err.message}",
                details={"credential_id": cred.get("credential_id"), "code": c_err.code},
            ))
            db.commit()
            raise GatewayPipelineError(
                f"Credential verification failed: {c_err.message}",
                code=c_err.code,
                status_code=c_err.status_code,
            ) from c_err

        # Check Subject Binding
        cred_subj = cred.get("subject") or {}
        cred_agt = cred_subj.get("agent_id")
        if cred_agt not in (src_agent_obj.agent_identifier, str(src_agent_obj.id), src_agent_obj.name):
            db.add(SecurityEvent(
                organization_id=src_org_obj.id if src_org_obj else None,
                event_type="credential_subject_mismatch",
                severity="warning",
                description="Presented credential subject does not match source agent.",
                details={"credential_subject": cred_agt, "source_agent": src_agent_obj.agent_identifier},
            ))
            db.commit()
            raise GatewayPipelineError(
                f"Credential subject '{cred_agt}' does not match source agent '{src_agent_obj.agent_identifier}'.",
                code="CREDENTIAL_SUBJECT_INVALID",
                status_code=403,
            )

        # Check Organization Binding
        cred_org = cred_subj.get("organization_id")
        if src_org_obj and cred_org not in (src_org_obj.name, str(src_org_obj.id)):
            db.add(SecurityEvent(
                organization_id=src_org_obj.id if src_org_obj else None,
                event_type="credential_organization_mismatch",
                severity="warning",
                description="Presented credential organization does not match source organization.",
                details={"credential_org": cred_org, "source_org": src_org_obj.name},
            ))
            db.commit()
            raise GatewayPipelineError(
                f"Credential organization '{cred_org}' does not match source organization '{src_org_obj.name}'.",
                code="CREDENTIAL_CLAIM_INVALID",
                status_code=403,
            )

        # Check Capability Binding
        if cred.get("credential_type") == "AgentCapabilityCredential":
            claims_caps = (cred.get("claims") or {}).get("capabilities", [])
            if capability not in claims_caps:
                db.add(SecurityEvent(
                    organization_id=src_org_obj.id if src_org_obj else None,
                    event_type="credential_capability_mismatch",
                    severity="warning",
                    description=f"Credential does not attest to requested capability '{capability}'.",
                    details={"requested_capability": capability, "credential_capabilities": claims_caps},
                ))
                db.commit()
                raise GatewayPipelineError(
                    f"Presented capability credential does not attest to capability '{capability}'.",
                    code="CREDENTIAL_CAPABILITY_MISMATCH",
                    status_code=403,
                )

    # -------------------------------------------------------------
    # Stage 6 & 7: Cross-Organization Trust Check
    # -------------------------------------------------------------
    is_mock = is_sandbox_mock_agent(target_addr)
    if not is_mock and src_org_obj:
        dst_org_obj, dst_agent_obj = resolve_agent_and_org(db, target_org_id, target_agent_id)
        if dst_org_obj and dst_org_obj.id != src_org_obj.id:
            trust = db.scalar(
                select(OrganizationTrustRelationship).where(
                    OrganizationTrustRelationship.source_organization_id == src_org_obj.id,
                    OrganizationTrustRelationship.target_organization_id == dst_org_obj.id,
                )
            )
            if not trust or trust.status != TrustStatus.ACTIVE:
                raise GatewayPipelineError(
                    f"No active cross-organization trust relationship between '{src_org_obj.name}' and '{dst_org_obj.name}'.",
                    code="CROSS_ORG_TRUST_REQUIRED",
                    status_code=403,
                )

    # -------------------------------------------------------------
    # Stage 8: Capability Authorization & Risk Engine Scoring
    # -------------------------------------------------------------
    # Check if high-value risk threshold triggers approval
    amount_val = 0
    if isinstance(payload, dict):
        amount_val = payload.get("amount") or payload.get("price") or 0
        try:
            amount_val = float(amount_val)
        except (ValueError, TypeError):
            amount_val = 0

    requires_approval = False
    approval_reason = None
    if amount_val > 5000:
        requires_approval = True
        approval_reason = f"High monetary value ({amount_val} USD) exceeds autonomous limit of $5,000."
    elif capability.endswith(".admin") or capability.endswith(".delete"):
        requires_approval = True
        approval_reason = f"High-risk capability '{capability}' requires explicit multi-party approval."

    # -------------------------------------------------------------
    # Stage 9: Multi-Party Approval Hold
    # -------------------------------------------------------------
    # Save authoritative message record
    target_org_uuid: Optional[UUID] = None
    target_agt_uuid: Optional[UUID] = None
    if not is_mock:
        dst_org_obj, dst_agent_obj = resolve_agent_and_org(db, target_org_id, target_agent_id)
        if dst_org_obj:
            target_org_uuid = dst_org_obj.id
        if dst_agent_obj:
            target_agt_uuid = dst_agent_obj.id

    msg_record = ATPMessageRecord(
        message_id=message_id,
        atp_version="1.0",
        message_type=message_type,
        source_organization_id=src_org_obj.id if src_org_obj else src_agent_obj.organization_id,
        source_agent_id=src_agent_obj.id,
        target_organization_id=target_org_uuid,
        target_agent_id=target_agt_uuid,
        capability=capability,
        status="PENDING_APPROVAL" if requires_approval else ATPDeliveryStatus.PENDING.value,
        decision_reason=approval_reason,
        payload_summary=payload if isinstance(payload, dict) else {"data": payload},
    )
    # Set transient properties for router
    setattr(msg_record, "source_address", source_addr)
    setattr(msg_record, "target_address", target_addr)
    setattr(msg_record, "payload_sha256", payload_sha256)

    db.add(msg_record)
    db.commit()
    db.refresh(msg_record)

    if requires_approval:
        return {
            "protocol": PROTOCOL_VERSION,
            "message_id": message_id,
            "status": "PENDING_APPROVAL",
            "approval_required": True,
            "reason": approval_reason,
            "notice": "This message is held in Gateway staging and will NOT route to the target agent until approved.",
            "created_at": msg_record.created_at.isoformat(),
        }

    # -------------------------------------------------------------
    # Stage 10: Target Endpoint Resolution & SSRF Protection
    # -------------------------------------------------------------
    endpoint: Optional[AgentEndpoint] = None
    if not is_mock:
        dst_org_obj, dst_agent_obj = resolve_agent_and_org(db, target_org_id, target_agent_id)
        if dst_agent_obj:
            endpoint = db.execute(
                select(AgentEndpoint).where(
                    AgentEndpoint.agent_id == dst_agent_obj.id,
                    AgentEndpoint.status.in_([EndpointStatus.VERIFIED.value, EndpointStatus.PENDING.value]),
                )
            ).scalar_one_or_none()

    # -------------------------------------------------------------
    # Stage 11: Gateway Attestation & Outbound Delivery
    # -------------------------------------------------------------
    try:
        target_response = route_atp_message(
            db=db,
            message_record=msg_record,
            endpoint=endpoint,
            allow_private_ips=allow_private_ips,
            enforce_https=enforce_https,
        )
        return {
            "protocol": PROTOCOL_VERSION,
            "message_id": message_id,
            "status": "DELIVERED",
            "target": target_addr,
            "capability": capability,
            "attestation_id": msg_record.attestation_id,
            "response": target_response,
        }
    except ATPRoutingError as exc:
        raise GatewayPipelineError(
            f"Routing failed: {exc.message}",
            code="ROUTING_FAILED",
            status_code=exc.status_code,
            details=exc.details,
        ) from exc
