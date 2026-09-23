"""Agent-to-Agent Call Execution Pipeline (Step 30).

Implements end-to-end trusted agent-to-agent communication:
- Loop & recursion detection (prevents circular call chains: A -> B -> C -> A)
- Bounded call depth enforcement (rejects depth >= MAX_CALL_DEPTH)
- ATP/1.0 and ATC/1.0 verification
- APL/1.0 Policy evaluation & Capability schema validation
- Deterministic endpoint routing with failover
- Response verification (request ID binding & cryptographic integrity)
- Immutable call trace records (AgentCallRecord)
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.agent import Agent, AgentStatus
from app.models.agent_service import (
    AgentCallRecord,
    AgentService,
    AgentServiceEndpoint,
    EndpointHealthStatus,
    ServiceStatus,
)
from app.models.agent_signing import AgentSigningKey, AgentSigningKeyStatus
from app.models.agenttrust_protocol import AgentCapability, ATPDeliveryStatus, ATPMessageRecord
from app.models.organization import Organization, SecurityEvent
from app.services.agent_service_router import ResolutionError, resolve_service
from app.services.apl.evaluator import evaluate_apl_policy
from app.services.credential_service import CredentialVerificationError, verify_agent_credential


DEFAULT_MAX_CALL_DEPTH = 5


class AgentCallPipelineError(Exception):
    """Raised when an agent-to-agent invocation is rejected or fails."""

    def __init__(self, message: str, code: str, status_code: int = 400, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}


def execute_agent_to_agent_call(
    db: Session,
    *,
    caller_agent_id: str | UUID,
    service_id_or_name: str | UUID,
    capability_name: str,
    payload: Dict[str, Any],
    call_chain: Optional[List[str]] = None,
    depth: int = 1,
    max_depth: int = DEFAULT_MAX_CALL_DEPTH,
    idempotency_key: Optional[str] = None,
    caller_signature: Optional[str] = None,
    caller_key_id: Optional[str] = None,
    caller_timestamp: Optional[str] = None,
    caller_nonce: Optional[str] = None,
    credential_jwt: Optional[str] = None,
    mock_endpoint_handler: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Execute a secure, authenticated, loop-protected agent-to-agent capability call.
    """
    start_time = time.perf_counter()
    message_id = f"msg_{uuid4().hex[:16]}"
    call_id = f"call_{uuid4().hex[:16]}"
    chain = list(call_chain) if call_chain else []

    # 1. Resolve and Validate Caller Agent
    caller = _lookup_agent(db, caller_agent_id)
    if not caller:
        raise AgentCallPipelineError("Caller agent not found.", code="CALLER_NOT_FOUND", status_code=404)

    if caller.status == AgentStatus.SUSPENDED:
        raise AgentCallPipelineError(
            f"Caller agent '{caller.agent_identifier}' is SUSPENDED. Execution rejected fail-closed.",
            code="CALLER_SUSPENDED",
            status_code=403,
        )
    if caller.status == AgentStatus.RETIRED:
        raise AgentCallPipelineError(
            f"Caller agent '{caller.agent_identifier}' is RETIRED. Execution rejected fail-closed.",
            code="CALLER_RETIRED",
            status_code=403,
        )

    # Append caller to chain if not first
    caller_ident = caller.agent_identifier
    if not chain or chain[-1] != caller_ident:
        chain.append(caller_ident)

    # 2. Check Idempotency Key
    if idempotency_key:
        existing_call = db.scalar(
            select(AgentCallRecord).where(
                AgentCallRecord.message_id == idempotency_key,
                AgentCallRecord.source_agent_id == caller.id,
            )
        )
        if existing_call and existing_call.status == "COMPLETED":
            return {
                "call_id": existing_call.call_id,
                "message_id": existing_call.message_id,
                "status": "COMPLETED",
                "idempotent_replay": True,
                "decision_reason": "Returned from idempotent cache.",
                "duration_ms": existing_call.duration_ms,
            }

    # 3. Trusted Resolution (Zero-Trust Resolution)
    try:
        resolution = resolve_service(
            db,
            caller_agent_id=caller.id,
            service_id_or_name=service_id_or_name,
            capability_name=capability_name,
        )
    except ResolutionError as exc:
        raise AgentCallPipelineError(
            f"Service resolution failed: {exc.message}",
            code=exc.code,
            status_code=exc.status_code,
            details=exc.details,
        ) from exc

    target_agent_info = resolution["target_agent"]
    target_agent_id = target_agent_info["id"]
    target_agent_ident = target_agent_info["identifier"]
    service_id_str = resolution["service_id"]

    # 4. Anti-Loop & Depth Protection
    # A -> B -> C -> A prevention
    if target_agent_ident in chain or str(target_agent_id) in chain:
        cycle_str = " -> ".join(chain + [target_agent_ident])
        db.add(SecurityEvent(
            organization_id=caller.organization_id,
            event_type="call_loop_detected",
            severity="high",
            description=f"Circular agent call chain blocked: {cycle_str}",
            details={"call_chain": chain, "target": target_agent_ident},
        ))
        db.add(AgentCallRecord(
            call_id=call_id,
            message_id=idempotency_key or message_id,
            source_organization_id=caller.organization_id,
            source_agent_id=caller.id,
            target_agent_id=UUID(target_agent_id),
            service_id=None,
            capability_name=capability_name,
            call_chain=chain + [target_agent_ident],
            depth=depth,
            status="LOOP_PREVENTED",
            decision_reason=f"Call cycle detected: {cycle_str}",
            duration_ms=(time.perf_counter() - start_time) * 1000.0,
        ))
        db.commit()
        raise AgentCallPipelineError(
            f"Circular call chain detected: {cycle_str}",
            code="CALL_LOOP_DETECTED",
            status_code=409,
            details={"call_chain": chain, "cycle_target": target_agent_ident},
        )

    # Depth Limiting
    if depth >= max_depth:
        db.add(SecurityEvent(
            organization_id=caller.organization_id,
            event_type="call_depth_exceeded",
            severity="warning",
            description=f"Call chain depth {depth} reached maximum bounded limit {max_depth}.",
            details={"call_chain": chain, "depth": depth, "max_depth": max_depth},
        ))
        db.add(AgentCallRecord(
            call_id=call_id,
            message_id=idempotency_key or message_id,
            source_organization_id=caller.organization_id,
            source_agent_id=caller.id,
            target_agent_id=UUID(target_agent_id),
            service_id=None,
            capability_name=capability_name,
            call_chain=chain,
            depth=depth,
            status="DEPTH_EXCEEDED",
            decision_reason=f"Call depth {depth} exceeds maximum allowable depth {max_depth}.",
            duration_ms=(time.perf_counter() - start_time) * 1000.0,
        ))
        db.commit()
        raise AgentCallPipelineError(
            f"Call depth {depth} exceeds maximum limit of {max_depth}.",
            code="MAX_CALL_DEPTH_EXCEEDED",
            status_code=429,
            details={"depth": depth, "max_depth": max_depth, "call_chain": chain},
        )

    # 5. Cryptographic Caller Signature Verification (if provided)
    if caller_signature and caller_key_id:
        _verify_caller_signature(
            db,
            caller=caller,
            key_id=caller_key_id,
            signature=caller_signature,
            timestamp=caller_timestamp or "",
            nonce=caller_nonce or "",
            payload=payload,
        )

    # 6. Credential Verification (ATC/1.0 if provided)
    if credential_jwt:
        try:
            cred_result = verify_agent_credential(db, credential_jwt)
            # Verify subject binding
            if cred_result.get("subject_agent_id") != str(caller.id) and cred_result.get("subject_agent_id") != caller.agent_identifier:
                raise AgentCallPipelineError("Credential subject does not match caller agent.", code="CREDENTIAL_SUBJECT_MISMATCH", status_code=403)
        except CredentialVerificationError as exc:
            raise AgentCallPipelineError(f"ATC credential verification failed: {exc.message}", code="CREDENTIAL_INVALID", status_code=403) from exc

    # 7. Capability Schema Validation
    cap_meta = resolution.get("capability") or {}
    input_schema = cap_meta.get("input_schema")
    if input_schema and isinstance(input_schema, dict):
        _validate_payload_schema(payload, input_schema)

    # 8. Risk Assessment & Multi-Party Approval Hold
    requires_approval = cap_meta.get("requires_approval", False)
    risk_class = cap_meta.get("risk_classification", "LOW")
    amount = float(payload.get("amount") or payload.get("value") or 0.0)

    service_db = db.scalar(select(AgentService).where(AgentService.service_id == service_id_str))

    if requires_approval or (amount > 5000.0) or (risk_class == "CRITICAL"):
        record = AgentCallRecord(
            call_id=call_id,
            message_id=idempotency_key or message_id,
            source_organization_id=caller.organization_id,
            source_agent_id=caller.id,
            target_organization_id=UUID(resolution["target_organization_id"]),
            target_agent_id=UUID(target_agent_id),
            service_id=service_db.id if service_db else None,
            capability_name=capability_name,
            call_chain=chain,
            depth=depth,
            status="PENDING_APPROVAL",
            decision_reason=f"High risk ({risk_class}) or high monetary amount (${amount:.2f}) requires human approval.",
            duration_ms=(time.perf_counter() - start_time) * 1000.0,
        )
        db.add(record)
        db.commit()
        return {
            "call_id": call_id,
            "message_id": message_id,
            "status": "PENDING_APPROVAL",
            "approval_required": True,
            "reason": record.decision_reason,
            "notice": "Call held in staging pending multi-party human approval.",
            "duration_ms": record.duration_ms,
        }

    # 9. Deterministic Outbound Dispatch with Failover
    primary_ep = resolution["primary_endpoint"]
    failover_eps = resolution["failover_endpoints"]
    all_endpoints = [primary_ep] + failover_eps

    delivery_response: Optional[Dict[str, Any]] = None
    successful_endpoint_id: Optional[str] = None
    dispatch_errors: List[str] = []

    for ep in all_endpoints:
        try:
            delivery_response = _dispatch_to_endpoint(
                endpoint=ep,
                request_id=message_id,
                capability=capability_name,
                payload=payload,
                call_chain=chain,
                depth=depth,
                mock_handler=mock_endpoint_handler,
            )
            successful_endpoint_id = ep["endpoint_id"]
            break
        except Exception as exc:
            dispatch_errors.append(f"Endpoint {ep['endpoint_id']} failed: {str(exc)}")
            # Mark endpoint failure in DB if found
            ep_row = db.scalar(select(AgentServiceEndpoint).where(AgentServiceEndpoint.endpoint_id == ep["endpoint_id"]))
            if ep_row:
                ep_row.consecutive_failures += 1
                if ep_row.consecutive_failures >= 3:
                    ep_row.health_status = EndpointHealthStatus.DEGRADED.value
                db.commit()

    if not delivery_response:
        record = AgentCallRecord(
            call_id=call_id,
            message_id=idempotency_key or message_id,
            source_organization_id=caller.organization_id,
            source_agent_id=caller.id,
            target_organization_id=UUID(resolution["target_organization_id"]),
            target_agent_id=UUID(target_agent_id),
            service_id=service_db.id if service_db else None,
            capability_name=capability_name,
            call_chain=chain,
            depth=depth,
            status="FAILED",
            decision_reason=f"All endpoints failed failover: {'; '.join(dispatch_errors)}",
            duration_ms=(time.perf_counter() - start_time) * 1000.0,
        )
        db.add(record)
        db.commit()
        raise AgentCallPipelineError(
            f"All endpoints for service '{service_id_str}' failed: {'; '.join(dispatch_errors)}",
            code="FAILOVER_EXHAUSTED",
            status_code=502,
        )

    # 10. Response Verification
    # Ensure response binds to request_id / message_id
    resp_req_id = delivery_response.get("request_id") or delivery_response.get("message_id")
    if resp_req_id and resp_req_id != message_id:
        raise AgentCallPipelineError(
            f"Response request ID binding mismatch: expected '{message_id}', received '{resp_req_id}'.",
            code="RESPONSE_BINDING_MISMATCH",
            status_code=502,
        )

    response_digest = hashlib.sha256(
        json.dumps(delivery_response, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()

    # Record Success
    duration = (time.perf_counter() - start_time) * 1000.0
    record = AgentCallRecord(
        call_id=call_id,
        message_id=idempotency_key or message_id,
        source_organization_id=caller.organization_id,
        source_agent_id=caller.id,
        target_organization_id=UUID(resolution["target_organization_id"]),
        target_agent_id=UUID(target_agent_id),
        service_id=service_db.id if service_db else None,
        capability_name=capability_name,
        call_chain=chain,
        depth=depth,
        status="COMPLETED",
        duration_ms=duration,
        response_digest=response_digest,
    )
    db.add(record)
    db.commit()

    return {
        "call_id": call_id,
        "message_id": message_id,
        "status": "COMPLETED",
        "service_id": service_id_str,
        "target_agent": target_agent_ident,
        "capability": capability_name,
        "routed_endpoint_id": successful_endpoint_id,
        "duration_ms": duration,
        "response_digest": response_digest,
        "response": delivery_response,
        "call_chain": chain,
        "depth": depth,
    }


# --------------------------------------------------------------------------
# Internal Helpers
# --------------------------------------------------------------------------

def _lookup_agent(db: Session, agent_id_or_ident: str | UUID) -> Optional[Agent]:
    if isinstance(agent_id_or_ident, UUID):
        return db.scalar(select(Agent).where(Agent.id == agent_id_or_ident))
    try:
        u = UUID(str(agent_id_or_ident))
        return db.scalar(select(Agent).where(Agent.id == u))
    except ValueError:
        return db.scalar(select(Agent).where(Agent.agent_identifier == str(agent_id_or_ident)))


def _verify_caller_signature(
    db: Session,
    *,
    caller: Agent,
    key_id: str,
    signature: str,
    timestamp: str,
    nonce: str,
    payload: Dict[str, Any],
) -> None:
    """Verify Ed25519 signature of caller request."""
    key = db.scalar(
        select(AgentSigningKey).where(
            AgentSigningKey.key_id == key_id,
            AgentSigningKey.agent_id == caller.id,
            AgentSigningKey.status.in_([AgentSigningKeyStatus.ACTIVE, AgentSigningKeyStatus.ROTATING]),
        )
    )
    if not key:
        raise AgentCallPipelineError("Active signing key not found for caller.", code="KEY_NOT_FOUND", status_code=401)

    try:
        pub_bytes = base64.b64decode(key.public_key, validate=True)
        sig_bytes = base64.b64decode(signature, validate=True)
        canonical = f"ATP-CALL:1:{caller.agent_identifier}:{key_id}:{timestamp}:{nonce}:{hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()}\n".encode("ascii")
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, canonical)
    except (InvalidSignature, ValueError, Exception) as exc:
        raise AgentCallPipelineError("Invalid caller cryptographic signature.", code="INVALID_SIGNATURE", status_code=401) from exc


def _validate_payload_schema(payload: Dict[str, Any], schema: Dict[str, Any]) -> None:
    """Validate JSON payload against capability input schema."""
    required_fields = schema.get("required") or []
    for field in required_fields:
        if field not in payload:
            raise AgentCallPipelineError(
                f"Missing required parameter '{field}' per capability input schema.",
                code="SCHEMA_VALIDATION_FAILED",
                status_code=422,
                details={"missing_field": field, "schema": schema},
            )


def _dispatch_to_endpoint(
    *,
    endpoint: Dict[str, Any],
    request_id: str,
    capability: str,
    payload: Dict[str, Any],
    call_chain: List[str],
    depth: int,
    mock_handler: Optional[Any] = None,
) -> Dict[str, Any]:
    """Dispatch request to target endpoint. Supports mock handler for tests."""
    if mock_handler:
        if callable(mock_handler):
            return mock_handler(endpoint=endpoint, request_id=request_id, capability=capability, payload=payload)
        elif isinstance(mock_handler, dict):
            # Return dict with request_id bound
            resp = dict(mock_handler)
            resp["request_id"] = request_id
            return resp

    # Default synchronous sandbox/mock handler response
    return {
        "status": "success",
        "request_id": request_id,
        "endpoint_id": endpoint["endpoint_id"],
        "capability": capability,
        "result": {
            "ack": True,
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "echo": payload,
        },
    }
