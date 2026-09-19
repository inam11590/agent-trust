"""ATP Message Router and Outbound Dispatcher (Step 21).

Handles delivery of authorized ATP messages to target agent endpoints:
- SSRF verification on destination URL
- Gateway Attestation header injection (X-ATP-Gateway-Attestation)
- Transient retry policy with exponential backoff
- Delivery recording (ATPMessageDelivery)
- Mock sandbox agent fallback/direct handling
- Response envelope parsing and validation
"""

from __future__ import annotations

from datetime import datetime, timezone
import time
from typing import Any, Dict, Optional, Tuple
from uuid import UUID

import httpx
from sqlalchemy.orm import Session

from app.models.agenttrust_protocol import (
    AgentEndpoint,
    ATPDeliveryStatus,
    ATPMessageDelivery,
    ATPMessageRecord,
)
from app.services.gateway_identity import create_gateway_attestation
from app.services.sandbox_mock_agents import (
    execute_sandbox_mock_agent,
    is_sandbox_mock_agent,
)
from app.services.ssrf_protection import SSRFValidationError, resolve_and_validate_endpoint_url


class ATPRoutingError(Exception):
    """Raised when routing to a target agent fails."""

    def __init__(self, message: str, status_code: int = 502, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


def route_atp_message(
    db: Session,
    message_record: ATPMessageRecord,
    endpoint: Optional[AgentEndpoint],
    allow_private_ips: bool = False,
    enforce_https: bool = True,
    timeout_seconds: float = 10.0,
    max_retries: int = 2,
) -> Dict[str, Any]:
    """
    Route an authorized ATP message to the target agent.
    If target is a sandbox mock agent, handles it synchronously.
    Otherwise, executes HTTP POST to target endpoint URL with Gateway attestation.
    """
    target_address = message_record.target_address
    capability = message_record.capability
    source_address = message_record.source_address
    message_id = message_record.message_id
    payload_sha256 = message_record.payload_sha256

    # 1. Check if target is a Sandbox Mock Agent
    if is_sandbox_mock_agent(target_address) or (endpoint and getattr(endpoint, "status", None) == "MOCK"):
        start_time = time.perf_counter()
        mock_response = execute_sandbox_mock_agent(
            target_address=target_address,
            capability=capability,
            payload=message_record.payload_summary or {},
            source_address=source_address,
            original_message_id=message_id,
        )
        latency_ms = int((time.perf_counter() - start_time) * 1000)

        # Record delivery
        delivery = ATPMessageDelivery(
            message_id=message_record.message_id,
            target_endpoint_id=endpoint.id if endpoint else None,
            attempt_count=1,
            status=ATPDeliveryStatus.DELIVERED.value,
            http_status=200,
            last_attempt_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            response_payload=mock_response.get("payload"),
        )
        db.add(delivery)
        message_record.status = ATPDeliveryStatus.DELIVERED.value
        message_record.decision_reason = "Delivered to Sandbox Mock Agent."
        message_record.completed_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(message_record)

        return mock_response

    # 2. External HTTP routing requires an active AgentEndpoint
    if not endpoint:
        raise ATPRoutingError(
            f"No registered or active endpoint found for target agent '{target_address}' and capability '{capability}'.",
            status_code=404,
            details={"target_address": target_address, "capability": capability},
        )

    # 3. SSRF Protection validation
    target_url = endpoint.endpoint_url
    try:
        validated_url, resolved_ips = resolve_and_validate_endpoint_url(
            target_url,
            allow_private_ips=allow_private_ips,
            enforce_https=enforce_https,
        )
    except SSRFValidationError as exc:
        message_record.status = ATPDeliveryStatus.FAILED.value
        message_record.decision_reason = f"SSRF_BLOCKED: {exc.message}"
        message_record.completed_at = datetime.now(timezone.utc)
        db.commit()
        raise ATPRoutingError(
            f"Target endpoint rejected by SSRF protection: {exc.message}",
            status_code=403,
            details={"code": exc.code, "target_url": target_url},
        ) from exc

    # 4. Generate Gateway Attestation
    attestation_token = create_gateway_attestation(
        source_address=source_address,
        target_address=target_address,
        capability=capability,
        message_id=message_id,
        payload_sha256=payload_sha256,
        ttl_seconds=60,
    )
    message_record.attestation_id = attestation_token[:64]

    # 5. Outbound request preparation
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "AgentTrust-Gateway/1.0",
        "X-ATP-Protocol": "ATP/1.0",
        "X-ATP-Message-ID": message_id,
        "X-ATP-Source": source_address,
        "X-ATP-Target": target_address,
        "X-ATP-Capability": capability,
        "X-ATP-Gateway-Attestation": attestation_token,
    }

    request_body = {
        "protocol": "ATP/1.0",
        "message_id": message_id,
        "message_type": message_record.message_type,
        "source": {
            "address": source_address,
        },
        "target": {
            "address": target_address,
        },
        "capability": capability,
        "payload": message_record.payload_summary,
        "payload_sha256": payload_sha256,
        "gateway_attestation": attestation_token,
    }

    # 6. Execute HTTP Dispatch with Exponential Backoff
    last_error: Optional[Exception] = None
    backoff_seconds = 0.1

    for attempt in range(1, max_retries + 2):
        start_time = time.perf_counter()
        delivery = ATPMessageDelivery(
            message_id=message_record.message_id,
            target_endpoint_id=endpoint.id,
            attempt_count=attempt,
            status=ATPDeliveryStatus.DELIVERING.value,
            last_attempt_at=datetime.now(timezone.utc),
        )
        db.add(delivery)
        db.commit()

        try:
            with httpx.Client(timeout=timeout_seconds, follow_redirects=False) as client:
                resp = client.post(target_url, json=request_body, headers=headers)
                delivery.http_status = resp.status_code

                if resp.status_code in (502, 503, 504) and attempt <= max_retries:
                    delivery.status = ATPDeliveryStatus.RETRYING.value
                    delivery.error_message = f"Transient HTTP {resp.status_code}"
                    db.commit()
                    time.sleep(backoff_seconds)
                    backoff_seconds *= 2
                    continue

                if resp.status_code >= 400:
                    delivery.status = ATPDeliveryStatus.FAILED.value
                    delivery.error_message = f"HTTP {resp.status_code}: {resp.text[:500]}"
                    delivery.completed_at = datetime.now(timezone.utc)
                    message_record.status = ATPDeliveryStatus.FAILED.value
                    message_record.decision_reason = f"Target error: HTTP {resp.status_code}"
                    message_record.completed_at = datetime.now(timezone.utc)
                    db.commit()
                    raise ATPRoutingError(
                        f"Target agent endpoint responded with status {resp.status_code}: {resp.text[:200]}",
                        status_code=resp.status_code,
                        details={"endpoint": target_url, "response": resp.text[:500]},
                    )

                # Successful delivery
                delivery.status = ATPDeliveryStatus.DELIVERED.value
                delivery.completed_at = datetime.now(timezone.utc)
                try:
                    resp_json = resp.json()
                    delivery.response_payload = resp_json.get("payload") if isinstance(resp_json, dict) else resp_json
                except Exception:
                    resp_json = {"raw_response": resp.text}

                message_record.status = ATPDeliveryStatus.DELIVERED.value
                message_record.decision_reason = "Successfully delivered to target endpoint."
                message_record.completed_at = datetime.now(timezone.utc)
                db.commit()
                db.refresh(message_record)
                return resp_json

        except httpx.RequestError as exc:
            delivery.status = ATPDeliveryStatus.RETRYING.value if attempt <= max_retries else ATPDeliveryStatus.FAILED.value
            delivery.error_message = f"Network error: {str(exc)}"
            if delivery.status == ATPDeliveryStatus.FAILED.value:
                delivery.completed_at = datetime.now(timezone.utc)
            db.commit()
            last_error = exc

            if attempt <= max_retries:
                time.sleep(backoff_seconds)
                backoff_seconds *= 2
                continue
            break

    # All attempts exhausted
    message_record.status = ATPDeliveryStatus.FAILED.value
    message_record.decision_reason = f"ENDPOINT_UNREACHABLE: {last_error}"
    message_record.completed_at = datetime.now(timezone.utc)
    db.commit()

    raise ATPRoutingError(
        f"Target endpoint '{target_url}' was unreachable after {max_retries + 1} attempts: {last_error}",
        status_code=504,
        details={"endpoint": target_url, "error": str(last_error)},
    )
