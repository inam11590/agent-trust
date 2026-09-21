"""Enterprise SIEM & Webhook Export engine with retry, SSRF validation, and dead-letter queue."""

from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
from typing import Any
from uuid import UUID, uuid4

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.secrets import get_secret_provider
from app.models import SecurityEvent, SecurityExportDeadLetter, SecurityExportDestination
from app.services.ssrf_protection import SSRFValidationError, resolve_and_validate_endpoint_url

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "agenttrust.security.event/v1"


def format_event_as_json(event: SecurityEvent) -> dict[str, Any]:
    """Serialize normalized security event into the stable v1 export schema."""
    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": event.event_id or f"evt_{event.id.hex}",
        "timestamp": event.created_at.isoformat() if event.created_at else datetime.now(timezone.utc).isoformat(),
        "severity": event.severity,
        "category": event.category or "SYSTEM",
        "event_type": event.event_type,
        "description": event.description,
        "organization_reference": str(event.organization_id) if event.organization_id else None,
        "agent_reference": str(event.agent_id) if event.agent_id else None,
        "gateway_reference": str(event.gateway_id) if event.gateway_id else None,
        "credential_reference": str(event.credential_id) if event.credential_id else None,
        "request_id": event.request_id,
        "trace_id": event.trace_id,
        "correlation_id": event.correlation_id,
        "actor": {
            "type": event.actor_type,
            "id": event.actor_id,
        },
        "target": {
            "type": event.target_type,
            "id": event.target_id,
        },
        "action": event.action,
        "decision": event.decision,
        "risk_level": event.risk_level,
        "region": event.region,
        "environment": event.environment,
        "metadata": event.details or {},
    }


def format_event_as_syslog(event: SecurityEvent) -> str:
    """RFC 5424 Syslog foundation format."""
    pri = 134 if event.severity in ("HIGH", "CRITICAL") else 134
    ts = event.created_at.isoformat() if event.created_at else datetime.now(timezone.utc).isoformat()
    app = "AgentTrust"
    proc_id = "-"
    msg_id = event.event_type
    sd = f'[agenttrust@48124 event_id="{event.event_id}" org="{event.organization_id}" category="{event.category}"]'
    msg = json.dumps(event.details or {})
    return f"<{pri}>1 {ts} localhost {app} {proc_id} {msg_id} {sd} {msg}"


def format_event_as_cef(event: SecurityEvent) -> str:
    """ArcSight Common Event Format (CEF) foundation."""
    severity_map = {"INFO": "1", "LOW": "3", "MEDIUM": "5", "HIGH": "8", "CRITICAL": "10"}
    sev = severity_map.get(event.severity.upper(), "5")
    ext_pairs = [
        f"eventId={event.event_id}",
        f"cat={event.category}",
        f"act={event.action}",
        f"outcome={event.decision or 'NONE'}",
        f"cs1={event.correlation_id or '-'}",
        f"cs1Label=CorrelationID",
    ]
    ext = " ".join(ext_pairs)
    return f"CEF:0|AgentTrust|AgentTrust|1.0|{event.event_type}|{event.description or event.event_type}|{sev}|{ext}"


def sign_webhook_payload(payload_bytes: bytes, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()


def deliver_export_payload(
    dest: SecurityExportDestination,
    payload: dict[str, Any],
) -> tuple[bool, str | None]:
    """Deliver exported payload to HTTP destination with SSRF protection."""
    try:
        resolve_and_validate_endpoint_url(dest.endpoint_url, allow_private_ips=False, enforce_https=False)
    except SSRFValidationError as err:
        return False, f"SSRF_PROTECTION_BLOCKED: {str(err)}"

    secret_value = ""
    if dest.secret_ref:
        provider = get_secret_provider()
        secret_value = provider.get_secret(dest.secret_ref) or ""

    body_bytes = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "AgentTrust-Security-Exporter/1.0",
        "X-AgentTrust-Event-Id": payload.get("event_id", ""),
        "X-AgentTrust-Schema": SCHEMA_VERSION,
    }

    if dest.destination_type.upper() == "WEBHOOK" and secret_value:
        ts = str(int(datetime.now(timezone.utc).timestamp()))
        sig = sign_webhook_payload(f"{ts}.".encode("utf-8") + body_bytes, secret_value)
        headers["X-AgentTrust-Timestamp"] = ts
        headers["X-AgentTrust-Signature"] = f"sha256={sig}"

    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(dest.endpoint_url, content=body_bytes, headers=headers)
            if 200 <= resp.status_code < 300:
                return True, None
            return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as exc:
        return False, f"Network error: {str(exc)}"


def export_event_to_siem_destinations(db: Session, event: SecurityEvent) -> None:
    """Non-blocking export to all active destinations configured for the organization."""
    if not event.organization_id:
        return

    destinations = list(db.scalars(
        select(SecurityExportDestination)
        .where(
            SecurityExportDestination.organization_id == event.organization_id,
            SecurityExportDestination.enabled == True,
        )
    ))

    if not destinations:
        return

    payload = format_event_as_json(event)
    now = datetime.now(timezone.utc)

    for dest in destinations:
        severity_ranks = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        min_rank = severity_ranks.get(dest.min_severity.upper(), 0)
        event_rank = severity_ranks.get(event.severity.upper(), 0)
        if event_rank < min_rank:
            continue

        if dest.categories and event.category not in dest.categories:
            continue

        success, err = deliver_export_payload(dest, payload)
        if success:
            dest.last_export_at = now
            dest.consecutive_failures = 0
            dest.last_error = None
            dest.status = "HEALTHY"
        else:
            dest.consecutive_failures += 1
            dest.last_error = err
            if dest.consecutive_failures >= 5:
                dest.status = "FAILING"
                dead_letter = SecurityExportDeadLetter(
                    id=uuid4(),
                    organization_id=event.organization_id,
                    destination_id=dest.destination_id,
                    event_id=event.event_id or f"evt_{event.id.hex}",
                    event_payload=payload,
                    error_message=err or "Max retries exceeded",
                    attempts=dest.consecutive_failures,
                )
                db.add(dead_letter)

    try:
        db.commit()
    except Exception:
        db.rollback()
