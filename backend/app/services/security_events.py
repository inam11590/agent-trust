"""Enterprise Unified Security Event service: Append-only audit & security event ingestion."""

from datetime import datetime, timezone
import os
import uuid
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.observability import (
    correlation_id_context,
    metrics,
    redact_secrets,
    request_id_context,
    trace_id_context,
)
from app.models import SecurityEvent


def generate_event_id() -> str:
    """Generate collision-safe event identifier: evt_<hex>"""
    return f"evt_{uuid.uuid4().hex}"


def infer_event_category(event_type: str) -> str:
    t = event_type.lower()
    if "replay" in t:
        return "REPLAY"
    if "cred" in t:
        return "CREDENTIAL"
    if "trust" in t:
        return "TRUST"
    if "delegat" in t:
        return "DELEGATION"
    if "gateway" in t:
        return "GATEWAY"
    if "key" in t or "signing" in t or "signature" in t:
        return "AUTHORIZATION"
    if "permission" in t or "authorization" in t:
        return "AUTHORIZATION"
    if "mfa" in t or "login" in t or "session" in t or "auth" in t:
        return "AUTHENTICATION"
    if "approval" in t:
        return "APPROVAL"
    if "admin" in t or "role" in t or "policy" in t:
        return "ADMIN"
    if "agent" in t:
        return "AGENT"
    if "supply" in t or "sbom" in t:
        return "SUPPLY_CHAIN"
    return "SYSTEM"


def sanitize_event_details(details: dict | None) -> dict:
    if not details:
        return {}
    sanitized = {}
    for k, v in details.items():
        k_lower = str(k).lower()
        if any(secret_key in k_lower for secret_key in ("password", "secret", "private_key", "token", "api_key")):
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, str):
            sanitized[k] = redact_secrets(v)
        elif isinstance(v, dict):
            sanitized[k] = sanitize_event_details(v)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_event_details(item) if isinstance(item, dict)
                else (redact_secrets(item) if isinstance(item, str) else item)
                for item in v
            ]
        else:
            sanitized[k] = v
    return sanitized


def record_security_event(
    db: Session,
    actor_user_id: UUID | None = None,
    event_type: str = "security_event",
    *,
    organization_id: UUID | None = None,
    target_user_id: UUID | None = None,
    description: str | None = None,
    severity: str = "info",
    details: dict | None = None,
    commit: bool = True,
    # Step 26 Enterprise Unified Event fields
    event_id: str | None = None,
    category: str | None = None,
    source_type: str | None = None,
    source_id: str | None = None,
    agent_id: UUID | None = None,
    gateway_id: UUID | None = None,
    credential_id: UUID | None = None,
    request_id: str | None = None,
    trace_id: str | None = None,
    correlation_id: str | None = None,
    actor_type: str | None = None,
    actor_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    action: str | None = None,
    decision: str | None = None,
    risk_level: str | None = None,
    region: str | None = None,
    environment: str | None = None,
) -> SecurityEvent:
    eff_event_id = event_id or generate_event_id()
    eff_category = category or infer_event_category(event_type)
    eff_request_id = request_id or (request_id_context.get() if request_id_context.get() != "-" else None)
    eff_trace_id = trace_id or (trace_id_context.get() if trace_id_context.get() != "-" else None)
    eff_correlation_id = correlation_id or (correlation_id_context.get() if correlation_id_context.get() != "-" else None)
    eff_env = environment or os.getenv("ENVIRONMENT", "production")
    safe_details = sanitize_event_details(details)

    event = SecurityEvent(
        id=uuid.uuid4(),
        event_id=eff_event_id,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        target_user_id=target_user_id,
        event_type=event_type,
        category=eff_category,
        severity=severity.upper() if severity else "INFO",
        description=description,
        source_type=source_type,
        source_id=source_id,
        agent_id=agent_id,
        gateway_id=gateway_id,
        credential_id=credential_id,
        request_id=eff_request_id,
        trace_id=eff_trace_id,
        correlation_id=eff_correlation_id,
        actor_type=actor_type or ("USER" if actor_user_id else ("AGENT" if agent_id else "SYSTEM")),
        actor_id=actor_id or (str(actor_user_id) if actor_user_id else (str(agent_id) if agent_id else None)),
        target_type=target_type,
        target_id=target_id,
        action=action or event_type,
        decision=decision,
        risk_level=risk_level,
        region=region,
        environment=eff_env,
        details=safe_details,
    )
    db.add(event)

    # Update SOC metrics
    ev_lower = event_type.lower()
    if "replay" in ev_lower:
        metrics.record_soc("replay_detected_total")
    if "signature" in ev_lower and ("fail" in ev_lower or "invalid" in ev_lower):
        metrics.record_soc("invalid_signature_total")
    if "cred" in ev_lower and ("fail" in ev_lower or "invalid" in ev_lower or "revoked" in ev_lower):
        metrics.record_soc("credential_failure_total")
    if "trust_violation" in ev_lower or "unauthorized_cross_org" in ev_lower:
        metrics.record_soc("trust_violation_total")
    if "gateway" in ev_lower and ("auth" in ev_lower or "fail" in ev_lower):
        metrics.record_soc("gateway_auth_failure_total")

    if commit:
        db.commit()
        db.refresh(event)

    # Run detection rules & export asynchronously / safely
    try:
        from app.services.soc_service import evaluate_detection_rules_for_event
        evaluate_detection_rules_for_event(db, event)
    except Exception:
        pass

    try:
        from app.services.siem_exporter import export_event_to_siem_destinations
        export_event_to_siem_destinations(db, event)
    except Exception:
        pass

    return event


def list_security_events(db: Session, organization_id: UUID, limit: int = 100) -> list[SecurityEvent]:
    return list(db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.organization_id == organization_id)
        .order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc())
        .limit(limit)
    ))
