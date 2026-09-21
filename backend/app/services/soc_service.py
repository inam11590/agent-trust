"""Enterprise Security Operations Center (SOC) service: Rules, Alerts, Triage, Profiles."""

from datetime import datetime, timedelta, timezone
import hashlib
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.observability import metrics
from app.models import (
    Agent,
    DetectionRule,
    EnterpriseGateway,
    Organization,
    SecurityAlert,
    SecurityEvent,
)

BUILTIN_RULES: list[dict[str, Any]] = [
    {
        "rule_id": "rule_replay_burst",
        "name": "Replay Attack Burst",
        "description": "Repeated nonce reuse or expired timestamp replay detected for an agent or source.",
        "event_type": "agent_replay_detected",
        "category": "REPLAY",
        "conditions": {},
        "threshold": 3,
        "window_seconds": 300,
        "severity": "HIGH",
    },
    {
        "rule_id": "rule_invalid_sig_burst",
        "name": "Repeated Invalid Signatures",
        "description": "Cryptographic signature verification failed repeatedly.",
        "event_type": "agent_signature_failed",
        "category": "AUTHORIZATION",
        "conditions": {},
        "threshold": 3,
        "window_seconds": 300,
        "severity": "HIGH",
    },
    {
        "rule_id": "rule_revoked_cred_use",
        "name": "Revoked Credential Usage",
        "description": "Attempt to access protected resources using an explicitly revoked credential.",
        "event_type": "credential_used_after_revocation",
        "category": "CREDENTIAL",
        "conditions": {},
        "threshold": 1,
        "window_seconds": 60,
        "severity": "HIGH",
    },
    {
        "rule_id": "rule_compromised_key_use",
        "name": "Compromised Key Usage",
        "description": "Critical security event: request signed by a cryptographic key marked COMPROMISED.",
        "event_type": "compromised_key_used",
        "category": "AUTHORIZATION",
        "conditions": {},
        "threshold": 1,
        "window_seconds": 60,
        "severity": "CRITICAL",
    },
    {
        "rule_id": "rule_trust_violation",
        "name": "Trust Relationship Violation",
        "description": "Cross-organization request rejected due to missing or revoked trust agreement.",
        "event_type": "trust_violation",
        "category": "TRUST",
        "conditions": {},
        "threshold": 2,
        "window_seconds": 300,
        "severity": "HIGH",
    },
    {
        "rule_id": "rule_delegation_abuse",
        "name": "Delegation Chain Abuse",
        "description": "Repeated delegation verification failures or over-scoped hops.",
        "event_type": "delegation_rejected",
        "category": "DELEGATION",
        "conditions": {},
        "threshold": 3,
        "window_seconds": 300,
        "severity": "HIGH",
    },
    {
        "rule_id": "rule_gateway_auth_failure",
        "name": "Gateway Authentication Failures",
        "description": "Repeated authentication failures from an Enterprise Gateway.",
        "event_type": "gateway_authentication_failed",
        "category": "GATEWAY",
        "conditions": {},
        "threshold": 3,
        "window_seconds": 300,
        "severity": "HIGH",
    },
    {
        "rule_id": "rule_gateway_offline",
        "name": "Gateway Unexpectedly Offline",
        "description": "Enterprise Gateway heartbeat missing beyond maximum offline threshold.",
        "event_type": "gateway_offline",
        "category": "GATEWAY",
        "conditions": {},
        "threshold": 1,
        "window_seconds": 60,
        "severity": "HIGH",
    },
    {
        "rule_id": "rule_config_rollback",
        "name": "Gateway Config Rollback Attempt",
        "description": "Gateway presented stale or rolled back configuration version.",
        "event_type": "config_rollback_rejected",
        "category": "GATEWAY",
        "conditions": {},
        "threshold": 1,
        "window_seconds": 60,
        "severity": "HIGH",
    },
    {
        "rule_id": "rule_admin_sec_change",
        "name": "Admin Security Configuration Change",
        "description": "Administrative changes to organization security settings, roles, or MFA policies.",
        "event_type": "admin_security_change",
        "category": "ADMIN",
        "conditions": {},
        "threshold": 1,
        "window_seconds": 60,
        "severity": "MEDIUM",
    },
    {
        "rule_id": "rule_mfa_failure",
        "name": "Repeated MFA Challenge Failures",
        "description": "Multiple failed two-factor authentication attempts for user account.",
        "event_type": "mfa_failure",
        "category": "AUTHENTICATION",
        "conditions": {},
        "threshold": 5,
        "window_seconds": 300,
        "severity": "MEDIUM",
    },
    {
        "rule_id": "rule_production_insecure_config",
        "name": "Insecure Production Config Attempt",
        "description": "Attempt to configure insecure settings in production environment.",
        "event_type": "production_insecure_config_blocked",
        "category": "SUPPLY_CHAIN",
        "conditions": {},
        "threshold": 1,
        "window_seconds": 60,
        "severity": "CRITICAL",
    },
]


def ensure_builtin_rules(db: Session) -> None:
    """Seed default detection rules if not already present."""
    for item in BUILTIN_RULES:
        existing = db.scalar(select(DetectionRule).where(DetectionRule.rule_id == item["rule_id"]))
        if not existing:
            rule = DetectionRule(
                id=uuid4(),
                rule_id=item["rule_id"],
                organization_id=None,
                name=item["name"],
                description=item["description"],
                event_type=item["event_type"],
                category=item["category"],
                conditions=item["conditions"],
                threshold=item["threshold"],
                window_seconds=item["window_seconds"],
                severity=item["severity"],
                enabled=True,
            )
            db.add(rule)
    try:
        db.commit()
    except Exception:
        db.rollback()


def compute_alert_fingerprint(org_id: UUID, rule_id: str, target: str | None = None) -> str:
    target_str = target or ""
    raw = f"{str(org_id)}:{rule_id}:{target_str}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def evaluate_detection_rules_for_event(db: Session, event: SecurityEvent) -> list[SecurityAlert]:
    """Declaratively check detection rules for an event and open or update alerts."""
    if not event.organization_id:
        return []

    stmt = (
        select(DetectionRule)
        .where(
            DetectionRule.enabled == True,
            (DetectionRule.organization_id == event.organization_id) | (DetectionRule.organization_id.is_(None)),
        )
    )
    rules = list(db.scalars(stmt))
    generated_alerts = []

    for rule in rules:
        if rule.event_type and rule.event_type != event.event_type:
            continue
        if rule.category and event.category and rule.category.upper() != event.category.upper():
            continue

        matched_conditions = True
        if rule.conditions:
            for k, expected_v in rule.conditions.items():
                actual_v = getattr(event, k, None) or (event.details.get(k) if event.details else None)
                if str(actual_v) != str(expected_v):
                    matched_conditions = False
                    break
        if not matched_conditions:
            continue

        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=rule.window_seconds)

        count_stmt = (
            select(func.count(SecurityEvent.id))
            .where(
                SecurityEvent.organization_id == event.organization_id,
                SecurityEvent.event_type == event.event_type,
                SecurityEvent.created_at >= window_start,
            )
        )
        if event.agent_id:
            count_stmt = count_stmt.where(SecurityEvent.agent_id == event.agent_id)
        elif event.gateway_id:
            count_stmt = count_stmt.where(SecurityEvent.gateway_id == event.gateway_id)

        event_count = db.scalar(count_stmt) or 1

        if event_count >= rule.threshold:
            target_ref = str(event.agent_id or event.gateway_id or event.target_id or "")
            fingerprint = compute_alert_fingerprint(event.organization_id, rule.rule_id, target_ref)

            existing_alert = db.scalar(
                select(SecurityAlert)
                .where(
                    SecurityAlert.organization_id == event.organization_id,
                    SecurityAlert.fingerprint == fingerprint,
                    SecurityAlert.status.in_(["OPEN", "ACKNOWLEDGED", "INVESTIGATING"]),
                )
            )

            if existing_alert:
                existing_alert.event_count += 1
                existing_alert.last_seen_at = now
                existing_alert.metadata_json = {
                    **(existing_alert.metadata_json or {}),
                    "last_event_id": event.event_id,
                }
                generated_alerts.append(existing_alert)
            else:
                new_alert = SecurityAlert(
                    id=uuid4(),
                    alert_id=f"alt_{uuid4().hex[:16]}",
                    organization_id=event.organization_id,
                    rule_id=rule.rule_id,
                    fingerprint=fingerprint,
                    severity=rule.severity,
                    status="OPEN",
                    title=f"{rule.name}: {event.event_type}",
                    description=f"{rule.description} (Triggered by event {event.event_id})",
                    first_seen_at=now,
                    last_seen_at=now,
                    event_count=1,
                    metadata_json={
                        "agent_id": str(event.agent_id) if event.agent_id else None,
                        "gateway_id": str(event.gateway_id) if event.gateway_id else None,
                        "target_id": str(event.target_id) if event.target_id else None,
                        "initial_event_id": event.event_id,
                    },
                )
                db.add(new_alert)
                generated_alerts.append(new_alert)

                if rule.severity in ("HIGH", "CRITICAL"):
                    try:
                        from app.services.notifications import create_notification
                        create_notification(
                            db=db,
                            organization_id=event.organization_id,
                            title=f"Security Alert: {rule.name}",
                            message=f"{rule.description} (Severity: {rule.severity})",
                            priority=rule.severity.lower(),
                        )
                    except Exception:
                        pass

    if generated_alerts:
        try:
            db.commit()
            open_count = db.scalar(
                select(func.count(SecurityAlert.id))
                .where(SecurityAlert.status == "OPEN")
            ) or 0
            metrics.set_alerts_open(open_count)
        except Exception:
            db.rollback()

    return generated_alerts


def acknowledge_alert(db: Session, alert: SecurityAlert, user_id: UUID) -> SecurityAlert:
    alert.status = "ACKNOWLEDGED"
    alert.acknowledged_at = datetime.now(timezone.utc)
    alert.acknowledged_by = user_id
    db.commit()
    db.refresh(alert)
    return alert


def resolve_alert(db: Session, alert: SecurityAlert, user_id: UUID, note: str | None = None) -> SecurityAlert:
    alert.status = "RESOLVED"
    alert.resolved_at = datetime.now(timezone.utc)
    alert.resolved_by = user_id
    alert.resolution_note = note
    db.commit()
    db.refresh(alert)
    return alert


def get_soc_overview(db: Session, organization_id: UUID, window_hours: int = 24) -> dict[str, Any]:
    since = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    base_events = select(SecurityEvent).where(
        SecurityEvent.organization_id == organization_id,
        SecurityEvent.created_at >= since,
    )

    total_events = db.scalar(select(func.count()).select_from(base_events.subquery())) or 0
    denied_actions = db.scalar(
        select(func.count()).select_from(base_events.where(SecurityEvent.decision == "DENIED").subquery())
    ) or 0
    replay_attempts = db.scalar(
        select(func.count()).select_from(base_events.where(SecurityEvent.category == "REPLAY").subquery())
    ) or 0
    invalid_signatures = db.scalar(
        select(func.count()).select_from(base_events.where(SecurityEvent.event_type.ilike("%signature%")).subquery())
    ) or 0
    revoked_credential_usage = db.scalar(
        select(func.count()).select_from(base_events.where(SecurityEvent.event_type.ilike("%revoked%")).subquery())
    ) or 0
    trust_violations = db.scalar(
        select(func.count()).select_from(base_events.where(SecurityEvent.category == "TRUST").subquery())
    ) or 0
    gateway_problems = db.scalar(
        select(func.count()).select_from(base_events.where(SecurityEvent.category == "GATEWAY", SecurityEvent.severity.in_(["HIGH", "CRITICAL"])).subquery())
    ) or 0
    high_risk_actions = db.scalar(
        select(func.count()).select_from(base_events.where(SecurityEvent.risk_level.in_(["HIGH", "CRITICAL"])).subquery())
    ) or 0
    admin_changes = db.scalar(
        select(func.count()).select_from(base_events.where(SecurityEvent.category == "ADMIN").subquery())
    ) or 0

    critical_alerts = db.scalar(
        select(func.count(SecurityAlert.id)).where(
            SecurityAlert.organization_id == organization_id,
            SecurityAlert.severity == "CRITICAL",
            SecurityAlert.status.in_(["OPEN", "ACKNOWLEDGED", "INVESTIGATING"]),
        )
    ) or 0
    high_alerts = db.scalar(
        select(func.count(SecurityAlert.id)).where(
            SecurityAlert.organization_id == organization_id,
            SecurityAlert.severity == "HIGH",
            SecurityAlert.status.in_(["OPEN", "ACKNOWLEDGED", "INVESTIGATING"]),
        )
    ) or 0

    return {
        "security_status": "CRITICAL" if critical_alerts > 0 else ("ELEVATED" if high_alerts > 0 else "OPERATIONAL"),
        "total_events": total_events,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "denied_actions": denied_actions,
        "replay_attempts": replay_attempts,
        "invalid_signatures": invalid_signatures,
        "revoked_credential_usage": revoked_credential_usage,
        "trust_violations": trust_violations,
        "gateway_problems": gateway_problems,
        "high_risk_actions": high_risk_actions,
        "admin_security_changes": admin_changes,
        "window_hours": window_hours,
    }


def get_agent_security_profile(db: Session, organization_id: UUID, agent_id: UUID) -> dict[str, Any]:
    agent = db.scalar(select(Agent).where(Agent.id == agent_id, Agent.organization_id == organization_id))
    if not agent:
        return {}

    events = list(db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.organization_id == organization_id, SecurityEvent.agent_id == agent_id)
        .order_by(SecurityEvent.created_at.desc())
        .limit(100)
    ))

    total = len(events)
    allowed = sum(1 for e in events if e.decision == "ALLOWED")
    denied = sum(1 for e in events if e.decision == "DENIED")

    alerts = list(db.scalars(
        select(SecurityAlert)
        .where(
            SecurityAlert.organization_id == organization_id,
            SecurityAlert.metadata_json["agent_id"].astext == str(agent_id),
        )
        .order_by(SecurityAlert.created_at.desc())
        .limit(10)
    ))

    return {
        "agent_id": str(agent.id),
        "name": agent.name,
        "status": agent.status.value if hasattr(agent.status, "value") else str(agent.status),
        "total_recent_events": total,
        "allowed_count": allowed,
        "denied_count": denied,
        "deny_rate": (denied / total) if total > 0 else 0.0,
        "recent_alerts": [
            {
                "alert_id": a.alert_id,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "first_seen_at": a.first_seen_at.isoformat(),
            }
            for a in alerts
        ],
        "recent_events": [
            {
                "event_id": e.event_id,
                "event_type": e.event_type,
                "severity": e.severity,
                "decision": e.decision,
                "created_at": e.created_at.isoformat(),
            }
            for e in events[:10]
        ],
    }


def get_gateway_security_profile(db: Session, organization_id: UUID, gateway_id: UUID) -> dict[str, Any]:
    gw = db.scalar(
        select(EnterpriseGateway).where(
            EnterpriseGateway.id == gateway_id,
            EnterpriseGateway.organization_id == organization_id,
        )
    )
    if not gw:
        return {}

    events = list(db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.organization_id == organization_id, SecurityEvent.gateway_id == gateway_id)
        .order_by(SecurityEvent.created_at.desc())
        .limit(100)
    ))

    now = datetime.now(timezone.utc)
    offline_seconds = 0
    if gw.last_seen_at:
        offline_seconds = max(0, int((now - gw.last_seen_at).total_seconds()))

    auth_failures = sum(1 for e in events if "auth" in e.event_type.lower() and e.severity in ("HIGH", "CRITICAL"))
    replay_count = sum(1 for e in events if e.category == "REPLAY")

    return {
        "gateway_id": str(gw.id),
        "name": gw.name,
        "status": gw.status.value if hasattr(gw.status, "value") else str(gw.status),
        "deployment_type": gw.deployment_type.value if hasattr(gw.deployment_type, "value") else str(gw.deployment_type),
        "software_version": getattr(gw, "software_version", getattr(gw, "version", "1.0.0")),
        "config_version": gw.config_version,
        "identity_fingerprint": getattr(gw, "identity_fingerprint", getattr(gw, "fingerprint", None)) or f"sha256:{hashlib.sha256(str(gw.id).encode()).hexdigest()[:16]}",
        "last_seen_at": gw.last_seen_at.isoformat() if gw.last_seen_at else None,
        "offline_age_seconds": offline_seconds,
        "recent_auth_failures": auth_failures,
        "recent_replay_events": replay_count,
    }
