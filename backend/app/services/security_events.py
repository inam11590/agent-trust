"""Small append-only audit trail for organization security changes."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import SecurityEvent


def record_security_event(
    db: Session,
    actor_user_id: UUID | None,
    event_type: str,
    *,
    organization_id: UUID | None = None,
    target_user_id: UUID | None = None,
    description: str | None = None,
    severity: str = "info",
    details: dict | None = None,
    commit: bool = True,
) -> SecurityEvent:
    event = SecurityEvent(
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        target_user_id=target_user_id,
        event_type=event_type,
        severity=severity,
        description=description,
        details=details or {},
    )
    db.add(event)
    if commit:
        db.commit()
        db.refresh(event)
    return event


def list_security_events(db: Session, organization_id: UUID, limit: int = 100) -> list[SecurityEvent]:
    return list(db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.organization_id == organization_id)
        .order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc())
        .limit(limit)
    ))
