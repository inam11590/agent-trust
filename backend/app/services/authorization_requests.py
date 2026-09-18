"""Owner-only lifecycle for requests that require a manual decision."""

from datetime import datetime, timezone
from math import ceil
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.models import (
    AgentStatus,
    AuditDecision,
    AuditLog,
    AuthorizationRequestRecord,
    AuthorizationRequestStatus,
    PermissionStatus,
    Agent,
    NotificationPriority,
    NotificationType,
)
from app.schemas.authorization import AuthorizationRequest
from app.schemas.authorization_request import AuthorizationRequestFilters
from app.services.notification_service import create_notification


class RequestNotFound(Exception):
    pass


class RequestAlreadyDecided(Exception):
    pass


class RequestExpired(Exception):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _audit_final_decision(
    db: Session,
    record: AuthorizationRequestRecord,
    decision: AuditDecision,
    reason: str,
) -> None:
    db.add(AuditLog(
        request_id=record.request_id,
        user_id=record.user_id,
        organization_id=record.agent.organization_id,
        agent_id=record.agent_id,
        agent_identifier=record.agent.agent_identifier,
        permission_id=record.permission_id,
        action=record.action,
        resource=record.resource,
        amount=record.amount,
        currency=record.currency,
        decision=decision,
        reason=reason,
        risk_score=record.risk_score,
        risk_level=record.risk_level,
        risk_recommendation=record.risk_recommendation,
        signature_verified=record.signature_verified,
        signing_key_id=record.signing_key_id,
        signature_version=record.signature_version,
        requested_at=record.created_at,
    ))


def _finalize(
    db: Session,
    record: AuthorizationRequestRecord,
    status: AuthorizationRequestStatus,
    reason: str,
    decided_at: datetime,
) -> None:
    record.status = status
    record.reason = reason
    record.decided_at = decided_at
    decision = (
        AuditDecision.APPROVED
        if status == AuthorizationRequestStatus.APPROVED
        else AuditDecision.REJECTED
    )
    _audit_final_decision(db, record, decision, reason)
    notification_type = (
        NotificationType.AUTHORIZATION_APPROVED
        if status == AuthorizationRequestStatus.APPROVED
        else NotificationType.AUTHORIZATION_REJECTED
    )
    amount = f" for {record.amount.normalize()} {record.currency}" if record.amount is not None else ""
    if status == AuthorizationRequestStatus.APPROVED:
        message = f"{record.agent.name} was approved to {record.action} {record.resource}{amount}."
    else:
        message = f"{record.agent.name} request to {record.action} {record.resource}{amount} was rejected."
    create_notification(
        db,
        user_id=record.user_id,
        organization_id=record.agent.organization_id,
        notification_type=notification_type,
        title="Action Approved" if status == AuthorizationRequestStatus.APPROVED else "Action Rejected",
        message=message,
        priority=NotificationPriority.NORMAL,
        related_request_id=record.id,
        related_agent_id=record.agent_id,
        related_permission_id=record.permission_id,
        metadata={"request_id": record.request_id},
        deduplication_key=f"authorization-final:{record.id}",
    )


def _expire_records(
    db: Session,
    owner_id: UUID,
    checked_at: datetime,
    organization_id: UUID | None = None,
) -> None:
    scope = (
        AuthorizationRequestRecord.agent_id.in_(select(Agent.id).where(Agent.organization_id == organization_id))
        if organization_id is not None
        else (AuthorizationRequestRecord.user_id == owner_id) & AuthorizationRequestRecord.agent_id.in_(
            select(Agent.id).where(Agent.owner_id == owner_id, Agent.organization_id.is_(None))
        )
    )
    records = list(db.scalars(
        select(AuthorizationRequestRecord)
        .where(
            scope,
            AuthorizationRequestRecord.status == AuthorizationRequestStatus.PENDING,
            AuthorizationRequestRecord.expires_at <= checked_at,
        )
        .with_for_update()
    ))
    for record in records:
        _finalize(
            db,
            record,
            AuthorizationRequestStatus.EXPIRED,
            "Request expired",
            checked_at,
        )
    if records:
        db.commit()


def list_owned_requests(
    db: Session,
    owner_id: UUID,
    filters: AuthorizationRequestFilters,
    organization_id: UUID | None = None,
) -> tuple[list[AuthorizationRequestRecord], int, int]:
    _expire_records(db, owner_id, utc_now(), organization_id)
    scope = (
        AuthorizationRequestRecord.agent_id.in_(select(Agent.id).where(Agent.organization_id == organization_id))
        if organization_id is not None
        else (AuthorizationRequestRecord.user_id == owner_id) & AuthorizationRequestRecord.agent_id.in_(
            select(Agent.id).where(Agent.owner_id == owner_id, Agent.organization_id.is_(None))
        )
    )
    conditions = [scope]
    if filters.status is not None:
        conditions.append(AuthorizationRequestRecord.status == filters.status)
    total = db.scalar(
        select(func.count()).select_from(AuthorizationRequestRecord).where(*conditions)
    ) or 0
    items = list(db.scalars(
        select(AuthorizationRequestRecord)
        .options(joinedload(AuthorizationRequestRecord.agent))
        .where(*conditions)
        .order_by(AuthorizationRequestRecord.created_at.desc(), AuthorizationRequestRecord.id.desc())
        .offset((filters.page - 1) * filters.page_size)
        .limit(filters.page_size)
    ))
    return items, total, ceil(total / filters.page_size) if total else 0


def get_owned_request(
    db: Session,
    owner_id: UUID,
    request_id: UUID,
    organization_id: UUID | None = None,
) -> AuthorizationRequestRecord | None:
    _expire_records(db, owner_id, utc_now(), organization_id)
    scope = (
        AuthorizationRequestRecord.agent_id.in_(select(Agent.id).where(Agent.organization_id == organization_id))
        if organization_id is not None
        else (AuthorizationRequestRecord.user_id == owner_id) & AuthorizationRequestRecord.agent_id.in_(
            select(Agent.id).where(Agent.owner_id == owner_id, Agent.organization_id.is_(None))
        )
    )
    return db.scalar(
        select(AuthorizationRequestRecord)
        .options(joinedload(AuthorizationRequestRecord.agent))
        .where(
            AuthorizationRequestRecord.id == request_id,
            scope,
        )
    )


def _validate_for_approval(record: AuthorizationRequestRecord, checked_at: datetime) -> str | None:
    agent = record.agent
    permission = record.permission
    if agent.status != AgentStatus.ACTIVE:
        return "Agent is not active"
    if permission.status == PermissionStatus.REVOKED:
        return "Permission revoked"
    if permission.status != PermissionStatus.ACTIVE or checked_at >= permission.expires_at:
        return "Permission expired"
    if checked_at < permission.valid_from:
        return "Permission has not started"
    if permission.agent_id != record.agent_id:
        return "Permission is not valid for this request"
    if permission.action != record.action:
        return "Action not permitted"
    if permission.resource != record.resource:
        return "Resource not permitted"
    if record.amount is None:
        if permission.maximum_amount is not None:
            return "Amount is required for this permission"
    else:
        if permission.maximum_amount is None:
            return "Permission does not allow an amount"
        if permission.currency != record.currency:
            return "Currency does not match"
        if record.amount > permission.maximum_amount:
            return "Amount exceeds allowed limit"
    return None


def decide_owned_request(
    db: Session,
    owner_id: UUID,
    request_id: UUID,
    approve: bool,
    at: datetime | None = None,
    organization_id: UUID | None = None,
) -> AuthorizationRequestRecord:
    checked_at = at or utc_now()
    scope = (
        AuthorizationRequestRecord.agent_id.in_(select(Agent.id).where(Agent.organization_id == organization_id))
        if organization_id is not None
        else (AuthorizationRequestRecord.user_id == owner_id) & AuthorizationRequestRecord.agent_id.in_(
            select(Agent.id).where(Agent.owner_id == owner_id, Agent.organization_id.is_(None))
        )
    )
    record = db.scalar(
        select(AuthorizationRequestRecord)
        .where(
            AuthorizationRequestRecord.id == request_id,
            scope,
        )
        .with_for_update()
    )
    if record is None:
        raise RequestNotFound
    if record.status != AuthorizationRequestStatus.PENDING:
        raise RequestAlreadyDecided
    if checked_at >= record.expires_at:
        _finalize(
            db, record, AuthorizationRequestStatus.EXPIRED, "Request expired", checked_at,
        )
        db.commit()
        raise RequestExpired

    if approve:
        validation_error = _validate_for_approval(record, checked_at)
        if validation_error is None:
            _finalize(
                db, record, AuthorizationRequestStatus.APPROVED, "Approved by user", checked_at,
            )
        else:
            _finalize(
                db, record, AuthorizationRequestStatus.REJECTED, validation_error, checked_at,
            )
    else:
        _finalize(
            db, record, AuthorizationRequestStatus.REJECTED, "Rejected by user", checked_at,
        )
    db.commit()
    db.refresh(record)
    return record
