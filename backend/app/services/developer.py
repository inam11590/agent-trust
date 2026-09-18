"""Versioned developer authorization, idempotency, status, and request logs."""

from datetime import datetime
import hashlib
import json
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import APIKey, AuditLog, AuthorizationRequestRecord, DeveloperRequest, RiskAssessment
from app.schemas.authorization import AuthorizationRequest
from app.services.api_keys import DeveloperPrincipal
from app.services.authorization import AuthorizationResult, authorize_action
from app.services.authorization_requests import get_owned_request
from app.services.webhooks import deliver_decision_webhook
from app.services.plan_limits import consume_authorization_request, release_authorization_request
from app.services.agent_signing import VerifiedAgentSignature


class IdempotencyConflict(Exception):
    pass


class RequestInProgress(Exception):
    pass


class DeveloperRequestNotFound(Exception):
    pass


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def payload_hash(payload: AuthorizationRequest) -> str:
    canonical = json.dumps(payload.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return _sha(canonical)


def resolve_result(db: Session, request_id: str) -> AuthorizationResult:
    assessment = db.scalar(select(RiskAssessment).where(RiskAssessment.request_id == request_id))
    pending = db.scalar(select(AuthorizationRequestRecord).where(
        AuthorizationRequestRecord.request_id == request_id,
    ))
    if pending is not None:
        if pending.status.value == "PENDING":
            pending = get_owned_request(
                db, pending.user_id, pending.id, pending.agent.organization_id,
            ) or pending
        return AuthorizationResult(
            request_id=request_id, decision=pending.status.value, reason=pending.reason,
            risk_level=assessment.risk_level.value if assessment else None,
            risk_score=assessment.risk_score if assessment else None,
        )
    audit = db.scalar(select(AuditLog).where(AuditLog.request_id == request_id))
    if audit is None:
        raise DeveloperRequestNotFound
    return AuthorizationResult(
        request_id=request_id, decision=audit.decision.value, reason=audit.reason,
        risk_level=assessment.risk_level.value if assessment else None,
        risk_score=assessment.risk_score if assessment else None,
    )


def developer_authorize(
    db: Session,
    principal: DeveloperPrincipal,
    payload: AuthorizationRequest,
    idempotency_key: str | None,
    settings: Settings,
    signature: VerifiedAgentSignature | None = None,
) -> AuthorizationResult:
    digest = payload_hash(payload)
    idempotency_hash = _sha(idempotency_key) if idempotency_key else None
    reservation = DeveloperRequest(
        api_key_id=principal.api_key.id,
        idempotency_hash=idempotency_hash,
        payload_hash=digest,
    )
    db.add(reservation)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        if idempotency_hash is None:
            raise
        existing = db.scalar(select(DeveloperRequest).where(
            DeveloperRequest.api_key_id == principal.api_key.id,
            DeveloperRequest.idempotency_hash == idempotency_hash,
        ))
        if existing is None:
            raise
        if existing.payload_hash != digest:
            raise IdempotencyConflict
        if existing.request_id is None:
            raise RequestInProgress
        return resolve_result(db, existing.request_id)

    usage_consumed = False
    try:
        is_sandbox = getattr(principal.api_key, "environment", "production") == "sandbox"
        if principal.api_key.organization_id is not None and not is_sandbox:
            consume_authorization_request(db, principal.api_key.organization_id)
            usage_consumed = True
        result = authorize_action(
            db,
            principal.user.id,
            payload,
            organization_scope=principal.api_key.organization_id,
            settings=settings,
            api_key=principal.api_key,
        )
        if signature is not None:
            signed_record = db.scalar(select(AuthorizationRequestRecord).where(
                AuthorizationRequestRecord.request_id == result.request_id,
            )) or db.scalar(select(AuditLog).where(AuditLog.request_id == result.request_id))
            if signed_record is not None:
                signed_record.signature_verified = True
                signed_record.signing_key_id = signature.key_id
                signed_record.signature_version = signature.version
        reservation.request_id = result.request_id
        db.commit()
        if result.decision != "PENDING":
            deliver_decision_webhook(
                db, settings, principal.api_key.organization_id,
                result.request_id, result.decision,
                is_test=is_sandbox,
            )
        return result
    except Exception:
        db.rollback()
        if usage_consumed and principal.api_key.organization_id is not None:
            release_authorization_request(db, principal.api_key.organization_id)
        stored = db.get(DeveloperRequest, reservation.id)
        if stored is not None:
            db.delete(stored)
            db.commit()
        raise


def get_developer_request(
    db: Session, principal: DeveloperPrincipal, request_id: str,
) -> AuthorizationResult:
    owned = db.scalar(select(DeveloperRequest.id).where(
        DeveloperRequest.api_key_id == principal.api_key.id,
        DeveloperRequest.request_id == request_id,
    ))
    if owned is None:
        raise DeveloperRequestNotFound
    return resolve_result(db, request_id)


def developer_logs(
    db: Session, user_id: UUID, organization_id: UUID | None = None,
    include_all_organization_keys: bool = False,
    environment: str | None = None,
    status_filter: str | None = None,
    agent_id_filter: str | None = None,
    request_id_filter: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    conditions = [APIKey.organization_id == organization_id, DeveloperRequest.request_id.is_not(None)]
    if organization_id is None or not include_all_organization_keys:
        conditions.append(APIKey.created_by_user_id == user_id)
    if environment:
        conditions.append(APIKey.environment == environment)
    if request_id_filter:
        conditions.append(DeveloperRequest.request_id == request_id_filter)
    rows = db.execute(
        select(DeveloperRequest, APIKey)
        .join(APIKey, APIKey.id == DeveloperRequest.api_key_id)
        .where(*conditions)
        .order_by(DeveloperRequest.created_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    output = []
    for record, key in rows:
        result = resolve_result(db, record.request_id)
        if status_filter and result.decision.upper() != status_filter.upper():
            continue
        pending = db.scalar(select(AuthorizationRequestRecord).where(
            AuthorizationRequestRecord.request_id == record.request_id,
        ))
        audit = None if pending else db.scalar(select(AuditLog).where(AuditLog.request_id == record.request_id))
        source = pending or audit
        agent_identifier = (source.agent_identifier if audit else source.agent.agent_identifier) if source else "unknown"
        if agent_id_filter and agent_id_filter not in (agent_identifier, str(getattr(source, "agent_id", ""))):
            continue
        output.append({
            "request_id": record.request_id,
            "status": result.decision,
            "reason": result.reason,
            "agent_id": agent_identifier,
            "action": source.action if source else "authorize",
            "environment": getattr(key, "environment", "production"),
            "api_key_prefix": key.key_prefix,
            "created_at": record.created_at,
        })
    return output


def get_developer_log_detail(
    db: Session, user_id: UUID, organization_id: UUID | None,
    request_id: str, include_all_keys: bool = False,
) -> dict | None:
    conditions = [DeveloperRequest.request_id == request_id]
    row = db.execute(
        select(DeveloperRequest, APIKey)
        .join(APIKey, APIKey.id == DeveloperRequest.api_key_id)
        .where(*conditions)
    ).first()
    if row is None:
        return None
    record, key = row
    if key.organization_id != organization_id and organization_id is not None:
        return None
    if not include_all_keys and key.created_by_user_id != user_id and organization_id is None:
        return None
    result = resolve_result(db, record.request_id)
    pending = db.scalar(select(AuthorizationRequestRecord).where(
        AuthorizationRequestRecord.request_id == record.request_id,
    ))
    audit = None if pending else db.scalar(select(AuditLog).where(AuditLog.request_id == record.request_id))
    source = pending or audit
    assessment = db.scalar(select(RiskAssessment).where(RiskAssessment.request_id == record.request_id))
    agent_id = (source.agent_identifier if audit else source.agent.agent_identifier) if source else "unknown"
    return {
        "request_id": record.request_id,
        "environment": getattr(key, "environment", "production"),
        "agent_id": agent_id,
        "action": source.action if source else "authorize",
        "resource": source.resource if source else "",
        "amount": str(source.amount) if source and source.amount is not None else None,
        "currency": source.currency if source else None,
        "status": result.decision,
        "reason": result.reason,
        "risk_level": assessment.risk_level.value if assessment else None,
        "risk_score": assessment.risk_score if assessment else None,
        "signature_verified": getattr(source, "signature_verified", False) if source else False,
        "signing_key_id": getattr(source, "signing_key_id", None) if source else None,
        "api_key_prefix": key.key_prefix,
        "response_time_ms": None,
        "created_at": record.created_at,
    }
