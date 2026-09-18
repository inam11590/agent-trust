"""Deterministic authorization decisions, separate from HTTP handling."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import secrets
from typing import Literal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    APIKey,
    Agent,
    AgentDelegation,
    AgentStatus,
    AuditDecision,
    AuditLog,
    AuthorizationRequestRecord,
    Permission,
    PermissionStatus,
    NotificationPriority,
    NotificationType,
    RiskAction,
)
from app.core.config import Settings
from app.schemas.authorization import AuthorizationRequest
from app.services.permissions import expire_owned_permissions
from app.services.agent_delegation import verify_delegation_chain
from app.services.notification_service import create_notification
from app.services.risk_engine import RiskEvaluation, evaluate_and_save
from app.services.organization_policy import evaluate_organization_policy
from app.core.observability import metrics

Decision = Literal["APPROVED", "REJECTED", "PENDING"]
MANUAL_APPROVAL_WINDOW = timedelta(minutes=5)
_UNSCOPED = object()


@dataclass(frozen=True)
class AuthorizationResult:
    request_id: str
    decision: Decision
    reason: str
    risk_level: str | None = None
    risk_score: int | None = None
    risk_reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Evaluation:
    decision: Decision
    reason: str
    agent_id: UUID | None = None
    permission_id: UUID | None = None


def _approved(agent_id: UUID, permission_id: UUID) -> _Evaluation:
    return _Evaluation(
        decision="APPROVED",
        reason="Permission valid",
        agent_id=agent_id,
        permission_id=permission_id,
    )


def _rejected(
    reason: str,
    agent_id: UUID | None = None,
    permission_id: UUID | None = None,
) -> _Evaluation:
    return _Evaluation(
        decision="REJECTED",
        reason=reason,
        agent_id=agent_id,
        permission_id=permission_id,
    )


def generate_request_id() -> str:
    """Return an opaque public ID with 96 bits of cryptographic randomness."""
    return f"req_{secrets.token_hex(12)}"


def _save_audit_log(
    db: Session,
    owner_id: UUID,
    request: AuthorizationRequest,
    evaluation: _Evaluation,
    requested_at: datetime,
    request_id: str | None = None,
    commit: bool = True,
    organization_id: UUID | None = None,
    risk: RiskEvaluation | None = None,
    environment: str = "production",
    delegation_id: str | None = None,
    parent_agent_id: UUID | None = None,
) -> AuthorizationResult:
    request_id = request_id or generate_request_id()
    db.add(AuditLog(
        request_id=request_id,
        user_id=owner_id,
        organization_id=organization_id,
        environment=environment,
        agent_id=evaluation.agent_id,
        agent_identifier=request.agent_id,
        permission_id=evaluation.permission_id,
        delegation_id=delegation_id,
        parent_agent_id=parent_agent_id,
        action=request.action,
        resource=request.resource,
        amount=request.amount,
        currency=request.currency,
        decision=AuditDecision(evaluation.decision),
        reason=evaluation.reason,
        risk_score=risk.score if risk else None,
        risk_level=risk.level.value if risk else None,
        risk_recommendation=risk.recommendation.value if risk else None,
        requested_at=requested_at,
    ))
    if commit:
        db.commit()
    metrics.authorization(evaluation.decision)
    return AuthorizationResult(
        request_id=request_id,
        decision=evaluation.decision,
        reason=evaluation.reason,
        risk_level=risk.level.value if risk else None,
        risk_score=risk.score if risk else None,
        risk_reasons=risk.reasons if risk else (),
    )


def _save_pending_request(
    db: Session,
    owner_id: UUID,
    request: AuthorizationRequest,
    permission: Permission,
    requested_at: datetime,
    request_id: str,
    risk: RiskEvaluation,
    risk_forced: bool,
    reason: str | None = None,
    environment: str = "production",
    delegation_id: str | None = None,
    parent_agent_id: UUID | None = None,
    acting_agent: Agent | None = None,
) -> AuthorizationResult:
    expires_at = min(permission.expires_at, requested_at + MANUAL_APPROVAL_WINDOW)
    requesting_agent_id = acting_agent.id if acting_agent else permission.agent_id
    record = AuthorizationRequestRecord(
        request_id=request_id,
        user_id=permission.owner_id,
        agent_id=requesting_agent_id,
        environment=environment,
        permission_id=permission.id,
        delegation_id=delegation_id,
        parent_agent_id=parent_agent_id,
        action=request.action,
        resource=request.resource,
        amount=request.amount,
        currency=request.currency,
        reason=reason or ("Manual approval required" if risk_forced else "Awaiting user approval"),
        policy_reason=reason,
        risk_score=risk.score,
        risk_level=risk.level.value,
        risk_recommendation=risk.recommendation.value,
        expires_at=expires_at,
    )
    db.add(record)
    db.flush()
    agent = acting_agent or db.get(Agent, permission.agent_id)
    amount = f" for {request.amount.normalize()} {request.currency}" if request.amount is not None else ""
    create_notification(
        db,
        user_id=record.user_id,
        organization_id=agent.organization_id if agent else None,
        notification_type=(
            NotificationType.HIGH_RISK_APPROVAL_REQUIRED
            if risk_forced else NotificationType.AUTHORIZATION_PENDING
        ),
        title="High-Risk Approval Required" if risk_forced else "Approval Required",
        message=(
            f"{agent.name if agent else 'Your agent'} is requesting {request.action} {request.resource}{amount}. "
            f"This request has a {risk.level.value.lower()} risk score."
            if risk_forced else
            f"{agent.name if agent else 'Your agent'} wants to {request.action} {request.resource}{amount}."
        ),
        priority=NotificationPriority.CRITICAL if risk.level.value == "CRITICAL" else NotificationPriority.HIGH,
        related_request_id=record.id,
        related_agent_id=record.agent_id,
        related_permission_id=record.permission_id,
        metadata={
            "request_id": record.request_id, "agent": agent.name if agent else "Agent",
            "action": request.action, "resource": request.resource,
            "amount": str(request.amount) if request.amount is not None else None,
            "currency": request.currency,
            "risk_level": risk.level.value,
            "delegation_id": delegation_id,
        },
        deduplication_key=f"authorization-pending:{record.id}",
    )
    db.commit()
    metrics.authorization("PENDING")
    return AuthorizationResult(
        request_id=request_id,
        decision="PENDING",
        reason=record.reason,
        risk_level=risk.level.value,
        risk_score=risk.score,
        risk_reasons=risk.reasons,
    )


def _complete_or_queue(
    db: Session,
    owner_id: UUID,
    request: AuthorizationRequest,
    permission: Permission,
    requested_at: datetime,
    organization_id: UUID | None = None,
    settings: Settings | None = None,
    api_key: APIKey | None = None,
    delegation: AgentDelegation | None = None,
    force_approval: bool = False,
    acting_agent: Agent | None = None,
) -> AuthorizationResult:
    request_id = generate_request_id()
    eval_agent = acting_agent or permission.agent
    environment = getattr(api_key, "environment", "production") if api_key else getattr(eval_agent, "environment", "production")
    _, risk = evaluate_and_save(
        db, settings or Settings(), request_id=request_id, user_id=owner_id,
        organization_id=organization_id, agent=eval_agent,
        permission=permission, request=request, requested_at=requested_at,
        api_key=api_key,
    )
    delegation_id = delegation.delegation_id if delegation else None
    parent_agent_id = delegation.parent_agent_id if delegation else None

    if risk.recommendation == RiskAction.REJECT:
        return _save_audit_log(
            db, owner_id, request,
            _rejected("Request rejected by risk policy", eval_agent.id, permission.id),
            requested_at, request_id=request_id, organization_id=organization_id, risk=risk,
            environment=environment,
            delegation_id=delegation_id,
            parent_agent_id=parent_agent_id,
        )
    organization_action, organization_reason = evaluate_organization_policy(db, organization_id, request, risk)
    if organization_action == "DENY":
        return _save_audit_log(
            db, owner_id, request,
            _rejected(organization_reason or "Request rejected by organization security policy", eval_agent.id, permission.id),
            requested_at, request_id=request_id, organization_id=organization_id, risk=risk,
            environment=environment,
            delegation_id=delegation_id,
            parent_agent_id=parent_agent_id,
        )
    risk_forced = risk.recommendation == RiskAction.REQUIRE_APPROVAL
    if permission.requires_approval or force_approval or risk_forced or organization_action == "REQUIRE_APPROVAL":
        return _save_pending_request(
            db, owner_id, request, permission, requested_at, request_id, risk, risk_forced,
            reason=organization_reason, environment=environment,
            delegation_id=delegation_id,
            parent_agent_id=parent_agent_id,
            acting_agent=eval_agent,
        )
    return _save_audit_log(
        db,
        owner_id,
        request,
        _approved(eval_agent.id, permission.id),
        requested_at,
        organization_id=organization_id, request_id=request_id, risk=risk,
        environment=environment,
        delegation_id=delegation_id,
        parent_agent_id=parent_agent_id,
    )


def authorize_action(
    db: Session,
    owner_id: UUID,
    request: AuthorizationRequest,
    at: datetime | None = None,
    organization_scope: UUID | None | object = _UNSCOPED,
    settings: Settings | None = None,
    api_key: APIKey | None = None,
) -> AuthorizationResult:
    """Evaluate one request, persist its decision, and return its public request ID."""
    checked_at = at or datetime.now(timezone.utc)
    audit_organization_id = organization_scope if isinstance(organization_scope, UUID) else None
    environment = getattr(api_key, "environment", "production") if api_key else "production"

    def save(evaluation: _Evaluation) -> AuthorizationResult:
        return _save_audit_log(
            db, owner_id, request, evaluation, checked_at,
            organization_id=audit_organization_id,
            environment=environment,
        )
    agent_conditions = [Agent.agent_identifier == request.agent_id]
    if api_key is not None:
        agent_conditions.append(Agent.environment == environment)
    if organization_scope is _UNSCOPED:
        agent_conditions.append(Agent.owner_id == owner_id)
    elif organization_scope is None:
        agent_conditions.extend([Agent.owner_id == owner_id, Agent.organization_id.is_(None)])
    else:
        agent_conditions.append(Agent.organization_id == organization_scope)
    agent = db.scalar(select(Agent).where(*agent_conditions))
    if agent is None:
        evaluation = _rejected("Agent not found")
        return save(evaluation)
    if agent.status != AgentStatus.ACTIVE:
        evaluation = _rejected("Agent is not active", agent.id)
        return save(evaluation)

    # Delegation Check: if request has delegation_id, verify delegation chain
    if request.delegation_id is not None:
        is_valid, reason, meta = verify_delegation_chain(
            db,
            delegation_id=request.delegation_id,
            action=request.action,
            resource=request.resource,
            amount=request.amount,
            currency=request.currency,
            at=checked_at,
            child_agent_id=agent.id,
            organization_id=audit_organization_id or agent.organization_id,
        )
        if not is_valid:
            evaluation = _rejected(f"Delegation invalid: {reason}", agent.id)
            return _save_audit_log(
                db, owner_id, request, evaluation, checked_at,
                organization_id=audit_organization_id or agent.organization_id,
                environment=environment,
                delegation_id=request.delegation_id,
                parent_agent_id=meta.get("parent_agent_id"),
            )

        delegation = meta["delegation"]
        root_permission = meta["root_permission"]
        force_approval = meta.get("effective_requires_approval", False)

        return _complete_or_queue(
            db,
            owner_id=root_permission.owner_id,
            request=request,
            permission=root_permission,
            requested_at=checked_at,
            organization_id=audit_organization_id or delegation.organization_id,
            settings=settings,
            api_key=api_key,
            delegation=delegation,
            force_approval=force_approval,
            acting_agent=agent,
        )

    # Persist the display status, while the checks below still compare time directly.
    expire_owned_permissions(
        db, owner_id, checked_at,
        organization_id=(... if organization_scope is _UNSCOPED else organization_scope),
    )
    permission_conditions = [Permission.agent_id == agent.id]
    if organization_scope is _UNSCOPED or organization_scope is None:
        permission_conditions.append(Permission.owner_id == owner_id)
    permissions = list(db.scalars(select(Permission).where(
        *permission_conditions,
    ).order_by(Permission.created_at.desc(), Permission.id.desc())))
    if not permissions:
        evaluation = _rejected("No permission found", agent.id)
        return save(evaluation)

    action_matches = [permission for permission in permissions if permission.action == request.action]
    if not action_matches:
        evaluation = _rejected("Action not permitted", agent.id)
        return save(evaluation)

    scope_matches = [
        permission for permission in action_matches if permission.resource == request.resource
    ]
    if not scope_matches:
        evaluation = _rejected("Resource not permitted", agent.id)
        return save(evaluation)

    active = [
        permission for permission in scope_matches
        if permission.status == PermissionStatus.ACTIVE
    ]
    if not active:
        revoked_permission = next(
            (permission for permission in scope_matches if permission.status == PermissionStatus.REVOKED),
            None,
        )
        if revoked_permission is not None:
            evaluation = _rejected("Permission revoked", agent.id, revoked_permission.id)
        else:
            evaluation = _rejected("Permission expired", agent.id, scope_matches[0].id)
        return save(evaluation)

    started = [permission for permission in active if permission.valid_from <= checked_at]
    if not started:
        evaluation = _rejected("Permission has not started", agent.id, active[0].id)
        return save(evaluation)

    current = [permission for permission in started if checked_at < permission.expires_at]
    if not current:
        evaluation = _rejected("Permission expired", agent.id, started[0].id)
        return save(evaluation)

    if request.amount is None:
        matching_permission = next(
            (permission for permission in current if permission.maximum_amount is None),
            None,
        )
        if matching_permission is not None:
            return _complete_or_queue(
                db, owner_id, request, matching_permission, checked_at, audit_organization_id,
                settings, api_key,
            )
        else:
            evaluation = _rejected("Amount is required for this permission", agent.id, current[0].id)
        return save(evaluation)

    amount_permissions = [
        permission for permission in current if permission.maximum_amount is not None
    ]
    if not amount_permissions:
        evaluation = _rejected("Permission does not allow an amount", agent.id, current[0].id)
        return save(evaluation)

    currency_matches = [
        permission for permission in amount_permissions
        if permission.currency == request.currency
    ]
    if not currency_matches:
        evaluation = _rejected("Currency does not match", agent.id, amount_permissions[0].id)
        return save(evaluation)

    matching_permission = next(
        (
            permission
            for permission in currency_matches
            if request.amount <= permission.maximum_amount
        ),
        None,
    )
    if matching_permission is not None:
        return _complete_or_queue(
            db, owner_id, request, matching_permission, checked_at, audit_organization_id,
            settings, api_key,
        )
    else:
        evaluation = _rejected(
            "Amount exceeds allowed limit", agent.id, currency_matches[0].id,
        )
    return save(evaluation)
