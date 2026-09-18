"""Service for Cross-Organization Authorization execution and multi-party approvals."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import secrets
from typing import Literal
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import (
    Agent,
    AgentStatus,
    AuditDecision,
    AuditLog,
    NotificationPriority,
    NotificationType,
    Organization,
    Permission,
    PermissionStatus,
    User,
)
from app.models.cross_organization_trust import (
    ApprovalStage,
    ApprovalStatus,
    CrossOrgRequestStatus,
    CrossOrganizationApproval,
    CrossOrganizationRequest,
    ExternalAgentConnection,
    OrganizationTrustPolicy,
    OrganizationTrustRelationship,
    TargetOrganizationPolicy,
    TrustStatus,
)
from app.schemas.cross_organization_trust import CrossOrgAuthorizePayload, CrossOrgAuthorizeResponse
from app.services.agent_delegation import verify_delegation_chain
from app.services.agent_signing import SigningError, verify_cross_org_request_v2
from app.services.notification_service import create_notification
from app.services.risk_engine import RiskEvaluation, evaluate_and_save
from app.services.security_events import record_security_event

EXPIRY_WINDOW = timedelta(hours=24)


def _compute_payload_hash(payload: CrossOrgAuthorizePayload) -> str:
    raw = f"{payload.source_agent_id}:{payload.target_organization_id}:{payload.target_agent_id}:{payload.action}:{payload.resource}:{payload.amount}:{payload.currency}:{payload.delegation_id}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _find_agent(db: Session, ident_or_id: str) -> Agent | None:
    try:
        val_uuid = UUID(ident_or_id)
        agent = db.get(Agent, val_uuid)
        if agent:
            return agent
    except ValueError:
        pass
    return db.scalar(select(Agent).where(Agent.agent_identifier == ident_or_id))


def authorize_cross_organization_action(
    db: Session,
    settings: Settings,
    redis_client,
    payload: CrossOrgAuthorizePayload,
    headers: dict,
    raw_body: bytes,
    caller_org_id: UUID | None = None,
    idempotency_key: str | None = None,
) -> CrossOrgAuthorizeResponse:
    """Evaluate an 11-step cross-organization request under strict zero-implicit-trust."""
    now = datetime.now(timezone.utc)

    # 1. Resolve source and target agents
    source_agent = _find_agent(db, payload.source_agent_id)
    if not source_agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Source agent not found")

    target_agent = _find_agent(db, payload.target_agent_id)
    if not target_agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target agent not found")

    source_org_id = source_agent.organization_id
    if not source_org_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Source agent must belong to an organization")

    if caller_org_id and caller_org_id != source_org_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Caller organization mismatch with source agent")

    target_org_id = target_agent.organization_id
    if not target_org_id or target_org_id != payload.target_organization_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Target agent does not belong to specified target organization")

    if source_org_id == target_org_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cross-organization authorization cannot be used within the same organization")

    # 2. Idempotency Check
    payload_hash = _compute_payload_hash(payload)
    if idempotency_key:
        existing_req = db.scalar(
            select(CrossOrganizationRequest).where(
                CrossOrganizationRequest.source_organization_id == source_org_id,
                CrossOrganizationRequest.idempotency_key == idempotency_key,
            )
        )
        if existing_req:
            if existing_req.idempotency_hash != payload_hash:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="CROSS_ORG_IDEMPOTENCY_CONFLICT: Idempotency key already used with different request parameters",
                )
            return CrossOrgAuthorizeResponse(
                request_id=existing_req.request_id,
                status=existing_req.status.value,
                reason=existing_req.decision_reason or "Idempotent response",
                risk_level=existing_req.risk_level,
                risk_score=existing_req.risk_score,
            )

    # 3. Cryptographic Signature Verification (v2)
    try:
        verify_cross_org_request_v2(
            db,
            settings,
            redis_client,
            source_agent=source_agent,
            target_agent=target_agent,
            source_org_id=source_org_id,
            target_org_id=target_org_id,
            headers=headers,
            body=raw_body,
            method="POST",
            path="/api/v1/cross-org/authorize",
        )
    except SigningError as e:
        raise HTTPException(status_code=e.status_code, detail=f"CROSS_ORG_SIGNATURE_INVALID: {e.code}")

    # 4. Check Organization and Agent Status
    source_org = db.get(Organization, source_org_id)
    target_org = db.get(Organization, target_org_id)
    if not source_org or not source_org.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Source organization is inactive")
    if not target_org or not target_org.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Target organization is inactive")

    if source_agent.status != AgentStatus.ACTIVE:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Source agent is not active")
    if target_agent.status != AgentStatus.ACTIVE:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Target agent is not active")

    # 5. Verify Source Agent Permission (Source must grant authority)
    source_perm = db.scalar(
        select(Permission).where(
            Permission.agent_id == source_agent.id,
            Permission.action == payload.action,
            Permission.resource == payload.resource,
            Permission.status == PermissionStatus.ACTIVE,
        )
    )
    if not source_perm or not source_perm.is_usable(now):
        # Check if internal delegation is used
        if payload.delegation_id:
            try:
                verify_delegation_chain(
                    db,
                    delegation_id=payload.delegation_id,
                    expected_agent_id=source_agent.id,
                    action=payload.action,
                    resource=payload.resource,
                    amount=payload.amount,
                    currency=payload.currency,
                    checked_at=now,
                )
            except Exception as exc:
                return _record_and_return_rejection(
                    db,
                    source_org_id,
                    target_org_id,
                    source_agent.id,
                    target_agent.id,
                    payload,
                    reason="SOURCE_PERMISSION_DENIED: Invalid delegation chain",
                    idempotency_key=idempotency_key,
                    idempotency_hash=payload_hash,
                )
        else:
            return _record_and_return_rejection(
                db,
                source_org_id,
                target_org_id,
                source_agent.id,
                target_agent.id,
                payload,
                reason="SOURCE_PERMISSION_DENIED: Source agent lacks permission for this action/resource",
                idempotency_key=idempotency_key,
                idempotency_hash=payload_hash,
            )

    # 6. Trust Relationship Check (Directional: Source -> Target)
    trust = db.scalar(
        select(OrganizationTrustRelationship).where(
            OrganizationTrustRelationship.source_organization_id == source_org_id,
            OrganizationTrustRelationship.target_organization_id == target_org_id,
        )
    )
    if not trust:
        return _record_and_return_rejection(
            db,
            source_org_id,
            target_org_id,
            source_agent.id,
            target_agent.id,
            payload,
            reason="TRUST_NOT_FOUND: No trust relationship exists between these organizations",
            idempotency_key=idempotency_key,
            idempotency_hash=payload_hash,
        )

    if trust.status == TrustStatus.PENDING:
        return _record_and_return_rejection(
            db, source_org_id, target_org_id, source_agent.id, target_agent.id, payload,
            reason="TRUST_PENDING: Trust relationship is awaiting target acceptance",
            trust_id=trust.id, idempotency_key=idempotency_key, idempotency_hash=payload_hash,
        )
    if trust.status == TrustStatus.REVOKED:
        return _record_and_return_rejection(
            db, source_org_id, target_org_id, source_agent.id, target_agent.id, payload,
            reason="TRUST_REVOKED: Trust relationship has been revoked",
            trust_id=trust.id, idempotency_key=idempotency_key, idempotency_hash=payload_hash,
        )
    if trust.status == TrustStatus.EXPIRED or (trust.expires_at and trust.expires_at <= now):
        return _record_and_return_rejection(
            db, source_org_id, target_org_id, source_agent.id, target_agent.id, payload,
            reason="TRUST_EXPIRED: Trust relationship has expired",
            trust_id=trust.id, idempotency_key=idempotency_key, idempotency_hash=payload_hash,
        )
    if trust.status != TrustStatus.ACTIVE:
        return _record_and_return_rejection(
            db, source_org_id, target_org_id, source_agent.id, target_agent.id, payload,
            reason=f"TRUST_SUSPENDED: Trust relationship status is '{trust.status.value}'",
            trust_id=trust.id, idempotency_key=idempotency_key, idempotency_hash=payload_hash,
        )

    # 7. External Agent Connection Check
    connection = db.scalar(
        select(ExternalAgentConnection).where(
            ExternalAgentConnection.trust_relationship_id == trust.id,
            ExternalAgentConnection.source_agent_id == source_agent.id,
            ExternalAgentConnection.target_agent_id == target_agent.id,
        )
    )
    if not connection or not connection.is_usable(now):
        return _record_and_return_rejection(
            db, source_org_id, target_org_id, source_agent.id, target_agent.id, payload,
            reason="EXTERNAL_AGENT_CONNECTION_NOT_FOUND: No active connection between these agents",
            trust_id=trust.id, idempotency_key=idempotency_key, idempotency_hash=payload_hash,
        )

    # 8. Trust Policy Evaluation
    trust_policy = db.scalar(
        select(OrganizationTrustPolicy).where(OrganizationTrustPolicy.trust_relationship_id == trust.id)
    )
    if trust_policy:
        if trust_policy.allowed_actions and payload.action not in trust_policy.allowed_actions:
            return _record_and_return_rejection(
                db, source_org_id, target_org_id, source_agent.id, target_agent.id, payload,
                reason="CROSS_ORG_ACTION_NOT_ALLOWED: Action not permitted by trust policy",
                trust_id=trust.id, connection_id=connection.id,
                idempotency_key=idempotency_key, idempotency_hash=payload_hash,
            )
        if trust_policy.allowed_resources and payload.resource not in trust_policy.allowed_resources:
            return _record_and_return_rejection(
                db, source_org_id, target_org_id, source_agent.id, target_agent.id, payload,
                reason="CROSS_ORG_RESOURCE_NOT_ALLOWED: Resource not permitted by trust policy",
                trust_id=trust.id, connection_id=connection.id,
                idempotency_key=idempotency_key, idempotency_hash=payload_hash,
            )
        if trust_policy.max_amount is not None:
            if payload.amount is None or payload.amount > trust_policy.max_amount or payload.currency != trust_policy.currency:
                return _record_and_return_rejection(
                    db, source_org_id, target_org_id, source_agent.id, target_agent.id, payload,
                    reason="CROSS_ORG_AMOUNT_EXCEEDED: Amount exceeds trust policy limit",
                    trust_id=trust.id, connection_id=connection.id,
                    idempotency_key=idempotency_key, idempotency_hash=payload_hash,
                )

    # 9. Target Organization Policy Evaluation
    target_policy = db.scalar(
        select(TargetOrganizationPolicy).where(TargetOrganizationPolicy.organization_id == target_org_id)
    )
    if target_policy:
        if target_policy.allowed_actions and payload.action not in target_policy.allowed_actions:
            return _record_and_return_rejection(
                db, source_org_id, target_org_id, source_agent.id, target_agent.id, payload,
                reason="TARGET_POLICY_DENIED: Action not accepted by target organization",
                trust_id=trust.id, connection_id=connection.id,
                idempotency_key=idempotency_key, idempotency_hash=payload_hash,
            )
        if target_policy.allowed_resources and payload.resource not in target_policy.allowed_resources:
            return _record_and_return_rejection(
                db, source_org_id, target_org_id, source_agent.id, target_agent.id, payload,
                reason="TARGET_POLICY_DENIED: Resource not accepted by target organization",
                trust_id=trust.id, connection_id=connection.id,
                idempotency_key=idempotency_key, idempotency_hash=payload_hash,
            )
        if target_policy.max_amount is not None:
            if payload.amount is None or payload.amount > target_policy.max_amount or payload.currency != target_policy.currency:
                return _record_and_return_rejection(
                    db, source_org_id, target_org_id, source_agent.id, target_agent.id, payload,
                    reason="CROSS_ORG_AMOUNT_EXCEEDED: Amount exceeds target organization limit",
                    trust_id=trust.id, connection_id=connection.id,
                    idempotency_key=idempotency_key, idempotency_hash=payload_hash,
                )

    # 10. Strongest Restriction (Source Max Amount vs Trust Max vs Target Max)
    if source_perm and source_perm.maximum_amount is not None:
        if payload.amount and payload.amount > source_perm.maximum_amount:
            return _record_and_return_rejection(
                db, source_org_id, target_org_id, source_agent.id, target_agent.id, payload,
                reason="SOURCE_PERMISSION_DENIED: Amount exceeds source permission limit",
                trust_id=trust.id, connection_id=connection.id,
                idempotency_key=idempotency_key, idempotency_hash=payload_hash,
            )

    # 11. Human Approval Determination (Source vs Target vs Trust Policy)
    requires_source_approval = False
    requires_target_approval = False

    if source_perm and source_perm.requires_approval:
        requires_source_approval = True

    if trust_policy and trust_policy.require_human_approval:
        if trust_policy.approval_threshold is None or (payload.amount and payload.amount >= trust_policy.approval_threshold):
            if trust_policy.approval_type == "SOURCE_APPROVAL":
                requires_source_approval = True
            elif trust_policy.approval_type == "TARGET_APPROVAL":
                requires_target_approval = True
            elif trust_policy.approval_type == "BOTH_APPROVAL":
                requires_source_approval = True
                requires_target_approval = True

    if target_policy and target_policy.require_human_approval:
        if target_policy.approval_threshold is None or (payload.amount and payload.amount >= target_policy.approval_threshold):
            requires_target_approval = True

    # 12. Create CrossOrganizationRequest Record
    request_status = CrossOrgRequestStatus.PENDING if (requires_source_approval or requires_target_approval) else CrossOrgRequestStatus.APPROVED
    decision_reason = "Approved by cross-organization policy" if request_status == CrossOrgRequestStatus.APPROVED else "Awaiting required human approval"

    req = CrossOrganizationRequest(
        trust_relationship_id=trust.id,
        connection_id=connection.id if connection else None,
        source_organization_id=source_org_id,
        target_organization_id=target_org_id,
        source_agent_id=source_agent.id,
        target_agent_id=target_agent.id,
        action=payload.action,
        resource=payload.resource,
        amount=payload.amount,
        currency=payload.currency,
        status=request_status,
        decision_reason=decision_reason,
        idempotency_key=idempotency_key,
        idempotency_hash=payload_hash,
        expires_at=now + EXPIRY_WINDOW,
        completed_at=now if request_status == CrossOrgRequestStatus.APPROVED else None,
    )
    db.add(req)
    db.flush()

    pending_stages: list[str] = []
    if requires_source_approval:
        pending_stages.append("SOURCE")
        appr_src = CrossOrganizationApproval(
            cross_org_request_id=req.id,
            organization_id=source_org_id,
            approval_stage=ApprovalStage.SOURCE,
            required_role="admin",
            status=ApprovalStatus.PENDING,
        )
        db.add(appr_src)

    if requires_target_approval:
        pending_stages.append("TARGET")
        appr_tgt = CrossOrganizationApproval(
            cross_org_request_id=req.id,
            organization_id=target_org_id,
            approval_stage=ApprovalStage.TARGET,
            required_role="admin",
            status=ApprovalStatus.PENDING,
        )
        db.add(appr_tgt)

    # 13. Dual Privacy-Preserving Audit Logs
    _record_dual_audit_logs(
        db,
        source_org_id=source_org_id,
        target_org_id=target_org_id,
        source_agent=source_agent,
        target_agent=target_agent,
        action=payload.action,
        resource=payload.resource,
        decision=AuditDecision.APPROVED if request_status == CrossOrgRequestStatus.APPROVED else AuditDecision.REJECTED,
        reason=decision_reason,
        amount=payload.amount,
        currency=payload.currency,
    )

    db.commit()
    db.refresh(req)

    return CrossOrgAuthorizeResponse(
        request_id=req.request_id,
        status=req.status.value,
        reason=decision_reason,
        pending_approvals=pending_stages,
    )


def decide_cross_org_approval(
    db: Session,
    request_id: str,
    user_id: UUID,
    caller_org_id: UUID,
    decision: Literal["APPROVED", "REJECTED"],
    reason: str | None = None,
) -> CrossOrganizationRequest:
    """Multi-party approval decision handler."""
    req = db.scalar(
        select(CrossOrganizationRequest).where(CrossOrganizationRequest.request_id == request_id)
    )
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cross-organization request not found")

    if req.status != CrossOrgRequestStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Request is not pending (current status: '{req.status.value}')",
        )

    # Find the approval entry belonging to caller's organization
    approval = db.scalar(
        select(CrossOrganizationApproval).where(
            CrossOrganizationApproval.cross_org_request_id == req.id,
            CrossOrganizationApproval.organization_id == caller_org_id,
        )
    )
    if not approval:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your organization does not have an active approval requirement for this request",
        )

    if approval.status != ApprovalStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Your organization has already decided this approval ({approval.status.value})",
        )

    now = datetime.now(timezone.utc)
    approval.status = ApprovalStatus[decision]
    approval.decided_by_user_id = user_id
    approval.decided_at = now
    approval.reason = reason

    if decision == "REJECTED":
        # Unilateral rejection: if either party rejects, overall request is REJECTED
        req.status = CrossOrgRequestStatus.REJECTED
        req.decision_reason = f"Rejected by {approval.approval_stage.value} organization: {reason or 'Denied'}"
        req.completed_at = now
    else:
        # Check if any other approval stages are still PENDING
        remaining = db.scalar(
            select(CrossOrganizationApproval).where(
                CrossOrganizationApproval.cross_org_request_id == req.id,
                CrossOrganizationApproval.status == ApprovalStatus.PENDING,
            )
        )
        if not remaining:
            req.status = CrossOrgRequestStatus.APPROVED
            req.decision_reason = "All required cross-organization approvals received"
            req.completed_at = now

    db.commit()
    db.refresh(req)

    record_security_event(
        db,
        actor_user_id=user_id,
        event_type=f"cross_org_approval_{decision.lower()}",
        organization_id=caller_org_id,
        severity="info",
        description=f"Decided {approval.approval_stage.value} approval for cross-org request {request_id}: {decision}",
        details={"request_id": request_id, "decision": decision, "reason": reason},
    )
    return req


def _record_and_return_rejection(
    db: Session,
    source_org_id: UUID,
    target_org_id: UUID,
    source_agent_id: UUID,
    target_agent_id: UUID,
    payload: CrossOrgAuthorizePayload,
    reason: str,
    trust_id: UUID | None = None,
    connection_id: UUID | None = None,
    idempotency_key: str | None = None,
    idempotency_hash: str | None = None,
) -> CrossOrgAuthorizeResponse:
    now = datetime.now(timezone.utc)
    req = CrossOrganizationRequest(
        trust_relationship_id=trust_id or UUID("00000000-0000-0000-0000-000000000000"),
        connection_id=connection_id,
        source_organization_id=source_org_id,
        target_organization_id=target_org_id,
        source_agent_id=source_agent_id,
        target_agent_id=target_agent_id,
        action=payload.action,
        resource=payload.resource,
        amount=payload.amount,
        currency=payload.currency,
        status=CrossOrgRequestStatus.REJECTED,
        decision_reason=reason,
        idempotency_key=idempotency_key,
        idempotency_hash=idempotency_hash,
        completed_at=now,
    )
    if trust_id:
        db.add(req)
        db.commit()
        db.refresh(req)
        request_id = req.request_id
    else:
        request_id = f"xreq_denied_{hashlib.sha256(now.isoformat().encode()).hexdigest()[:16]}"

    return CrossOrgAuthorizeResponse(
        request_id=request_id,
        status="REJECTED",
        reason=reason,
    )


def _record_dual_audit_logs(
    db: Session,
    source_org_id: UUID,
    target_org_id: UUID,
    source_agent: Agent,
    target_agent: Agent,
    action: str,
    resource: str,
    decision: AuditDecision,
    reason: str,
    amount: Decimal | None,
    currency: str | None,
) -> None:
    now = datetime.now(timezone.utc)
    # Source Audit Log (Outbound)
    audit_source = AuditLog(
        request_id=f"req_{secrets.token_hex(12)}",
        user_id=source_agent.owner_id,
        organization_id=source_org_id,
        agent_id=source_agent.id,
        agent_identifier=source_agent.agent_identifier,
        action=action,
        resource=resource,
        amount=amount,
        currency=currency,
        decision=decision,
        reason=(f"Outbound cross-org request to {target_agent.name}: {reason}")[:255],
        signature_verified=True,
        signature_version="v2",
        requested_at=now,
    )
    db.add(audit_source)

    # Target Audit Log (Inbound)
    audit_target = AuditLog(
        request_id=f"req_{secrets.token_hex(12)}",
        user_id=target_agent.owner_id,
        organization_id=target_org_id,
        agent_id=target_agent.id,
        agent_identifier=target_agent.agent_identifier,
        action=action,
        resource=resource,
        amount=amount,
        currency=currency,
        decision=decision,
        reason=(f"Inbound cross-org request from {source_agent.name}: {reason}")[:255],
        signature_verified=True,
        signature_version="v2",
        requested_at=now,
    )
    db.add(audit_target)
