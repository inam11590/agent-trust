"""Tenant-scoped risk history and policy management."""

from math import ceil
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Agent, AuditLog, AuthorizationRequestRecord, RiskAssessment, RiskLevel, RiskPolicy
from app.schemas.risk import RiskAssessmentResponse, RiskFilters, RiskPolicyUpdate
from app.services.risk_engine import get_or_create_policy


def _scope(user_id: UUID, organization_id: UUID | None):
    return (
        RiskAssessment.organization_id == organization_id
        if organization_id is not None
        else (RiskAssessment.user_id == user_id) & RiskAssessment.organization_id.is_(None)
    )


def _view(
    assessment: RiskAssessment, agent: Agent,
    pending: AuthorizationRequestRecord | None, audit: AuditLog | None,
) -> RiskAssessmentResponse:
    source = pending or audit
    return RiskAssessmentResponse(
        id=assessment.id, request_id=assessment.request_id,
        agent_id=assessment.agent_id,
        agent_identifier=agent.agent_identifier,
        agent_name=agent.name,
        action=source.action, resource=source.resource, amount=source.amount,
        currency=source.currency, risk_score=assessment.risk_score,
        risk_level=assessment.risk_level,
        recommendation=assessment.decision_recommendation,
        reasons=list(assessment.reasons),
        final_status=pending.status.value if pending else audit.decision.value,
        model_version=assessment.model_version, created_at=assessment.created_at,
    )


def list_assessments(
    db: Session, user_id: UUID, organization_id: UUID | None, filters: RiskFilters,
) -> tuple[list[RiskAssessmentResponse], int, int]:
    conditions = [_scope(user_id, organization_id)]
    if filters.level is not None:
        conditions.append(RiskAssessment.risk_level == filters.level)
    total = db.scalar(select(func.count()).select_from(RiskAssessment).where(*conditions)) or 0
    rows = db.execute(
        select(RiskAssessment, Agent, AuthorizationRequestRecord, AuditLog)
        .join(Agent, Agent.id == RiskAssessment.agent_id)
        .outerjoin(AuthorizationRequestRecord, AuthorizationRequestRecord.request_id == RiskAssessment.request_id)
        .outerjoin(AuditLog, AuditLog.request_id == RiskAssessment.request_id)
        .where(*conditions)
        .order_by(RiskAssessment.created_at.desc(), RiskAssessment.id.desc())
        .offset((filters.page - 1) * filters.page_size).limit(filters.page_size)
    ).all()
    return [_view(*row) for row in rows], total, ceil(total / filters.page_size) if total else 0


def get_assessment(
    db: Session, user_id: UUID, organization_id: UUID | None, assessment_id: UUID,
) -> RiskAssessmentResponse | None:
    row = db.execute(
        select(RiskAssessment, Agent, AuthorizationRequestRecord, AuditLog)
        .join(Agent, Agent.id == RiskAssessment.agent_id)
        .outerjoin(AuthorizationRequestRecord, AuthorizationRequestRecord.request_id == RiskAssessment.request_id)
        .outerjoin(AuditLog, AuditLog.request_id == RiskAssessment.request_id)
        .where(RiskAssessment.id == assessment_id, _scope(user_id, organization_id))
    ).one_or_none()
    return _view(*row) if row else None


def overview(db: Session, user_id: UUID, organization_id: UUID | None) -> dict[RiskLevel, int]:
    rows = db.execute(select(RiskAssessment.risk_level, func.count()).where(
        _scope(user_id, organization_id),
    ).group_by(RiskAssessment.risk_level)).all()
    values = {level: 0 for level in RiskLevel}
    values.update({level: count for level, count in rows})
    return values


def update_policy(
    db: Session, user_id: UUID, organization_id: UUID | None, payload: RiskPolicyUpdate,
) -> RiskPolicy:
    policy = get_or_create_policy(db, user_id, organization_id)
    for name, value in payload.model_dump(exclude_none=True).items():
        setattr(policy, name, value)
    db.commit()
    db.refresh(policy)
    return policy
