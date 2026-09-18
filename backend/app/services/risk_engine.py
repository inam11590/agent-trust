"""Fast, transparent risk scoring run only after permission validation succeeds."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Protocol
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import (
    APIKey, Agent, AuditDecision, AuditLog, Permission, RiskAction,
    RiskAssessment, RiskLevel, RiskPolicy,
)
from app.core.observability import metrics
from app.schemas.authorization import AuthorizationRequest

RULE_MODEL_VERSION = "rules-v1"


@dataclass(frozen=True)
class RiskEvaluation:
    score: int
    level: RiskLevel
    recommendation: RiskAction
    reasons: tuple[str, ...]
    features: dict[str, int | float | bool | None]


class RiskProvider(Protocol):
    def evaluate(
        self, db: Session, *, user_id: UUID, organization_id: UUID | None,
        agent: Agent, permission: Permission, request: AuthorizationRequest,
        requested_at: datetime, policy: RiskPolicy, api_key: APIKey | None = None,
    ) -> RiskEvaluation: ...


def get_or_create_policy(
    db: Session, user_id: UUID, organization_id: UUID | None,
) -> RiskPolicy:
    condition = (
        RiskPolicy.organization_id == organization_id
        if organization_id is not None
        else RiskPolicy.user_id == user_id
    )
    policy = db.scalar(select(RiskPolicy).where(condition))
    if policy is None:
        policy = RiskPolicy(
            organization_id=organization_id,
            user_id=None if organization_id is not None else user_id,
        )
        db.add(policy)
        db.flush()
    return policy


def risk_level(score: int, settings: Settings) -> RiskLevel:
    if score <= settings.risk_low_max:
        return RiskLevel.LOW
    if score <= settings.risk_medium_max:
        return RiskLevel.MEDIUM
    if score <= settings.risk_high_max:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def policy_action(level: RiskLevel, policy: RiskPolicy) -> RiskAction:
    if level == RiskLevel.LOW:
        return RiskAction.ALLOW
    if level == RiskLevel.MEDIUM:
        return policy.medium_action
    if level == RiskLevel.HIGH:
        return policy.high_action
    return policy.critical_action


class RuleBasedRiskProvider:
    """Score bounded recent aggregates; rule points live in this one module."""

    def __init__(self, settings: Settings):
        self.settings = settings

    def evaluate(
        self, db: Session, *, user_id: UUID, organization_id: UUID | None,
        agent: Agent, permission: Permission, request: AuthorizationRequest,
        requested_at: datetime, policy: RiskPolicy, api_key: APIKey | None = None,
    ) -> RiskEvaluation:
        if not policy.enabled:
            return RiskEvaluation(0, RiskLevel.LOW, RiskAction.ALLOW, ("Risk checks are disabled",), {})

        score = 0
        reasons: list[str] = []
        agent_env = getattr(agent, "environment", "production")
        history_start = requested_at - timedelta(days=self.settings.risk_history_days)
        recent_amounts = list(db.scalars(
            select(AuditLog.amount).where(
                AuditLog.agent_id == agent.id,
                AuditLog.environment == agent_env,
                AuditLog.decision == AuditDecision.APPROVED,
                AuditLog.action == request.action,
                AuditLog.resource == request.resource,
                AuditLog.currency == request.currency,
                AuditLog.amount.is_not(None),
                AuditLog.requested_at >= history_start,
            ).order_by(AuditLog.requested_at.desc()).limit(20)
        ))
        average_amount = (
            sum((Decimal(value) for value in recent_amounts), Decimal("0")) / len(recent_amounts)
            if recent_amounts else None
        )

        if policy.amount_anomaly_enabled and request.amount is not None:
            if average_amount and average_amount > 0:
                ratio = request.amount / average_amount
                if ratio >= 4:
                    score += 45; reasons.append("Amount is much higher than recent activity")
                elif ratio >= 2:
                    score += 25; reasons.append("Amount is higher than recent activity")
                elif ratio >= Decimal("1.5"):
                    score += 15; reasons.append("Amount is above the recent average")
            if permission.maximum_amount:
                limit_ratio = request.amount / permission.maximum_amount
                if limit_ratio >= Decimal("0.90"):
                    score += 15; reasons.append("Amount is close to the permission limit")
                elif limit_ratio >= Decimal("0.75"):
                    score += 8; reasons.append("Amount uses most of the permission limit")

        velocity_start = requested_at - timedelta(seconds=self.settings.risk_velocity_window_seconds)
        recent_requests = db.scalar(select(func.count()).select_from(RiskAssessment).where(
            RiskAssessment.agent_id == agent.id, RiskAssessment.created_at >= velocity_start,
        )) or 0
        if policy.velocity_enabled:
            if recent_requests >= self.settings.risk_velocity_critical_count:
                score += 55; reasons.append("Very high request frequency")
            elif recent_requests >= self.settings.risk_velocity_high_count:
                score += 35; reasons.append("High request frequency")
            elif recent_requests >= self.settings.risk_velocity_medium_count:
                score += 18; reasons.append("Request frequency is above normal")

        rejection_start = requested_at - timedelta(minutes=self.settings.risk_rejection_window_minutes)
        recent_rejections = db.scalar(select(func.count()).select_from(AuditLog).where(
            AuditLog.agent_id == agent.id,
            AuditLog.environment == agent_env,
            AuditLog.decision == AuditDecision.REJECTED,
            AuditLog.requested_at >= rejection_start,
        )) or 0
        if policy.rejection_history_enabled:
            if recent_rejections >= 5:
                score += 25; reasons.append("Multiple recent rejected requests")
            elif recent_rejections >= 3:
                score += 15; reasons.append("Several recent rejected requests")

        agent_age_hours = max(0.0, (requested_at - agent.created_at).total_seconds() / 3600)
        if agent_age_hours < self.settings.risk_new_agent_hours and request.amount is not None:
            score += 10; reasons.append("Agent was created recently")

        permission_age_minutes = max(0.0, (requested_at - permission.updated_at).total_seconds() / 60)
        if permission_age_minutes < self.settings.risk_recent_permission_minutes and request.amount is not None:
            score += 5; reasons.append("Permission was created or changed recently")

        history_count = db.scalar(select(func.count()).select_from(AuditLog).where(
            AuditLog.agent_id == agent.id, AuditLog.requested_at >= history_start,
        )) or 0
        if history_count >= 3:
            action_count = db.scalar(select(func.count()).select_from(AuditLog).where(
                AuditLog.agent_id == agent.id, AuditLog.action == request.action,
                AuditLog.requested_at >= history_start,
            )) or 0
            resource_count = db.scalar(select(func.count()).select_from(AuditLog).where(
                AuditLog.agent_id == agent.id, AuditLog.resource == request.resource,
                AuditLog.requested_at >= history_start,
            )) or 0
            if action_count == 0:
                score += 12; reasons.append("Action is unusual for this agent")
            if resource_count == 0:
                score += 12; reasons.append("Resource is unusual for this agent")

        api_key_recent = False
        if api_key is not None:
            api_key_recent = requested_at - api_key.created_at < timedelta(hours=1)
            if api_key_recent:
                score += 5; reasons.append("API key was created recently")

        score = min(score, 100)
        level = risk_level(score, self.settings)
        return RiskEvaluation(
            score, level, policy_action(level, policy), tuple(reasons or ["No unusual activity detected"]),
            {
                "historical_amount_count": len(recent_amounts),
                "amount_to_average_ratio": float(request.amount / average_amount) if request.amount is not None and average_amount else None,
                "request_count_in_window": int(recent_requests),
                "recent_rejection_count": int(recent_rejections),
                "agent_age_hours": round(agent_age_hours, 2),
                "permission_age_minutes": round(permission_age_minutes, 2),
                "api_key_recent": api_key_recent,
            },
        )


def evaluate_and_save(
    db: Session, settings: Settings, *, request_id: str, user_id: UUID,
    organization_id: UUID | None, agent: Agent, permission: Permission,
    request: AuthorizationRequest, requested_at: datetime,
    api_key: APIKey | None = None, provider: RiskProvider | None = None,
) -> tuple[RiskAssessment, RiskEvaluation]:
    policy = get_or_create_policy(db, user_id, organization_id)
    evaluation = (provider or RuleBasedRiskProvider(settings)).evaluate(
        db, user_id=user_id, organization_id=organization_id, agent=agent,
        permission=permission, request=request, requested_at=requested_at,
        policy=policy, api_key=api_key,
    )
    assessment = RiskAssessment(
        request_id=request_id, user_id=user_id, organization_id=organization_id,
        agent_id=agent.id, permission_id=permission.id,
        risk_score=evaluation.score, risk_level=evaluation.level,
        decision_recommendation=evaluation.recommendation,
        reasons=list(evaluation.reasons), features=evaluation.features,
        model_version=RULE_MODEL_VERSION,
    )
    db.add(assessment)
    db.flush()
    metrics.event(f"risk_{evaluation.level.value.lower()}")
    return assessment, evaluation
