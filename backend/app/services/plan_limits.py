"""Central subscription lookup, resource limits, and concurrency-safe usage metering."""

from calendar import monthrange
from dataclasses import dataclass
from datetime import date, datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models import (
    APIKey, APIKeyStatus, Agent, InvitationStatus, MemberStatus,
    NotificationPriority, NotificationType, Organization, OrganizationInvitation,
    OrganizationMember, OrganizationSubscription, SubscriptionPlan,
    SubscriptionStatus, UsageMetric, UsageRecord, WebhookEndpoint,
)
from app.services.notification_service import create_notification


class PlanLimitReached(Exception):
    def __init__(self, message: str):
        self.code = "PLAN_LIMIT_REACHED"
        self.message = message
        super().__init__(message)


def month_period(at: datetime | None = None) -> tuple[date, date]:
    current = (at or datetime.now(timezone.utc)).date()
    start = current.replace(day=1)
    end = date(current.year + (1 if current.month == 12 else 0), 1 if current.month == 12 else current.month + 1, 1)
    return start, end


def get_plan(db: Session, code: str) -> SubscriptionPlan | None:
    return db.scalar(select(SubscriptionPlan).where(SubscriptionPlan.code == code, SubscriptionPlan.is_active.is_(True)))


def ensure_subscription(db: Session, organization_id: UUID, *, lock: bool = False) -> tuple[OrganizationSubscription, SubscriptionPlan]:
    query = select(OrganizationSubscription).where(OrganizationSubscription.organization_id == organization_id)
    if lock:
        query = query.with_for_update()
    subscription = db.scalar(query)
    if subscription is None:
        plan = get_plan(db, "free")
        if plan is None:
            raise RuntimeError("Free subscription plan is not configured")
        start, end = month_period()
        subscription = OrganizationSubscription(
            organization_id=organization_id, plan_id=plan.id,
            current_period_start=datetime.combine(start, datetime.min.time(), timezone.utc),
            current_period_end=datetime.combine(end, datetime.min.time(), timezone.utc),
        )
        db.add(subscription)
        db.flush()
        return subscription, plan
    plan = db.get(SubscriptionPlan, subscription.plan_id)
    if plan is None or not plan.is_active:
        raise RuntimeError("Organization subscription plan is unavailable")
    return subscription, plan


def attach_free_subscription(db: Session, organization_id: UUID) -> OrganizationSubscription:
    subscription, _ = ensure_subscription(db, organization_id)
    return subscription


def _check_subscription_access(subscription: OrganizationSubscription, plan: SubscriptionPlan) -> None:
    now = datetime.now(timezone.utc)
    if subscription.status == SubscriptionStatus.PAST_DUE and subscription.grace_ends_at and now <= subscription.grace_ends_at:
        return
    if subscription.status in {SubscriptionStatus.INCOMPLETE, SubscriptionStatus.SUSPENDED, SubscriptionStatus.PAST_DUE}:
        raise PlanLimitReached("Billing is restricted. Security history remains available while the owner resolves billing.")


def _count_for_resource(db: Session, organization_id: UUID, resource: str) -> int:
    if resource == "agents":
        return db.scalar(select(func.count()).select_from(Agent).where(Agent.organization_id == organization_id)) or 0
    if resource == "api keys":
        return db.scalar(select(func.count()).select_from(APIKey).where(
            APIKey.organization_id == organization_id, APIKey.status == APIKeyStatus.ACTIVE,
        )) or 0
    if resource == "team members":
        # Owner is included automatically; max_members is the number of additional seats.
        members = db.scalar(select(func.count()).select_from(OrganizationMember).where(
            OrganizationMember.organization_id == organization_id,
            OrganizationMember.status == MemberStatus.ACTIVE,
            OrganizationMember.role != "owner",
        )) or 0
        pending = db.scalar(select(func.count()).select_from(OrganizationInvitation).where(
            OrganizationInvitation.organization_id == organization_id,
            OrganizationInvitation.status == InvitationStatus.PENDING,
            OrganizationInvitation.expires_at > datetime.now(timezone.utc),
        )) or 0
        return members + pending
    if resource == "webhooks":
        return db.scalar(select(func.count()).select_from(WebhookEndpoint).where(
            WebhookEndpoint.organization_id == organization_id,
        )) or 0
    raise ValueError("Unknown plan resource")


def enforce_resource_limit(db: Session, organization_id: UUID | None, resource: str) -> None:
    if organization_id is None:
        return
    subscription, plan = ensure_subscription(db, organization_id, lock=True)
    _check_subscription_access(subscription, plan)
    limit = {
        "agents": plan.max_agents,
        "api keys": plan.max_api_keys,
        "team members": plan.max_members,
        "webhooks": plan.max_webhooks,
    }[resource]
    if limit is not None and _count_for_resource(db, organization_id, resource) >= limit:
        raise PlanLimitReached(f"Your {plan.name} plan supports up to {limit} {resource}.")


def _usage_record(db: Session, organization_id: UUID, metric: UsageMetric, *, lock: bool = True) -> UsageRecord:
    start, end = month_period()
    db.execute(pg_insert(UsageRecord).values(
        id=uuid4(), organization_id=organization_id, metric=metric,
        period_start=start, period_end=end, quantity=0,
    ).on_conflict_do_nothing(index_elements=["organization_id", "metric", "period_start"]))
    query = select(UsageRecord).where(
        UsageRecord.organization_id == organization_id,
        UsageRecord.metric == metric,
        UsageRecord.period_start == start,
    )
    if lock:
        query = query.with_for_update()
    return db.scalar(query)


def consume_authorization_request(db: Session, organization_id: UUID) -> UsageRecord:
    subscription, plan = ensure_subscription(db, organization_id, lock=True)
    _check_subscription_access(subscription, plan)
    record = _usage_record(db, organization_id, UsageMetric.AUTHORIZATION_REQUESTS)
    limit = plan.max_authorization_requests_monthly
    if limit is not None and record.quantity >= limit:
        _notify_usage(db, organization_id, record, plan, 100)
        db.commit()
        raise PlanLimitReached(f"Your {plan.name} plan monthly authorization request limit has been reached.")
    record.quantity += 1
    if limit:
        percent = record.quantity * 100 // limit
        for threshold in (100, 90, 80):
            if percent >= threshold:
                _notify_usage(db, organization_id, record, plan, threshold)
                break
    db.commit()
    db.refresh(record)
    return record


def release_authorization_request(db: Session, organization_id: UUID) -> None:
    record = _usage_record(db, organization_id, UsageMetric.AUTHORIZATION_REQUESTS)
    if record.quantity > 0:
        record.quantity -= 1
    db.commit()


def _notify_usage(db: Session, organization_id: UUID, record: UsageRecord, plan: SubscriptionPlan, threshold: int) -> None:
    organization = db.get(Organization, organization_id)
    create_notification(
        db, user_id=organization.owner_id, organization_id=organization_id,
        notification_type=NotificationType.BILLING_USAGE_WARNING,
        title="Monthly Usage Warning" if threshold < 100 else "Monthly Request Limit Reached",
        message=(f"You have used {threshold}% of your monthly authorization requests."
                 if threshold < 100 else "Your monthly authorization request limit has been reached."),
        priority=NotificationPriority.HIGH if threshold < 100 else NotificationPriority.CRITICAL,
        metadata={"metric": record.metric.value, "threshold": threshold, "plan": plan.code},
        deduplication_key=f"billing-usage:{organization_id}:{record.period_start}:{record.metric.value}:{threshold}",
    )


@dataclass(frozen=True)
class UsageValue:
    used: int
    limit: int | None


def usage_values(db: Session, organization_id: UUID) -> tuple[OrganizationSubscription, SubscriptionPlan, dict[str, UsageValue]]:
    subscription, plan = ensure_subscription(db, organization_id)
    authorization = _usage_record(db, organization_id, UsageMetric.AUTHORIZATION_REQUESTS, lock=False)
    values = {
        "authorization_requests": UsageValue(authorization.quantity, plan.max_authorization_requests_monthly),
        "agents": UsageValue(_count_for_resource(db, organization_id, "agents"), plan.max_agents),
        "api_keys": UsageValue(_count_for_resource(db, organization_id, "api keys"), plan.max_api_keys),
        "team_members": UsageValue(_count_for_resource(db, organization_id, "team members"), plan.max_members),
        "webhooks": UsageValue(_count_for_resource(db, organization_id, "webhooks"), plan.max_webhooks),
    }
    db.commit()
    return subscription, plan, values
