"""Organization billing lifecycle, driven only by trusted provider webhooks."""

from datetime import datetime, timedelta, timezone
import json
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import (BillingCheckout, BillingEvent, BillingEventStatus, NotificationPriority,
    NotificationType, Organization, OrganizationSubscription, SubscriptionPlan, SubscriptionStatus)
from app.services.billing_providers import BillingProviderError, provider_for
from app.services.notification_service import create_notification
from app.services.plan_limits import ensure_subscription, month_period
from app.services.security_events import record_security_event


class BillingInputError(Exception): pass


def configure_plan_prices(db: Session, settings: Settings) -> None:
    configured = {"starter": settings.billing_starter_monthly_price, "business": settings.billing_business_monthly_price}
    changed = False
    for plan in db.scalars(select(SubscriptionPlan).where(SubscriptionPlan.code.in_(configured))):
        if plan.monthly_price != configured[plan.code]:
            plan.monthly_price = configured[plan.code]; changed = True
    if changed: db.commit()


def list_plans(db: Session, settings: Settings) -> list[SubscriptionPlan]:
    configure_plan_prices(db, settings)
    return list(db.scalars(select(SubscriptionPlan).where(SubscriptionPlan.is_active.is_(True)).order_by(SubscriptionPlan.monthly_price.asc().nulls_last())))


def create_checkout(db: Session, settings: Settings, organization_id: UUID, user_id: UUID, email: str, plan_code: str) -> str:
    configure_plan_prices(db, settings)
    plan = db.scalar(select(SubscriptionPlan).where(SubscriptionPlan.code == plan_code, SubscriptionPlan.is_active.is_(True)))
    if plan is None or plan.code in {"free", "enterprise"}:
        raise BillingInputError("This plan cannot be purchased through checkout")
    price_id = settings.billing_price_starter_monthly if plan.code == "starter" else settings.billing_price_business_monthly
    if settings.billing_provider == "paddle_sandbox" and not price_id:
        raise BillingInputError("The sandbox price is not configured")
    session = provider_for(settings).create_checkout(price_id=price_id or f"test_{plan.code}", organization_id=str(organization_id), plan_code=plan.code, user_email=email)
    db.add(BillingCheckout(organization_id=organization_id, plan_id=plan.id, created_by_user_id=user_id,
        provider_session_id=session.id, expires_at=datetime.now(timezone.utc) + timedelta(hours=1)))
    record_security_event(db, user_id, "billing.checkout_created", organization_id=organization_id, description=f"Plan: {plan.code}", commit=False)
    db.commit()
    return session.url


def portal_url(db: Session, settings: Settings, organization_id: UUID) -> str:
    subscription, _ = ensure_subscription(db, organization_id)
    if not subscription.provider_customer_id: raise BillingInputError("No billing portal is available for this subscription")
    return provider_for(settings).create_portal(subscription.provider_customer_id)


def cancel(db: Session, settings: Settings, organization_id: UUID, user_id: UUID) -> OrganizationSubscription:
    subscription, plan = ensure_subscription(db, organization_id, lock=True)
    if plan.code == "free": raise BillingInputError("The Free plan has no paid subscription to cancel")
    if subscription.provider_subscription_id:
        provider_for(settings).cancel_subscription(subscription.provider_subscription_id)
    subscription.cancel_at_period_end = True
    record_security_event(db, user_id, "billing.cancellation_scheduled", organization_id=organization_id, description=f"Plan: {plan.code}", commit=False)
    organization = db.get(Organization, organization_id)
    create_notification(db, user_id=organization.owner_id, organization_id=organization_id,
        notification_type=NotificationType.BILLING_CANCELING, title="Subscription Cancellation Scheduled",
        message=f"Your {plan.name} plan will remain active until the current billing period ends.",
        priority=NotificationPriority.HIGH, deduplication_key=f"billing-cancel:{subscription.id}:{subscription.current_period_end.isoformat()}")
    db.commit(); db.refresh(subscription)
    return subscription


def _parse_time(value, fallback: datetime) -> datetime:
    if not value: return fallback
    try: return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError): return fallback


def process_webhook(db: Session, settings: Settings, body: bytes, signature: str) -> str:
    provider = provider_for(settings)
    if not provider.verify_webhook(body, signature): raise BillingInputError("Invalid billing webhook signature")
    try:
        payload = json.loads(body); event_id = str(payload["event_id"]); event_type = str(payload["event_type"]); data = payload.get("data") or {}
    except (ValueError, KeyError, TypeError): raise BillingInputError("Invalid billing webhook payload") from None
    if not event_id or len(event_id) > 100 or not event_type or len(event_type) > 80 or not isinstance(data, dict):
        raise BillingInputError("Invalid billing webhook payload")
    existing = db.scalar(select(BillingEvent).where(BillingEvent.provider_event_id == event_id))
    if existing: return "duplicate"
    custom = data.get("custom_data") or {}
    try: organization_id = UUID(str(custom.get("organization_id")))
    except (ValueError, TypeError): organization_id = None
    event = BillingEvent(provider_event_id=event_id, event_type=event_type, organization_id=organization_id, status=BillingEventStatus.IGNORED)
    db.add(event)
    try: db.flush()
    except IntegrityError:
        db.rollback(); return "duplicate"
    checkout = db.scalar(select(BillingCheckout).where(BillingCheckout.provider_session_id == str(data.get("id"))))
    if checkout is not None:
        organization_id = checkout.organization_id; event.organization_id = organization_id
    if organization_id is None or db.get(Organization, organization_id) is None:
        event.processed_at = datetime.now(timezone.utc); db.commit(); return "ignored"
    subscription, old_plan = ensure_subscription(db, organization_id, lock=True)
    plan_code = custom.get("plan_code")
    plan = db.scalar(select(SubscriptionPlan).where(SubscriptionPlan.code == plan_code)) if plan_code else None
    now = datetime.now(timezone.utc)
    if event_type in {"transaction.completed", "subscription.created", "subscription.updated"} and plan is not None:
        start, end = month_period(now)
        subscription.plan_id = plan.id; subscription.status = SubscriptionStatus.ACTIVE
        subscription.billing_provider = settings.billing_provider
        subscription.provider_customer_id = data.get("customer_id") or subscription.provider_customer_id
        subscription.provider_subscription_id = data.get("subscription_id") or data.get("id") or subscription.provider_subscription_id
        subscription.current_period_start = _parse_time(data.get("current_billing_period", {}).get("starts_at"), datetime.combine(start, datetime.min.time(), timezone.utc))
        subscription.current_period_end = _parse_time(data.get("current_billing_period", {}).get("ends_at"), datetime.combine(end, datetime.min.time(), timezone.utc))
        subscription.cancel_at_period_end = False; subscription.grace_ends_at = None
        if checkout: checkout.status = "completed"
        event.status = BillingEventStatus.PROCESSED
        organization = db.get(Organization, organization_id)
        create_notification(db, user_id=organization.owner_id, organization_id=organization_id,
            notification_type=NotificationType.BILLING_PLAN_CHANGED, title="Subscription Updated", message=f"Your plan is now {plan.name}.",
            metadata={"plan": plan.code}, deduplication_key=f"billing-event:{event_id}")
        record_security_event(db, organization.owner_id, "billing.plan_changed", organization_id=organization_id, description=f"{old_plan.code} to {plan.code}", commit=False)
    elif event_type in {"subscription.past_due", "transaction.payment_failed"}:
        subscription.status = SubscriptionStatus.PAST_DUE; subscription.grace_ends_at = now + timedelta(days=settings.billing_grace_period_days)
        event.status = BillingEventStatus.PROCESSED
        organization = db.get(Organization, organization_id)
        create_notification(db, user_id=organization.owner_id, organization_id=organization_id,
            notification_type=NotificationType.BILLING_PAYMENT_FAILED, title="Sandbox Payment Failed", message="Billing is past due. A grace period is active.",
            priority=NotificationPriority.CRITICAL, deduplication_key=f"billing-event:{event_id}")
    elif event_type in {"subscription.canceled", "subscription.cancelled"}:
        free = db.scalar(select(SubscriptionPlan).where(SubscriptionPlan.code == "free"))
        subscription.plan_id = free.id; subscription.status = SubscriptionStatus.CANCELED; subscription.canceled_at = now; subscription.cancel_at_period_end = False
        event.status = BillingEventStatus.PROCESSED
    event.processed_at = now
    db.commit()
    return event.status.value
