"""Database-backed notification delivery and permission-expiry jobs."""

from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import (
    Agent, AgentSigningKey, AgentSigningKeyStatus, DeliveryChannel, DeliveryStatus, Device, DeviceStatus, Notification,
    NotificationDelivery, NotificationPriority, NotificationType, Permission,
    PermissionStatus, User,
)
from app.services.notification_providers import DeliveryProviderError, FirebasePushProvider, email_provider
from app.services.notification_service import create_notification
from app.services.notification_service import get_preferences
from app.services.security_events import record_security_event
from app.core.observability import metrics


def render_email(notification: Notification) -> str:
    """Return a plain-text template with safe action details and no direct approval action."""
    data = notification.metadata_json or {}
    if notification.type == NotificationType.AUTHORIZATION_PENDING:
        amount = f"{data.get('amount')} {data.get('currency')}" if data.get("amount") else "Not specified"
        return (
            f"{data.get('agent', 'An AI agent')} wants permission to:\n\n"
            f"Action: {str(data.get('action', '')).title()}\n"
            f"Resource: {str(data.get('resource', '')).title()}\n"
            f"Amount: {amount}\n\nOpen AgentTrust and sign in to approve or reject this request."
        )
    return f"{notification.message}\n\nOpen AgentTrust to review this event."


def process_permission_expiry_notifications(db: Session, settings: Settings, now: datetime | None = None) -> int:
    checked_at = now or datetime.now(timezone.utc)
    warning_end = checked_at + timedelta(minutes=settings.permission_expiry_warning_minutes)
    permissions = list(db.scalars(
        select(Permission).where(
            Permission.status == PermissionStatus.ACTIVE,
            Permission.expires_at <= warning_end,
            or_(Permission.expiry_warning_sent_at.is_(None), Permission.expiry_notification_sent_at.is_(None)),
        ).with_for_update()
    ))
    created = 0
    for permission in permissions:
        agent = db.get(Agent, permission.agent_id)
        if agent is None:
            continue
        expiry_notifications_enabled = get_preferences(db, permission.owner_id).permission_expiry_enabled
        if permission.expires_at <= checked_at:
            permission.status = PermissionStatus.EXPIRED
            if permission.expiry_notification_sent_at is None and expiry_notifications_enabled:
                create_notification(
                    db, user_id=permission.owner_id, organization_id=agent.organization_id,
                    notification_type=NotificationType.PERMISSION_EXPIRED,
                    title="Permission Expired",
                    message=f"{agent.name} can no longer {permission.action} {permission.resource}.",
                    related_agent_id=agent.id, related_permission_id=permission.id,
                    deduplication_key=f"permission-expired:{permission.id}",
                )
                permission.expiry_notification_sent_at = checked_at
                created += 1
        elif permission.expiry_warning_sent_at is None and expiry_notifications_enabled:
            minutes = max(1, int((permission.expires_at - checked_at).total_seconds() // 60))
            create_notification(
                db, user_id=permission.owner_id, organization_id=agent.organization_id,
                notification_type=NotificationType.PERMISSION_EXPIRING,
                title="Permission Expiring Soon",
                message=f"{agent.name} {permission.resource} permission expires in about {minutes} minutes.",
                priority=NotificationPriority.HIGH,
                related_agent_id=agent.id, related_permission_id=permission.id,
                deduplication_key=f"permission-expiring:{permission.id}",
            )
            permission.expiry_warning_sent_at = checked_at
            created += 1
    if permissions:
        db.commit()
    return created


def process_signing_key_expiry_notifications(db: Session, settings: Settings, now: datetime | None = None) -> int:
    checked_at = now or datetime.now(timezone.utc)
    warning_end = checked_at + timedelta(days=settings.agent_key_expiry_warning_days)
    already_notified = select(Notification.id).where(
        Notification.deduplication_key == ("agent-signing-key-expiring:" + AgentSigningKey.key_id),
    ).exists()
    keys = list(db.scalars(select(AgentSigningKey).where(
        AgentSigningKey.status.in_([AgentSigningKeyStatus.ACTIVE, AgentSigningKeyStatus.ROTATING]),
        AgentSigningKey.expires_at.is_not(None), AgentSigningKey.expires_at <= warning_end,
        or_(AgentSigningKey.expires_at <= checked_at, ~already_notified),
    ).order_by(AgentSigningKey.expires_at).limit(settings.notification_worker_batch_size)
        .with_for_update(skip_locked=True)))
    created = 0
    for key in keys:
        if key.expires_at <= checked_at:
            key.status = AgentSigningKeyStatus.EXPIRED
            continue
        agent = db.get(Agent, key.agent_id)
        if agent is None:
            continue
        dedup = f"agent-signing-key-expiring:{key.key_id}"
        if db.scalar(select(Notification.id).where(Notification.deduplication_key == dedup)) is not None:
            continue
        create_notification(db, user_id=agent.owner_id, organization_id=agent.organization_id,
            notification_type=NotificationType.SECURITY_ALERT, title="Agent Signing Key Expiring",
            message=f"{agent.name} signing key {key.key_id} expires soon. Register a new public key before it expires.",
            priority=NotificationPriority.HIGH, related_agent_id=agent.id, deduplication_key=dedup)
        created += 1
    if keys:
        db.commit()
    return created


def _mark_failure(delivery: NotificationDelivery, settings: Settings, now: datetime, message: str) -> None:
    metrics.event("notification_failure")
    delivery.attempt_count += 1
    delivery.last_error = message[:255]
    if delivery.attempt_count >= settings.notification_max_delivery_attempts:
        delivery.status = DeliveryStatus.FAILED
        delivery.next_attempt_at = None
    else:
        delivery.status = DeliveryStatus.PENDING
        seconds = settings.notification_retry_base_seconds * (2 ** (delivery.attempt_count - 1))
        delivery.next_attempt_at = now + timedelta(seconds=seconds)


def process_notification_deliveries(db: Session, settings: Settings, now: datetime | None = None) -> int:
    checked_at = now or datetime.now(timezone.utc)
    deliveries = list(db.scalars(
        select(NotificationDelivery).where(
            NotificationDelivery.status == DeliveryStatus.PENDING,
            or_(NotificationDelivery.next_attempt_at.is_(None), NotificationDelivery.next_attempt_at <= checked_at),
        ).order_by(NotificationDelivery.created_at).limit(settings.notification_worker_batch_size).with_for_update(skip_locked=True)
    ))
    push = FirebasePushProvider(settings)
    email = email_provider(settings)
    for delivery in deliveries:
        notification = db.get(Notification, delivery.notification_id)
        user = db.get(User, notification.user_id) if notification else None
        if notification is None or user is None:
            _mark_failure(delivery, settings, checked_at, "Notification recipient is unavailable")
            continue
        try:
            if delivery.channel == DeliveryChannel.EMAIL:
                result = email.send(to=user.email, subject=notification.title, body=render_email(notification))
            elif delivery.channel == DeliveryChannel.PUSH:
                devices = list(db.scalars(select(Device).where(
                    Device.user_id == user.id, Device.status == DeviceStatus.ACTIVE,
                )))
                if not devices:
                    raise DeliveryProviderError("No active push device")
                ids = []
                for device in devices:
                    try:
                        result = push.send(
                            token=device.push_token, title=notification.title, body=notification.message,
                            data={
                                "notification_id": str(notification.id),
                                "request_id": str(notification.related_request_id or ""),
                                "type": notification.type.value,
                            },
                        )
                        if result.message_id:
                            ids.append(result.message_id)
                    except DeliveryProviderError:
                        continue
                if not ids:
                    raise DeliveryProviderError("Push provider request failed")
                result = type(result)(message_id=",".join(ids)[:255] or None)
            else:
                delivery.status = DeliveryStatus.DELIVERED
                continue
            delivery.attempt_count += 1
            delivery.status = DeliveryStatus.SENT
            delivery.provider_message_id = result.message_id
            delivery.last_error = None
            delivery.next_attempt_at = None
            record_security_event(
                db, user.id, f"notification.{delivery.channel.value}_sent",
                organization_id=notification.organization_id, target_user_id=user.id,
                description=f"Notification: {notification.id}", commit=False,
            )
        except DeliveryProviderError as exc:
            _mark_failure(delivery, settings, checked_at, str(exc))
    db.commit()
    return len(deliveries)
