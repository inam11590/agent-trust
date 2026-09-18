"""Central creation and ownership-safe lifecycle for all notifications."""

from dataclasses import dataclass
from datetime import datetime, timezone
from math import ceil
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import (
    DeliveryChannel, DeliveryStatus, Device, DeviceStatus, Notification,
    NotificationDelivery, NotificationPreference, NotificationPriority,
    NotificationStatus, NotificationType,
)
from app.schemas.notification import DeviceCreate, NotificationFilters, NotificationPreferenceUpdate
from app.services.security_events import record_security_event


APPROVAL_TYPES = {
    NotificationType.AUTHORIZATION_PENDING,
    NotificationType.AUTHORIZATION_APPROVED,
    NotificationType.AUTHORIZATION_REJECTED,
    NotificationType.HIGH_RISK_APPROVAL_REQUIRED,
}
SECURITY_TYPES = {
    NotificationType.SECURITY_ALERT, NotificationType.API_KEY_REVOKED,
    NotificationType.AGENT_SUSPENDED, NotificationType.AGENT_REVOKED,
}


@dataclass(frozen=True)
class NotificationChannels:
    push: bool = False
    email: bool = False


class DeviceTokenConflict(Exception):
    pass


class DeviceLimitReached(Exception):
    pass


def get_preferences(db: Session, user_id: UUID) -> NotificationPreference:
    preference = db.scalar(select(NotificationPreference).where(NotificationPreference.user_id == user_id))
    if preference is None:
        preference = NotificationPreference(user_id=user_id)
        db.add(preference)
        db.flush()
    return preference


def update_preferences(
    db: Session, user_id: UUID, payload: NotificationPreferenceUpdate,
) -> NotificationPreference:
    preference = get_preferences(db, user_id)
    for name, value in payload.model_dump(exclude_none=True).items():
        setattr(preference, name, value)
    db.commit()
    db.refresh(preference)
    return preference


def _channels(preference: NotificationPreference, notification_type: NotificationType) -> NotificationChannels:
    approval = notification_type in APPROVAL_TYPES
    security = notification_type in SECURITY_TYPES
    return NotificationChannels(
        push=preference.push_enabled and (not approval or preference.approval_push_enabled),
        email=preference.email_enabled and (
            (approval and preference.approval_email_enabled)
            or (security and preference.security_email_enabled)
            or notification_type == NotificationType.TEAM_INVITATION
        ),
    )


def create_notification(
    db: Session,
    *,
    user_id: UUID,
    notification_type: NotificationType,
    title: str,
    message: str,
    priority: NotificationPriority = NotificationPriority.NORMAL,
    organization_id: UUID | None = None,
    related_request_id: UUID | None = None,
    related_agent_id: UUID | None = None,
    related_permission_id: UUID | None = None,
    metadata: dict | None = None,
    deduplication_key: str | None = None,
) -> Notification:
    """Write an in-app record and queue external channels without network I/O."""
    if deduplication_key:
        existing = db.scalar(select(Notification).where(Notification.deduplication_key == deduplication_key))
        if existing is not None:
            return existing
    preference = get_preferences(db, user_id)
    notification = Notification(
        user_id=user_id, organization_id=organization_id, type=notification_type,
        title=title[:160], message=message[:500], priority=priority,
        related_request_id=related_request_id, related_agent_id=related_agent_id,
        related_permission_id=related_permission_id, metadata_json=metadata,
        deduplication_key=deduplication_key,
    )
    db.add(notification)
    db.flush()
    if notification_type == NotificationType.SECURITY_ALERT:
        record_security_event(
            db, user_id, "notification.security_alert", organization_id=organization_id,
            target_user_id=user_id, description=f"Notification: {notification.id}", commit=False,
        )
    if preference.in_app_enabled:
        db.add(NotificationDelivery(
            notification_id=notification.id, channel=DeliveryChannel.IN_APP,
            status=DeliveryStatus.DELIVERED, attempt_count=1,
        ))
    channels = _channels(preference, notification_type)
    if channels.push:
        db.add(NotificationDelivery(notification_id=notification.id, channel=DeliveryChannel.PUSH))
    if channels.email:
        db.add(NotificationDelivery(notification_id=notification.id, channel=DeliveryChannel.EMAIL))
    return notification


def list_notifications(db: Session, user_id: UUID, filters: NotificationFilters):
    in_app_ids = select(NotificationDelivery.notification_id).where(
        NotificationDelivery.channel == DeliveryChannel.IN_APP,
    )
    conditions = [
        Notification.user_id == user_id, Notification.id.in_(in_app_ids),
        Notification.status != NotificationStatus.ARCHIVED,
    ]
    if filters.unread is True:
        conditions.append(Notification.status == NotificationStatus.UNREAD)
    elif filters.unread is False:
        conditions.append(Notification.status == NotificationStatus.READ)
    if filters.type is not None:
        conditions.append(Notification.type == filters.type)
    if filters.priority is not None:
        conditions.append(Notification.priority == filters.priority)
    total = db.scalar(select(func.count()).select_from(Notification).where(*conditions)) or 0
    items = list(db.scalars(
        select(Notification).where(*conditions)
        .order_by(Notification.created_at.desc(), Notification.id.desc())
        .offset((filters.page - 1) * filters.page_size).limit(filters.page_size)
    ))
    return items, total, ceil(total / filters.page_size) if total else 0


def unread_count(db: Session, user_id: UUID) -> int:
    return db.scalar(select(func.count()).select_from(Notification).where(
        Notification.user_id == user_id, Notification.status == NotificationStatus.UNREAD,
        Notification.id.in_(select(NotificationDelivery.notification_id).where(
            NotificationDelivery.channel == DeliveryChannel.IN_APP,
        )),
    )) or 0


def mark_read(db: Session, user_id: UUID, notification_id: UUID) -> Notification | None:
    item = db.scalar(select(Notification).where(
        Notification.id == notification_id, Notification.user_id == user_id,
    ).with_for_update())
    if item is None:
        return None
    if item.status == NotificationStatus.UNREAD:
        item.status = NotificationStatus.READ
        item.read_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(item)
    return item


def mark_all_read(db: Session, user_id: UUID) -> int:
    items = list(db.scalars(select(Notification).where(
        Notification.user_id == user_id, Notification.status == NotificationStatus.UNREAD,
    ).with_for_update()))
    now = datetime.now(timezone.utc)
    for item in items:
        item.status = NotificationStatus.READ
        item.read_at = now
    db.commit()
    return len(items)


def archive_notification(db: Session, user_id: UUID, notification_id: UUID) -> Notification | None:
    item = db.scalar(select(Notification).where(
        Notification.id == notification_id, Notification.user_id == user_id,
    ).with_for_update())
    if item is None:
        return None
    item.status = NotificationStatus.ARCHIVED
    if item.read_at is None:
        item.read_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(item)
    return item


def register_device(db: Session, user_id: UUID, payload: DeviceCreate) -> Device:
    now = datetime.now(timezone.utc)
    device = db.scalar(select(Device).where(Device.push_token == payload.push_token).with_for_update())
    if device is None:
        active_count = db.scalar(select(func.count()).select_from(Device).where(
            Device.user_id == user_id, Device.status == DeviceStatus.ACTIVE,
        )) or 0
        if active_count >= 10:
            raise DeviceLimitReached
        device = Device(user_id=user_id, **payload.model_dump(), last_seen_at=now)
        db.add(device)
    else:
        if device.user_id != user_id:
            raise DeviceTokenConflict
        device.platform = payload.platform
        device.device_name = payload.device_name
        device.status = DeviceStatus.ACTIVE
        device.last_seen_at = now
    create_notification(
        db, user_id=user_id, notification_type=NotificationType.SECURITY_ALERT,
        title="New Device Registered",
        message=f"A new {payload.platform.value} device was registered for push notifications.",
        priority=NotificationPriority.HIGH,
        deduplication_key=f"device-registered:{device.id}",
    )
    db.commit()
    db.refresh(device)
    return device


def revoke_device(db: Session, user_id: UUID, device_id: UUID) -> bool:
    device = db.scalar(select(Device).where(Device.id == device_id, Device.user_id == user_id).with_for_update())
    if device is None:
        return False
    device.status = DeviceStatus.REVOKED
    db.commit()
    return True
