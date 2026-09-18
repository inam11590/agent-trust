"""Account registration and credential verification, without HTTP concerns."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import DUMMY_PASSWORD_HASH, hash_password, verify_password
from app.core.config import Settings
from app.models import User
from app.models import NotificationPriority, NotificationType
from app.services.notification_service import create_notification
from app.schemas.auth import RegisterRequest
from app.services.security_events import record_security_event


class EmailAlreadyRegistered(Exception):
    pass


class InvalidCredentials(Exception):
    pass


def find_user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(func.lower(User.email) == email.lower()))


def register_user(db: Session, payload: RegisterRequest) -> User:
    if find_user_by_email(db, payload.email) is not None:
        raise EmailAlreadyRegistered
    user = User(
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password.get_secret_value()),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        constraint = getattr(getattr(exc.orig, "diag", None), "constraint_name", None)
        if constraint in {"uq_users_email", "uq_users_email_lower"}:
            # The unique index also handles simultaneous registration requests.
            raise EmailAlreadyRegistered from None
        raise
    db.refresh(user)
    return user


def authenticate_user(db: Session, email: str, password: str, settings: Settings) -> User:
    user = db.scalar(
        select(User).where(func.lower(User.email) == email.lower()).with_for_update()
    )
    stored_hash = user.hashed_password if user is not None else DUMMY_PASSWORD_HASH
    valid_password = verify_password(password, stored_hash)
    now = datetime.now(timezone.utc)
    is_locked = user is not None and user.locked_until is not None and user.locked_until > now
    if user is None or not valid_password or not user.is_active or is_locked:
        if user is not None and user.is_active and not is_locked:
            record_security_event(db, user.id, "login_failed", description="Invalid password", severity="warning", commit=False)
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.account_lock_attempts:
                user.locked_until = now + timedelta(minutes=settings.account_lock_minutes)
                user.failed_login_attempts = 0
                create_notification(
                    db, user_id=user.id, notification_type=NotificationType.SECURITY_ALERT,
                    title="Account Temporarily Locked",
                    message="Your account was temporarily locked after repeated failed sign-in attempts.",
                    priority=NotificationPriority.CRITICAL,
                    deduplication_key=f"account-lock:{user.id}:{int(now.timestamp()) // 60}",
                )
            db.commit()
        raise InvalidCredentials
    if user.failed_login_attempts or user.locked_until is not None:
        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()
    return user
