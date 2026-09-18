"""Revocable backend sessions; only a hash of each JWT identifier is stored."""

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.security import create_access_token
from app.models import AuthSession, NotificationPriority, NotificationType, User
from app.services.notification_service import create_notification


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _device_summary(user_agent: str) -> tuple[str, str]:
    agent = user_agent[:512].lower()
    platform = next((name for needle, name in (("android", "Android"), ("iphone", "iPhone"), ("ipad", "iPad"), ("windows", "Windows"), ("mac os", "macOS"), ("linux", "Linux")) if needle in agent), "Unknown")
    browser = next((name for needle, name in (("edg/", "Edge"), ("firefox/", "Firefox"), ("chrome/", "Chrome"), ("safari/", "Safari")) if needle in agent), "App")
    device = "mobile" if platform in {"Android", "iPhone", "iPad"} else "desktop" if platform != "Unknown" else "unknown"
    return device, f"{browser} on {platform}"


def issue_session(
    db: Session, user: User, settings: Settings, request: Request,
    *, auth_method: str, mfa_verified: bool = False,
) -> str:
    now = datetime.now(timezone.utc)
    nonce = secrets.token_urlsafe(32)
    device, summary = _device_summary(request.headers.get("user-agent", ""))
    address = request.client.host if request.client else ""
    ip_hash = hmac.new(settings.jwt_secret_key.get_secret_value().encode(), address.encode(), hashlib.sha256).hexdigest() if address else None
    session = AuthSession(
        user_id=user.id, token_hash=token_hash(nonce), auth_method=auth_method,
        mfa_verified_at=now if mfa_verified else None,
        step_up_at=now if auth_method == "password" or mfa_verified else None,
        device_type=device, user_agent_summary=summary, ip_hash=ip_hash,
        expires_at=now + timedelta(minutes=settings.jwt_access_token_expire_minutes),
    )
    prior_session = db.scalar(select(AuthSession.id).where(AuthSession.user_id == user.id).limit(1))
    recognized_device = db.scalar(select(AuthSession.id).where(
        AuthSession.user_id == user.id, AuthSession.user_agent_summary == summary,
    ).limit(1))
    db.add(session)
    if prior_session is not None and recognized_device is None:
        create_notification(db, user_id=user.id, notification_type=NotificationType.SECURITY_ALERT,
            title="New Sign-In Device", message=f"A new {summary} session signed in to your account.",
            priority=NotificationPriority.HIGH,
            deduplication_key=f"new-login-device:{user.id}:{hashlib.sha256(summary.encode()).hexdigest()[:16]}")
    db.commit()
    return create_access_token(user.id, settings, session_token=nonce)


def active_session(db: Session, user_id: UUID, nonce: str) -> AuthSession | None:
    now = datetime.now(timezone.utc)
    return db.scalar(select(AuthSession).where(
        AuthSession.user_id == user_id, AuthSession.token_hash == token_hash(nonce),
        AuthSession.revoked_at.is_(None), AuthSession.expires_at > now,
    ))


def revoke_session(db: Session, session: AuthSession) -> None:
    if session.revoked_at is None:
        session.revoked_at = datetime.now(timezone.utc)
        db.commit()
