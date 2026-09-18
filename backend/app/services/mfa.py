"""Encrypted TOTP credentials, one-use recovery codes, and MFA challenges."""

import hashlib
import hmac
import secrets
import base64
from io import BytesIO
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pyotp
import qrcode
from qrcode.image.svg import SvgPathImage
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.security import verify_password
from app.models import MFAChallenge, MFACredential, MFARecoveryCode, MemberStatus, Organization, OrganizationMember, OrganizationSecurityPolicy, User
from app.models import NotificationPriority, NotificationType
from app.services.notification_service import create_notification
from app.services.security_events import record_security_event
from app.services.sessions import token_hash


class MFAError(Exception):
    pass


def _cipher(settings: Settings) -> Fernet:
    key = settings.mfa_encryption_key.get_secret_value()
    if not key:
        raise MFAError("MFA encryption is not configured")
    return Fernet(key.encode())


def _secret(credential: MFACredential, settings: Settings) -> str:
    try:
        return _cipher(settings).decrypt(credential.encrypted_secret.encode()).decode()
    except (InvalidToken, UnicodeDecodeError):
        raise MFAError("MFA credential is unavailable") from None


def _matching_step(secret: str, code: str, at: datetime) -> int | None:
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return None
    current = int(at.timestamp()) // 30
    totp = pyotp.TOTP(secret)
    for step in (current - 1, current, current + 1):
        if hmac.compare_digest(totp.at(step * 30), code):
            return step
    return None


def mfa_status(db: Session, user_id: UUID) -> dict[str, int | bool]:
    credential = db.get(MFACredential, user_id)
    remaining = db.scalar(select(func.count()).select_from(MFARecoveryCode).where(
        MFARecoveryCode.user_id == user_id, MFARecoveryCode.used_at.is_(None),
    )) or 0
    return {"enabled": bool(credential and credential.enabled_at),
        "pending": bool(credential and credential.pending_expires_at and credential.pending_expires_at > datetime.now(timezone.utc)),
        "recovery_codes_remaining": remaining}


def start_setup(db: Session, user: User, settings: Settings) -> dict[str, str]:
    cipher = _cipher(settings)
    credential = db.get(MFACredential, user.id)
    if credential is not None and credential.enabled_at is not None:
        raise MFAError("MFA is already enabled")
    secret = pyotp.random_base32(length=32)
    now = datetime.now(timezone.utc)
    if credential is None:
        credential = MFACredential(user_id=user.id, encrypted_secret="")
        db.add(credential)
    credential.encrypted_secret = cipher.encrypt(secret.encode()).decode()
    credential.pending_expires_at = now + timedelta(minutes=10)
    credential.last_used_step = None
    db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="AgentTrust")
    image = qrcode.make(uri, image_factory=SvgPathImage)
    output = BytesIO()
    image.save(output)
    return {"secret": secret, "otpauth_uri": uri,
        "qr_svg_data_url": "data:image/svg+xml;base64," + base64.b64encode(output.getvalue()).decode()}


def _new_recovery_codes(db: Session, user_id: UUID) -> list[str]:
    db.execute(delete(MFARecoveryCode).where(MFARecoveryCode.user_id == user_id))
    codes = [secrets.token_urlsafe(15) for _ in range(10)]
    db.add_all(MFARecoveryCode(user_id=user_id, code_hash=token_hash(code)) for code in codes)
    return codes


def confirm_setup(db: Session, user: User, settings: Settings, code: str) -> list[str]:
    credential = db.scalar(select(MFACredential).where(MFACredential.user_id == user.id).with_for_update())
    now = datetime.now(timezone.utc)
    if credential is None or credential.enabled_at is not None or credential.pending_expires_at is None or credential.pending_expires_at <= now:
        raise MFAError("MFA setup has expired")
    if credential.locked_until is not None and credential.locked_until > now:
        raise MFAError("Too many MFA attempts. Please try again later")
    step = _matching_step(_secret(credential, settings), code, now)
    if step is None:
        credential.failed_attempts += 1
        record_security_event(db, user.id, "mfa_failed", description="Invalid MFA setup attempt", severity="warning", commit=False)
        if credential.failed_attempts >= settings.mfa_max_attempts:
            credential.failed_attempts = 0
            credential.locked_until = now + timedelta(minutes=settings.mfa_lock_minutes)
        db.commit()
        raise MFAError("Invalid authenticator code")
    credential.enabled_at = now
    credential.pending_expires_at = None
    credential.last_used_step = step
    credential.failed_attempts = 0
    credential.locked_until = None
    codes = _new_recovery_codes(db, user.id)
    record_security_event(db, user.id, "mfa_enabled", description="Two-factor authentication enabled", commit=False)
    create_notification(db, user_id=user.id, notification_type=NotificationType.SECURITY_ALERT,
        title="Two-Factor Authentication Enabled", message="An authenticator was added to your account.", priority=NotificationPriority.HIGH)
    db.commit()
    return codes


def create_challenge(db: Session, user_id: UUID, settings: Settings) -> str:
    nonce = secrets.token_urlsafe(32)
    db.add(MFAChallenge(user_id=user_id, token_hash=token_hash(nonce),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.mfa_challenge_expire_minutes)))
    db.commit()
    return nonce


def _verify_factor(db: Session, credential: MFACredential, settings: Settings, code: str, *, allow_recovery: bool) -> bool:
    now = datetime.now(timezone.utc)
    if credential.locked_until is not None and credential.locked_until > now:
        raise MFAError("Too many MFA attempts. Please try again later")
    step = _matching_step(_secret(credential, settings), code, now)
    if step is not None and (credential.last_used_step is None or step > credential.last_used_step):
        credential.last_used_step = step
        credential.failed_attempts = 0
        credential.locked_until = None
        return False
    if allow_recovery and len(code) <= 64:
        candidate = db.scalar(select(MFARecoveryCode).where(
            MFARecoveryCode.user_id == credential.user_id,
            MFARecoveryCode.code_hash == token_hash(code),
            MFARecoveryCode.used_at.is_(None),
        ).with_for_update())
        if candidate is not None:
            candidate.used_at = now
            credential.failed_attempts = 0
            credential.locked_until = None
            record_security_event(db, credential.user_id, "recovery_code_used", description="MFA recovery code used", severity="warning", commit=False)
            create_notification(db, user_id=credential.user_id, notification_type=NotificationType.SECURITY_ALERT,
                title="Recovery Code Used", message="A recovery code was used to access your account.", priority=NotificationPriority.HIGH)
            return True
    credential.failed_attempts += 1
    record_security_event(db, credential.user_id, "mfa_failed", description="Invalid MFA attempt", severity="warning", commit=False)
    if credential.failed_attempts >= settings.mfa_max_attempts:
        credential.failed_attempts = 0
        credential.locked_until = now + timedelta(minutes=settings.mfa_lock_minutes)
        create_notification(db, user_id=credential.user_id, notification_type=NotificationType.SECURITY_ALERT,
            title="MFA Temporarily Locked", message="Multiple failed authenticator attempts temporarily blocked sign-in.", priority=NotificationPriority.HIGH)
    db.commit()
    raise MFAError("Invalid or already used MFA code")


def verify_challenge(db: Session, challenge_token: str, code: str, settings: Settings) -> tuple[User, bool]:
    now = datetime.now(timezone.utc)
    challenge = db.scalar(select(MFAChallenge).where(MFAChallenge.token_hash == token_hash(challenge_token)).with_for_update())
    if challenge is None or challenge.used_at is not None or challenge.expires_at <= now or challenge.attempts >= settings.mfa_max_attempts:
        raise MFAError("MFA challenge expired or invalid")
    user = db.get(User, challenge.user_id)
    credential = db.scalar(select(MFACredential).where(MFACredential.user_id == challenge.user_id).with_for_update())
    if user is None or not user.is_active or credential is None or credential.enabled_at is None:
        raise MFAError("MFA challenge expired or invalid")
    challenge.attempts += 1
    try:
        used_recovery = _verify_factor(db, credential, settings, code, allow_recovery=True)
    except MFAError:
        db.commit()
        raise
    challenge.used_at = now
    db.commit()
    return user, used_recovery


def require_factor(db: Session, user_id: UUID, code: str, settings: Settings, *, allow_recovery: bool = True) -> None:
    credential = db.scalar(select(MFACredential).where(MFACredential.user_id == user_id).with_for_update())
    if credential is None or credential.enabled_at is None:
        raise MFAError("MFA is not enabled")
    _verify_factor(db, credential, settings, code, allow_recovery=allow_recovery)
    db.commit()


def regenerate_recovery_codes(db: Session, user: User, code: str, settings: Settings) -> list[str]:
    require_factor(db, user.id, code, settings)
    codes = _new_recovery_codes(db, user.id)
    record_security_event(db, user.id, "recovery_codes_regenerated", description="MFA recovery codes regenerated", commit=False)
    db.commit()
    return codes


def disable_mfa(db: Session, user: User, password: str, code: str, settings: Settings) -> None:
    if not verify_password(password, user.hashed_password):
        raise MFAError("Strong verification failed")
    policy = db.scalar(select(OrganizationSecurityPolicy).join(
        OrganizationMember, OrganizationMember.organization_id == OrganizationSecurityPolicy.organization_id,
    ).where(OrganizationMember.user_id == user.id, OrganizationMember.status == MemberStatus.ACTIVE,
            OrganizationSecurityPolicy.require_mfa.is_(True)))
    if policy is not None:
        raise MFAError("An organization requires MFA")
    legacy_owner_policy = db.scalar(select(OrganizationSecurityPolicy).join(
        Organization, Organization.id == OrganizationSecurityPolicy.organization_id,
    ).where(Organization.owner_id == user.id, OrganizationSecurityPolicy.require_mfa.is_(True)))
    if legacy_owner_policy is not None:
        raise MFAError("An organization requires MFA")
    require_factor(db, user.id, code, settings)
    db.execute(delete(MFARecoveryCode).where(MFARecoveryCode.user_id == user.id))
    db.execute(delete(MFACredential).where(MFACredential.user_id == user.id))
    record_security_event(db, user.id, "mfa_disabled", description="Two-factor authentication disabled", severity="warning", commit=False)
    create_notification(db, user_id=user.id, notification_type=NotificationType.SECURITY_ALERT,
        title="Two-Factor Authentication Disabled", message="Two-factor authentication was removed from your account.", priority=NotificationPriority.HIGH)
    db.commit()
