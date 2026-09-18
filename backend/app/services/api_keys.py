"""API key generation, one-way storage, authentication, and revocation."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import secrets
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import APIKey, APIKeyStatus, Organization, OrganizationRole, User
from app.schemas.developer import APIKeyCreate
from app.services.plan_limits import enforce_resource_limit
from app.services.organization_context import resolve_workspace
from app.services.notification_service import create_notification
from app.models import NotificationPriority, NotificationType

KEY_PREFIX_LENGTH = 20
MAX_KEY_ATTEMPTS = 5


class OrganizationNotFound(Exception):
    pass


class APIKeyNotFound(Exception):
    pass


@dataclass(frozen=True)
class DeveloperPrincipal:
    api_key: APIKey
    user: User
    organization: Organization | None


def hash_api_key(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def generate_api_key(environment: str = "production") -> str:
    prefix = "at_test_" if environment == "sandbox" else "at_live_"
    return f"{prefix}{secrets.token_hex(32)}"


def create_api_key(
    db: Session, user: User, payload: APIKeyCreate,
    organization_id: UUID | None = None,
) -> tuple[APIKey, str]:
    enforce_resource_limit(db, organization_id, "api keys")
    organization = None
    target_organization_id = organization_id if organization_id is not None else payload.organization_id
    if target_organization_id is not None:
        organization = db.scalar(select(Organization).where(
            Organization.id == target_organization_id,
            Organization.is_active.is_(True),
        ))
        if organization is None:
            raise OrganizationNotFound
    environment = getattr(payload, "environment", "sandbox") or "sandbox"
    for _ in range(MAX_KEY_ATTEMPTS):
        full_key = generate_api_key(environment)
        record = APIKey(
            organization_id=organization.id if organization else None,
            created_by_user_id=user.id,
            name=payload.name,
            environment=environment,
            key_prefix=full_key[:KEY_PREFIX_LENGTH],
            key_hash=hash_api_key(full_key),
            expires_at=payload.expires_at,
        )
        db.add(record)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            continue
        db.refresh(record)
        return record, full_key
    raise RuntimeError("Could not generate a unique API key")


def list_api_keys(
    db: Session, user_id: UUID, organization_id: UUID | None = None,
    role: OrganizationRole = OrganizationRole.OWNER,
) -> list[APIKey]:
    now = datetime.now(timezone.utc)
    conditions = [APIKey.organization_id == organization_id]
    if organization_id is None or role == OrganizationRole.DEVELOPER:
        conditions.append(APIKey.created_by_user_id == user_id)
    keys = list(db.scalars(select(APIKey).where(*conditions).order_by(APIKey.created_at.desc())))
    changed = False
    for key in keys:
        if key.status == APIKeyStatus.ACTIVE and key.expires_at is not None and key.expires_at <= now:
            key.status = APIKeyStatus.EXPIRED
            changed = True
    if changed:
        db.commit()
    return keys


def revoke_api_key(
    db: Session, user_id: UUID, key_id: UUID,
    organization_id: UUID | None = None,
    role: OrganizationRole = OrganizationRole.OWNER,
) -> APIKey:
    conditions = [APIKey.id == key_id, APIKey.organization_id == organization_id]
    if organization_id is None or role == OrganizationRole.DEVELOPER:
        conditions.append(APIKey.created_by_user_id == user_id)
    key = db.scalar(select(APIKey).where(*conditions).with_for_update())
    if key is None:
        raise APIKeyNotFound
    if key.status == APIKeyStatus.ACTIVE:
        key.status = APIKeyStatus.REVOKED
        key.revoked_at = datetime.now(timezone.utc)
        create_notification(
            db, user_id=key.created_by_user_id, organization_id=key.organization_id,
            notification_type=NotificationType.API_KEY_REVOKED,
            title="API Key Revoked", message=f"The API key {key.name} was revoked.",
            priority=NotificationPriority.HIGH,
            deduplication_key=f"api-key-revoked:{key.id}",
        )
        db.commit()
        db.refresh(key)
    return key


def authenticate_api_key(db: Session, raw_key: str) -> DeveloperPrincipal | None:
    if not (raw_key.startswith("at_live_") or raw_key.startswith("at_test_")) or len(raw_key) != 72:
        return None
    key = db.scalar(select(APIKey).where(APIKey.key_prefix == raw_key[:KEY_PREFIX_LENGTH]))
    if key is None or not hmac.compare_digest(key.key_hash, hash_api_key(raw_key)):
        return None
    expected_env = "sandbox" if raw_key.startswith("at_test_") else "production"
    if getattr(key, "environment", "production") != expected_env:
        return None
    now = datetime.now(timezone.utc)
    if key.status != APIKeyStatus.ACTIVE:
        return None
    if key.expires_at is not None and key.expires_at <= now:
        key.status = APIKeyStatus.EXPIRED
        db.commit()
        return None
    user = db.get(User, key.created_by_user_id)
    if user is None or not user.is_active:
        return None
    organization = db.get(Organization, key.organization_id) if key.organization_id else None
    if key.organization_id is not None and (organization is None or not organization.is_active):
        return None
    if key.organization_id is not None:
        workspace = resolve_workspace(db, user.id, key.organization_id)
        if workspace is None or not workspace.can("manage_keys"):
            return None
    key.last_used_at = now
    db.commit()
    return DeveloperPrincipal(api_key=key, user=user, organization=organization)


def public_key(record: APIKey, full_key: str | None = None) -> dict:
    data = {
        "id": record.id,
        "organization_id": record.organization_id,
        "name": record.name,
        "environment": getattr(record, "environment", "production"),
        "prefix": record.key_prefix,
        "status": record.status,
        "created_at": record.created_at,
        "last_used_at": record.last_used_at,
        "expires_at": record.expires_at,
        "revoked_at": record.revoked_at,
    }
    if full_key is not None:
        data["api_key"] = full_key
    return data
