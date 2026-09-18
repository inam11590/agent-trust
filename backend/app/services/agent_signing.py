"""Ed25519 agent identity, exact-byte v1 signing, and atomic replay protection."""

import base64
import binascii
import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import Agent, AgentRequestNonce, AgentSigningKey, AgentSigningKeyStatus
from app.schemas.agent_signing import SigningKeyCreate
from app.services.api_keys import DeveloperPrincipal

KEY_ID_PATTERN = re.compile(r"^key_ag_[0-9a-f]{24}$")
NONCE_PATTERN = re.compile(r"^nonce_[0-9a-f]{32}$")
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SIGNATURE_VERSION = "v1"
SIGNATURE_PATH = "/api/v1/authorize"
SIGNED_HEADERS = (
    "X-Agent-ID", "X-Agent-Key-ID", "X-Agent-Timestamp", "X-Agent-Nonce",
    "X-Agent-Signature", "X-Agent-Signature-Version",
)


class SigningError(Exception):
    def __init__(self, code: str, status_code: int = 401):
        self.code = code
        self.status_code = status_code
        super().__init__(code)


@dataclass(frozen=True)
class VerifiedAgentSignature:
    key_id: str
    version: str = SIGNATURE_VERSION


def canonical_request(method: str, path: str, agent_id: str, key_id: str,
                      timestamp: str, nonce: str, body: bytes) -> bytes:
    """ASCII metadata plus SHA-256 of exact HTTP entity bytes, with a final LF."""
    return ("\n".join((SIGNATURE_VERSION, method.upper(), path, agent_id, key_id,
                       timestamp, nonce, hashlib.sha256(body).hexdigest())) + "\n").encode("ascii")


def decode_public_key(value: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
        if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value:
            raise ValueError
        Ed25519PublicKey.from_public_bytes(raw)
        return raw
    except (ValueError, binascii.Error):
        raise SigningError("INVALID_PUBLIC_KEY", 422) from None


def fingerprint(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def register_key(db: Session, agent: Agent, payload: SigningKeyCreate, settings: Settings,
                 *, rotated_from: AgentSigningKey | None = None) -> AgentSigningKey:
    # Lock the agent row so concurrent registrations cannot exceed the active-key cap.
    locked = db.scalar(select(Agent).where(Agent.id == agent.id).with_for_update())
    if locked is None or locked.status.value == "revoked":
        raise SigningError("AGENT_NOT_AVAILABLE", 409)
    now = datetime.now(timezone.utc)
    count = db.scalar(select(func.count()).select_from(AgentSigningKey).where(
        AgentSigningKey.agent_id == agent.id,
        AgentSigningKey.status.in_([AgentSigningKeyStatus.ACTIVE, AgentSigningKeyStatus.ROTATING]),
        (AgentSigningKey.expires_at.is_(None) | (AgentSigningKey.expires_at > now)),
    )) or 0
    if count >= settings.agent_max_active_signing_keys:
        raise SigningError("ACTIVE_KEY_LIMIT_REACHED", 409)
    raw = decode_public_key(payload.public_key)
    digest = fingerprint(raw)
    if db.scalar(select(AgentSigningKey.id).where(AgentSigningKey.fingerprint == digest)) is not None:
        raise SigningError("PUBLIC_KEY_ALREADY_REGISTERED", 409)
    key = AgentSigningKey(
        key_id=f"key_ag_{secrets.token_hex(12)}", agent_id=agent.id,
        organization_id=agent.organization_id, algorithm="Ed25519",
        public_key=base64.b64encode(raw).decode("ascii"), fingerprint=digest,
        status=AgentSigningKeyStatus.ACTIVE, activated_at=now,
        expires_at=payload.expires_at,
        rotated_from_key_id=rotated_from.key_id if rotated_from else None,
    )
    db.add(key)
    if rotated_from is not None:
        rotated_from.status = AgentSigningKeyStatus.ROTATING
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise SigningError("PUBLIC_KEY_ALREADY_REGISTERED", 409) from None
    db.refresh(key)
    return key


def revoke_key(db: Session, key: AgentSigningKey) -> AgentSigningKey:
    locked = db.scalar(select(AgentSigningKey).where(AgentSigningKey.id == key.id).with_for_update())
    if locked is None:
        raise SigningError("SIGNING_KEY_NOT_FOUND", 404)
    if locked.status != AgentSigningKeyStatus.REVOKED:
        locked.status = AgentSigningKeyStatus.REVOKED
        locked.revoked_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(locked)
    return locked


def _accept_nonce(db: Session, redis_client, settings: Settings, key_id: str, nonce: str,
                  now: datetime) -> None:
    digest = hashlib.sha256(f"{key_id}:{nonce}".encode("ascii")).hexdigest()
    ttl = 2 * settings.agent_signature_clock_window_seconds + 30
    if settings.redis_url.get_secret_value():
        if redis_client is None:
            raise SigningError("REPLAY_PROTECTION_UNAVAILABLE", 503)
        try:
            accepted = redis_client.set(f"agenttrust:signing:nonce:{digest}", "1", nx=True, ex=ttl)
        except Exception:
            raise SigningError("REPLAY_PROTECTION_UNAVAILABLE", 503) from None
        if not accepted:
            raise SigningError("REPLAY_DETECTED", 409)
    # PostgreSQL is the authoritative uniqueness guard even if Redis evicts a key.
    try:
        if secrets.randbelow(64) == 0:
            db.execute(delete(AgentRequestNonce).where(AgentRequestNonce.expires_at <= now))
        accepted = db.execute(insert(AgentRequestNonce).values(
            id=uuid4(), key_id=key_id, nonce_hash=digest,
            expires_at=now + timedelta(seconds=ttl),
        ).on_conflict_do_nothing(constraint="uq_agent_request_nonce").returning(AgentRequestNonce.id)).scalar_one_or_none()
        db.commit()
    except Exception:
        db.rollback()
        raise SigningError("REPLAY_PROTECTION_UNAVAILABLE", 503) from None
    if accepted is None:
        raise SigningError("REPLAY_DETECTED", 409)


def cleanup_expired_nonces(db: Session, now: datetime | None = None, batch_size: int = 1000) -> int:
    """Delete only expired replay records in a bounded worker batch."""
    checked_at = now or datetime.now(timezone.utc)
    ids = list(db.scalars(select(AgentRequestNonce.id).where(
        AgentRequestNonce.expires_at <= checked_at,
    ).order_by(AgentRequestNonce.expires_at).limit(batch_size)))
    if ids:
        db.execute(delete(AgentRequestNonce).where(AgentRequestNonce.id.in_(ids)))
        db.commit()
    return len(ids)


def verify_request(db: Session, principal: DeveloperPrincipal, settings: Settings,
                   redis_client, *, agent_id: str, headers, body: bytes,
                   method: str, path: str, raw_headers=()) -> VerifiedAgentSignature | None:
    signed_names = {name.lower().encode("ascii") for name in SIGNED_HEADERS}
    seen = set()
    for name, _ in raw_headers:
        lower = name.lower()
        if lower in signed_names:
            if lower in seen:
                raise SigningError("INVALID_AGENT_SIGNATURE")
            seen.add(lower)
    agent = db.scalar(select(Agent).where(Agent.agent_identifier == agent_id))
    supplied = any(headers.get(name) is not None for name in SIGNED_HEADERS)
    if agent is not None and (agent.organization_id != principal.api_key.organization_id or (
        agent.organization_id is None and agent.owner_id != principal.user.id
    )):
        if supplied:
            raise SigningError("INVALID_AGENT_SIGNATURE")
        return None  # The existing permission engine gives a tenant-safe rejection.
    has_key = agent is not None and db.scalar(select(AgentSigningKey.id).where(
        AgentSigningKey.agent_id == agent.id).limit(1)) is not None
    if not has_key and not supplied:
        return None  # Explicit legacy migration path for agents without a registered key.
    if not has_key or not supplied:
        raise SigningError("AGENT_SIGNATURE_REQUIRED" if has_key else "INVALID_AGENT_SIGNATURE")
    values = [headers.get(name) for name in SIGNED_HEADERS]
    if any(value is None or len(value) > 200 for value in values):
        raise SigningError("INVALID_AGENT_SIGNATURE")
    header_agent, key_id, timestamp, nonce, signature, version = values
    if version != SIGNATURE_VERSION:
        raise SigningError("UNKNOWN_AGENT_SIGNATURE_VERSION")
    if header_agent != agent_id or not KEY_ID_PATTERN.fullmatch(key_id) or not NONCE_PATTERN.fullmatch(nonce):
        raise SigningError("INVALID_AGENT_SIGNATURE")
    if not TIMESTAMP_PATTERN.fullmatch(timestamp):
        raise SigningError("REQUEST_TIMESTAMP_INVALID")
    try:
        signed_at = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise SigningError("REQUEST_TIMESTAMP_INVALID") from None
    now = datetime.now(timezone.utc)
    if abs((now - signed_at).total_seconds()) > settings.agent_signature_clock_window_seconds:
        raise SigningError("REQUEST_TIMESTAMP_INVALID")
    key = db.scalar(select(AgentSigningKey).where(AgentSigningKey.key_id == key_id))
    if key is None or key.agent_id != agent.id or key.organization_id != agent.organization_id:
        raise SigningError("INVALID_AGENT_SIGNATURE")
    if key.status == AgentSigningKeyStatus.REVOKED:
        raise SigningError("SIGNING_KEY_REVOKED")
    if key.status == AgentSigningKeyStatus.EXPIRED or (key.expires_at is not None and key.expires_at <= now):
        raise SigningError("SIGNING_KEY_EXPIRED")
    if key.status not in {AgentSigningKeyStatus.ACTIVE, AgentSigningKeyStatus.ROTATING} or key.algorithm != "Ed25519":
        raise SigningError("INVALID_AGENT_SIGNATURE")
    try:
        signature_bytes = base64.b64decode(signature, validate=True)
        if len(signature_bytes) != 64:
            raise ValueError
        public_bytes = base64.b64decode(key.public_key, validate=True)
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            signature_bytes, canonical_request(method, path, agent_id, key_id, timestamp, nonce, body),
        )
    except (InvalidSignature, ValueError, binascii.Error):
        raise SigningError("INVALID_AGENT_SIGNATURE") from None
    _accept_nonce(db, redis_client, settings, key_id, nonce, now)
    key.last_used_at = now
    db.commit()
    return VerifiedAgentSignature(key_id=key_id)
