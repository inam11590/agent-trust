"""Trust Registry and Verifiable Agent Credentials Database Models (Step 22)."""

from __future__ import annotations

import secrets
from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4

from sqlalchemy import (
    DateTime,
    Enum as SqlEnum,
    ForeignKey,
    Index,
    JSON,
    String,
    Text,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class IssuerStatus(str, Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class IssuerKeyStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    ROTATED = "ROTATED"


class CredentialStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    SUSPENDED = "SUSPENDED"


class CredentialRevocationReason(str, Enum):
    AGENT_REVOKED = "AGENT_REVOKED"
    KEY_COMPROMISED = "KEY_COMPROMISED"
    CLAIMS_CHANGED = "CLAIMS_CHANGED"
    ISSUER_ACTION = "ISSUER_ACTION"
    SECURITY_EVENT = "SECURITY_EVENT"


def generate_issuer_id() -> str:
    return f"iss_{secrets.token_hex(8)}"


def generate_credential_id() -> str:
    return f"cred_{secrets.token_hex(12)}"


def generate_issuer_key_id() -> str:
    return f"iss_key_{secrets.token_hex(8)}"


class CredentialIssuer(Base):
    """An organization's trusted credential issuing identity."""

    __tablename__ = "credential_issuers"
    __table_args__ = (
        Index("ix_issuers_org_status", "organization_id", "status"),
        Index("ix_issuers_issuer_id", "issuer_id", unique=True),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    issuer_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, default=generate_issuer_id)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default=IssuerStatus.ACTIVE.value, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    signing_keys: Mapped[list["IssuerSigningKey"]] = relationship(
        "IssuerSigningKey", back_populates="issuer", cascade="all, delete-orphan"
    )
    credentials: Mapped[list["AgentCredential"]] = relationship(
        "AgentCredential", back_populates="issuer", cascade="all, delete-orphan"
    )


class IssuerSigningKey(Base):
    """Public Ed25519 signing key registered for an Issuer."""

    __tablename__ = "issuer_signing_keys"
    __table_args__ = (
        Index("ix_issuer_keys_issuer_status", "issuer_id", "status"),
        Index("ix_issuer_keys_key_id", "key_id", unique=True),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    key_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, default=generate_issuer_key_id)
    issuer_id: Mapped[UUID] = mapped_column(
        ForeignKey("credential_issuers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    algorithm: Mapped[str] = mapped_column(String(20), default="Ed25519", nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default=IssuerKeyStatus.ACTIVE.value, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rotated_from_key_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    issuer: Mapped["CredentialIssuer"] = relationship("CredentialIssuer", back_populates="signing_keys")


class AgentCredential(Base):
    """Cryptographically verifiable credential issued to an Agent."""

    __tablename__ = "agent_credentials"
    __table_args__ = (
        Index("ix_agent_credentials_cred_id", "credential_id", unique=True),
        Index("ix_agent_credentials_issuer", "issuer_id"),
        Index("ix_agent_credentials_subject", "subject_agent_id", "status"),
        Index("ix_agent_credentials_org", "organization_id"),
        Index("ix_agent_credentials_status_expires", "status", "expires_at"),
        Index("ix_agent_credentials_signing_key", "signing_key_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    credential_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, default=generate_credential_id)
    issuer_id: Mapped[UUID] = mapped_column(
        ForeignKey("credential_issuers.id", ondelete="CASCADE"), nullable=False
    )
    subject_agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    credential_type: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(16), default="ATC/1.0", nullable=False)
    environment: Mapped[str] = mapped_column(String(16), default="production", nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default=CredentialStatus.ACTIVE.value, nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    claims_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    claims_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    signature_value: Mapped[str] = mapped_column(Text, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    issuer: Mapped["CredentialIssuer"] = relationship("CredentialIssuer", back_populates="credentials")
