"""Public agent signing keys and short-lived database replay records."""

from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Enum as SqlEnum, ForeignKey, Index, String, Uuid, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class AgentSigningKeyStatus(str, Enum):
    ACTIVE = "ACTIVE"
    ROTATING = "ROTATING"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class AgentSigningKey(Base):
    __tablename__ = "agent_signing_keys"
    __table_args__ = (
        Index("ix_agent_signing_keys_agent_status", "agent_id", "status"),
        Index("ix_agent_signing_keys_org_status", "organization_id", "status"),
        Index("ix_agent_signing_keys_expires", "expires_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    key_id: Mapped[str] = mapped_column(String(31), unique=True, nullable=False)
    agent_id: Mapped[UUID] = mapped_column(ForeignKey("agents.id", ondelete="RESTRICT"), nullable=False)
    organization_id: Mapped[UUID | None] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"))
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    public_key: Mapped[str] = mapped_column(String(44), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    status: Mapped[AgentSigningKeyStatus] = mapped_column(
        SqlEnum(AgentSigningKeyStatus, name="agent_signing_key_status", native_enum=False, create_constraint=True,
                values_callable=lambda values: [value.value for value in values]),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rotated_from_key_id: Mapped[str | None] = mapped_column(String(31))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AgentRequestNonce(Base):
    __tablename__ = "agent_request_nonces"
    __table_args__ = (
        UniqueConstraint("key_id", "nonce_hash", name="uq_agent_request_nonce"),
        Index("ix_agent_request_nonces_expires", "expires_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    key_id: Mapped[str] = mapped_column(String(31), nullable=False)
    nonce_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
