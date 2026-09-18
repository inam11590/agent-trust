"""Organization security policy and provider-neutral OIDC configuration."""

from datetime import datetime
from decimal import Decimal
from uuid import UUID, uuid4

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, JSON, Numeric, String, Uuid, func, text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class OrganizationSecurityPolicy(Base):
    __tablename__ = "organization_security_policies"
    __table_args__ = (
        CheckConstraint("session_timeout_minutes BETWEEN 5 AND 60", name="session_timeout_range"),
        CheckConstraint("max_session_lifetime_minutes BETWEEN 15 AND 1440", name="max_session_lifetime_range"),
        CheckConstraint("require_manual_approval_above_amount IS NULL OR require_manual_approval_above_amount > 0", name="approval_threshold_positive"),
        CheckConstraint("approval_threshold_currency ~ '^[A-Z]{3}$'", name="approval_threshold_currency_format"),
    )

    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), primary_key=True)
    require_mfa: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    require_sso: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    session_timeout_minutes: Mapped[int] = mapped_column(Integer, server_default="15", nullable=False)
    max_session_lifetime_minutes: Mapped[int] = mapped_column(Integer, server_default="1440", nullable=False)
    allowed_email_domains: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    require_manual_approval_above_amount: Mapped[Decimal | None] = mapped_column(Numeric(19, 4))
    approval_threshold_currency: Mapped[str] = mapped_column(String(3), server_default="USD", nullable=False)
    block_critical_risk: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    require_approval_for_high_risk: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class SSOConnection(Base):
    __tablename__ = "sso_connections"
    __table_args__ = (Index("ix_sso_connections_org_status", "organization_id", "status"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False)
    provider_type: Mapped[str] = mapped_column(String(16), server_default="OIDC", nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    encrypted_client_secret: Mapped[str] = mapped_column(String(1024), nullable=False)
    discovery_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    allowed_domains: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(20), server_default="draft", nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class SSOLoginAttempt(Base):
    __tablename__ = "sso_login_attempts"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    connection_id: Mapped[UUID] = mapped_column(ForeignKey("sso_connections.id", ondelete="RESTRICT"), nullable=False)
    state_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    nonce_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    encrypted_code_verifier: Mapped[str] = mapped_column(String(512), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SSOLoginTicket(Base):
    __tablename__ = "sso_login_tickets"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    mfa_verified: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
