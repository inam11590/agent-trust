"""Database models for AgentTrust Policy-as-Code (APL/1.0).

Supports:
- Declarative Policies with version control and content hashing
- Immutable published PolicyVersions
- Multi-tier PolicyBindings (Organization, Agent, Capability, Environment)
- Test cases for automated policy unit testing
"""

from __future__ import annotations

from datetime import datetime, timezone
import secrets
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def generate_policy_id() -> str:
    """Generate collision-safe public identifier for a policy: pol_<hex>"""
    return f"pol_{secrets.token_hex(8)}"


class Policy(Base):
    """Authoritative container for a policy and its versions."""
    __tablename__ = "policies"
    __table_args__ = (
        Index("ix_policies_org_status", "organization_id", "status"),
        Index("ix_policies_scope", "scope_type", "scope_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    policy_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False, default=generate_policy_id)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    scope_type: Mapped[str] = mapped_column(String(32), default="organization", nullable=False)
    scope_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    environment: Mapped[str] = mapped_column(String(32), default="all", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="DRAFT", nullable=False)
    current_version_id: Mapped[Optional[UUID]] = mapped_column(Uuid, nullable=True)
    is_shadow: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_by: Mapped[Optional[UUID]] = mapped_column(Uuid, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    versions: Mapped[List[PolicyVersion]] = relationship(
        "PolicyVersion", back_populates="policy", cascade="all, delete-orphan", order_by="PolicyVersion.version_number.desc()"
    )
    bindings: Mapped[List[PolicyBinding]] = relationship(
        "PolicyBinding", back_populates="policy", cascade="all, delete-orphan"
    )
    test_cases: Mapped[List[PolicyTestCase]] = relationship(
        "PolicyTestCase", back_populates="policy", cascade="all, delete-orphan"
    )


class PolicyVersion(Base):
    """Immutable version of an APL policy document."""
    __tablename__ = "policy_versions"
    __table_args__ = (
        UniqueConstraint("policy_id", "version_number", name="uq_policy_version_number"),
        Index("ix_policy_versions_content_hash", "content_hash"),
        Index("ix_policy_versions_status", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    policy_id: Mapped[UUID] = mapped_column(
        ForeignKey("policies.id", ondelete="CASCADE"), index=True, nullable=False
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    source_format: Mapped[str] = mapped_column(String(16), default="yaml", nullable=False)
    source_document: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_document: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="DRAFT", nullable=False)
    rule_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_by: Mapped[Optional[UUID]] = mapped_column(Uuid, nullable=True)
    reviewed_by: Mapped[Optional[UUID]] = mapped_column(Uuid, nullable=True)
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    review_comment: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    published_by: Mapped[Optional[UUID]] = mapped_column(Uuid, nullable=True)
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    policy: Mapped[Policy] = relationship("Policy", back_populates="versions")


class PolicyBinding(Base):
    """Attachment of a policy to a target scope, environment, and priority."""
    __tablename__ = "policy_bindings"
    __table_args__ = (
        Index("ix_policy_bindings_lookup", "organization_id", "scope_type", "scope_id", "environment"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    policy_id: Mapped[UUID] = mapped_column(
        ForeignKey("policies.id", ondelete="CASCADE"), index=True, nullable=False
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scope_type: Mapped[str] = mapped_column(String(32), default="organization", nullable=False)
    scope_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    environment: Mapped[str] = mapped_column(String(32), default="all", nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    policy: Mapped[Policy] = relationship("Policy", back_populates="bindings")


class PolicyTestCase(Base):
    """Executable test specification for a policy."""
    __tablename__ = "policy_test_cases"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    policy_id: Mapped[UUID] = mapped_column(
        ForeignKey("policies.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    input_context: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    expected_decision: Mapped[str] = mapped_column(String(32), nullable=False)
    expected_rule_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    policy: Mapped[Policy] = relationship("Policy", back_populates="test_cases")
