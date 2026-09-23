"""Database models for AgentTrust Agent Discovery (Step 29).

Covers:
- DiscoverySource: Multi-type discovery connectors (Kubernetes, Container, Cloud, CI/CD, Repository, Telemetry, Import)
- DiscoveryRun: Audited scan execution records with resource and candidate metrics
- DiscoveryCandidate: Discovered AI workloads, services, and pipelines with confidence scoring and matching
- DiscoveryEvidence: Safe, non-secret evidence records (frameworks, model SDKs, k8s labels, env var names)
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import secrets
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base

if TYPE_CHECKING:
    from app.models.agent import Agent
    from app.models.organization import Organization
    from app.models.user import User


class DiscoverySourceType(str, Enum):
    KUBERNETES = "KUBERNETES"
    CONTAINER_PLATFORM = "CONTAINER_PLATFORM"
    CLOUD = "CLOUD"
    CI_CD = "CI_CD"
    SOURCE_REPOSITORY = "SOURCE_REPOSITORY"
    GATEWAY_TELEMETRY = "GATEWAY_TELEMETRY"
    SIDECAR_TELEMETRY = "SIDECAR_TELEMETRY"
    RUNTIME_SIGNAL = "RUNTIME_SIGNAL"
    IMPORT = "IMPORT"


class DiscoverySourceStatus(str, Enum):
    CONFIGURED = "CONFIGURED"
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    ERROR = "ERROR"
    DISABLED = "DISABLED"


class DiscoveryRunStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class DiscoveryCandidateStatus(str, Enum):
    NEW = "NEW"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    MATCHED = "MATCHED"
    UNMANAGED = "UNMANAGED"
    ONBOARDING = "ONBOARDING"
    REGISTERED = "REGISTERED"
    IGNORED = "IGNORED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    STALE = "STALE"


class DiscoveryCandidateType(str, Enum):
    WORKLOAD = "WORKLOAD"
    SERVICE = "SERVICE"
    CONTAINER = "CONTAINER"
    REPOSITORY = "REPOSITORY"
    PIPELINE = "PIPELINE"
    RUNTIME_PROCESS = "RUNTIME_PROCESS"


class ConfidenceLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class EvidenceCategory(str, Enum):
    FRAMEWORK = "FRAMEWORK"
    PROVIDER = "PROVIDER"
    DEPLOYMENT = "DEPLOYMENT"
    NETWORK = "NETWORK"
    CONFIG = "CONFIG"
    METADATA = "METADATA"


class EvidenceStrength(str, Enum):
    WEAK = "WEAK"
    STRONG = "STRONG"
    VERIFIED = "VERIFIED"


def generate_discovery_source_id() -> str:
    return f"src_{secrets.token_hex(8)}"


def generate_discovery_run_id() -> str:
    return f"drun_{secrets.token_hex(8)}"


def generate_candidate_id() -> str:
    return f"cand_{secrets.token_hex(8)}"


def generate_evidence_id() -> str:
    return f"evd_{secrets.token_hex(8)}"


class DiscoverySource(Base):
    """External or internal source connecting infrastructure to Agent Discovery."""

    __tablename__ = "discovery_sources"
    __table_args__ = (
        Index("ix_discovery_sources_org_status", "organization_id", "status"),
        Index("ix_discovery_sources_org_type", "organization_id", "source_type"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    source_id: Mapped[str] = mapped_column(
        String(32), unique=True, nullable=False, index=True, default=generate_discovery_source_id
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), server_default=DiscoverySourceStatus.CONFIGURED.value, default=DiscoverySourceStatus.CONFIGURED.value, nullable=False
    )
    configuration: Mapped[dict] = mapped_column(JSON, default=dict, server_default=text("'{}'"), nullable=False)
    credential_reference: Mapped[str | None] = mapped_column(String(128), nullable=True)

    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    resources_examined_count: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"), nullable=False)
    candidates_found_count: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"), nullable=False)

    created_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    runs: Mapped[list["DiscoveryRun"]] = relationship(
        "DiscoveryRun", back_populates="source", cascade="all, delete-orphan", order_by="desc(DiscoveryRun.started_at)"
    )
    candidates: Mapped[list["DiscoveryCandidate"]] = relationship(
        "DiscoveryCandidate", back_populates="source", cascade="all, delete-orphan"
    )


class DiscoveryRun(Base):
    """Execution instance of an infrastructure discovery scan."""

    __tablename__ = "discovery_runs"
    __table_args__ = (
        Index("ix_discovery_runs_source_status", "source_id", "status"),
        Index("ix_discovery_runs_org_started", "organization_id", "started_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    run_id: Mapped[str] = mapped_column(
        String(32), unique=True, nullable=False, index=True, default=generate_discovery_run_id
    )
    source_id: Mapped[UUID] = mapped_column(
        ForeignKey("discovery_sources.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(20), server_default=DiscoveryRunStatus.PENDING.value, default=DiscoveryRunStatus.PENDING.value, nullable=False
    )
    trigger_type: Mapped[str] = mapped_column(String(32), default="MANUAL", server_default="MANUAL", nullable=False)

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    resources_examined: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"), nullable=False)
    candidates_found: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"), nullable=False)
    known_matches: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"), nullable=False)
    unmanaged_found: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"), nullable=False)
    errors_count: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"), nullable=False)
    error_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    run_summary: Mapped[dict] = mapped_column(JSON, default=dict, server_default=text("'{}'"), nullable=False)

    # Relationships
    source: Mapped["DiscoverySource"] = relationship("DiscoverySource", back_populates="runs")


class DiscoveryCandidate(Base):
    """Potential AI workload or agent candidate discovered across infrastructure."""

    __tablename__ = "discovery_candidates"
    __table_args__ = (
        Index("ix_discovery_candidates_org_status", "organization_id", "status"),
        Index("ix_discovery_candidates_fingerprint", "organization_id", "fingerprint"),
        Index("ix_discovery_candidates_confidence", "organization_id", "confidence_score"),
        Index("ix_discovery_candidates_matched_agent", "matched_agent_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    candidate_id: Mapped[str] = mapped_column(
        String(32), unique=True, nullable=False, index=True, default=generate_candidate_id
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_id: Mapped[UUID] = mapped_column(
        ForeignKey("discovery_sources.id", ondelete="CASCADE"), nullable=False, index=True
    )
    external_resource_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    candidate_type: Mapped[str] = mapped_column(String(64), nullable=False, default=DiscoveryCandidateType.WORKLOAD.value)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    environment: Mapped[str] = mapped_column(String(32), default="unknown", server_default="unknown", nullable=False)
    location_reference: Mapped[str] = mapped_column(String(255), nullable=False, default="")

    confidence_score: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"), nullable=False)
    confidence_level: Mapped[str] = mapped_column(String(16), default=ConfidenceLevel.LOW.value, server_default=ConfidenceLevel.LOW.value, nullable=False)
    confidence_reasons: Mapped[list] = mapped_column(JSON, default=list, server_default=text("'[]'"), nullable=False)

    status: Mapped[str] = mapped_column(
        String(32), default=DiscoveryCandidateStatus.NEW.value, server_default=DiscoveryCandidateStatus.NEW.value, nullable=False
    )
    matched_agent_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("agents.id", ondelete="SET NULL"), nullable=True
    )
    match_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    match_reasons: Mapped[list] = mapped_column(JSON, default=list, server_default=text("'[]'"), nullable=False)

    suggested_owner_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    suggested_owner_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    suggested_owner_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    suggested_owner_confidence: Mapped[str | None] = mapped_column(String(16), nullable=True)
    suggested_owner_reasons: Mapped[list] = mapped_column(JSON, default=list, server_default=text("'[]'"), nullable=False)

    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    ignored_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ignore_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    false_positive_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)

    evidence_summary: Mapped[dict] = mapped_column(JSON, default=dict, server_default=text("'{}'"), nullable=False)
    relationships: Mapped[list] = mapped_column(JSON, default=list, server_default=text("'[]'"), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    source: Mapped["DiscoverySource"] = relationship("DiscoverySource", back_populates="candidates")
    matched_agent: Mapped[Optional["Agent"]] = relationship("Agent", foreign_keys=[matched_agent_id])
    evidence_items: Mapped[list["DiscoveryEvidence"]] = relationship(
        "DiscoveryEvidence", back_populates="candidate", cascade="all, delete-orphan"
    )


class DiscoveryEvidence(Base):
    """Structured, safe point of evidence observed for a discovery candidate."""

    __tablename__ = "discovery_evidence"
    __table_args__ = (
        Index("ix_discovery_evidence_candidate", "candidate_id"),
        Index("ix_discovery_evidence_type", "evidence_type"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    evidence_id: Mapped[str] = mapped_column(
        String(32), unique=True, nullable=False, index=True, default=generate_evidence_id
    )
    candidate_id: Mapped[UUID] = mapped_column(
        ForeignKey("discovery_candidates.id", ondelete="CASCADE"), nullable=False, index=True
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_id: Mapped[UUID] = mapped_column(
        ForeignKey("discovery_sources.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False, default=EvidenceCategory.METADATA.value)
    strength: Mapped[str] = mapped_column(String(16), nullable=False, default=EvidenceStrength.WEAK.value)
    details: Mapped[dict] = mapped_column(JSON, default=dict, server_default=text("'{}'"), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    candidate: Mapped["DiscoveryCandidate"] = relationship("DiscoveryCandidate", back_populates="evidence_items")
