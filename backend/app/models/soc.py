"""Enterprise SOC models: Detection rules, Security Alerts, SIEM Export destinations, Dead letters."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text, Uuid, func, text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    __table_args__ = (
        Index("ix_detection_rules_org_enabled", "organization_id", "enabled"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    rule_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True,
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(String(512), nullable=False)
    event_type: Mapped[str | None] = mapped_column(String(80), nullable=True)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    conditions: Mapped[dict] = mapped_column(JSON, default=dict, server_default=text("'{}'::json"), nullable=False)
    threshold: Mapped[int] = mapped_column(Integer, server_default="1", nullable=False)
    window_seconds: Mapped[int] = mapped_column(Integer, server_default="300", nullable=False)
    severity: Mapped[str] = mapped_column(String(16), server_default="HIGH", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    __table_args__ = (
        Index("ix_security_alerts_org_status", "organization_id", "status"),
        Index("ix_security_alerts_org_created", "organization_id", "created_at"),
        Index("ix_security_alerts_fingerprint", "fingerprint"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    alert_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False,
    )
    rule_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(20), server_default="OPEN", nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(1024), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, server_default="1", nullable=False)
    assigned_to: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolution_note: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, server_default=text("'{}'::json"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class SecurityExportDestination(Base):
    __tablename__ = "security_export_destinations"
    __table_args__ = (
        Index("ix_security_exports_org_enabled", "organization_id", "enabled"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    destination_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False,
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    destination_type: Mapped[str] = mapped_column(String(32), nullable=False)
    endpoint_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    secret_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    min_severity: Mapped[str] = mapped_column(String(16), server_default="INFO", nullable=False)
    categories: Mapped[list[str]] = mapped_column(JSON, default=list, server_default=text("'[]'::json"), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), server_default="HEALTHY", nullable=False)
    last_export_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    last_error: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class SecurityExportDeadLetter(Base):
    __tablename__ = "security_export_dead_letters"
    __table_args__ = (
        Index("ix_export_dead_letters_org", "organization_id"),
        Index("ix_export_dead_letters_dest", "destination_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    destination_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    event_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    event_payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    error_message: Mapped[str] = mapped_column(String(1024), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, server_default="5", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SecurityInvestigation(Base):
    __tablename__ = "security_investigations"
    __table_args__ = (
        Index("ix_security_investigations_org_status", "organization_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    case_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), server_default="OPEN", nullable=False)
    severity: Mapped[str] = mapped_column(String(16), server_default="HIGH", nullable=False)
    assigned_to: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    related_alert_ids: Mapped[list[str]] = mapped_column(JSON, default=list, server_default=text("'[]'::json"), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
