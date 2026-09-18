"""User persistence model. Only password hashes belong in hashed_password."""

from __future__ import annotations

from typing import TYPE_CHECKING

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, UUIDTimestampMixin

if TYPE_CHECKING:
    from app.models.agent import Agent
    from app.models.audit_log import AuditLog
    from app.models.authorization_request import AuthorizationRequestRecord
    from app.models.organization import Organization
    from app.models.permission import Permission


class User(UUIDTimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (Index("uq_users_email_lower", func.lower(email), unique=True),)

    organizations: Mapped[list[Organization]] = relationship(back_populates="owner", passive_deletes="all")
    agents: Mapped[list[Agent]] = relationship(back_populates="owner", passive_deletes="all")
    permissions: Mapped[list[Permission]] = relationship(back_populates="owner", passive_deletes="all")
    audit_logs: Mapped[list[AuditLog]] = relationship(back_populates="user", passive_deletes="all")
    authorization_requests: Mapped[list[AuthorizationRequestRecord]] = relationship(
        back_populates="user", passive_deletes="all",
    )
