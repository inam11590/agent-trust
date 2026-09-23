"""Agent Discovery tables and schema (Step 29).

Revision ID: 0030
Revises: 0029
Create Date: 2026-09-22
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0030"
down_revision: Union[str, None] = "0029"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. discovery_sources
    op.create_table(
        "discovery_sources",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.String(length=32), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=20), server_default="CONFIGURED", nullable=False),
        sa.Column("configuration", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("credential_reference", sa.String(length=128), nullable=True),
        sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=64), nullable=True),
        sa.Column("last_error_message", sa.Text(), nullable=True),
        sa.Column("resources_examined_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("candidates_found_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_id"),
    )
    op.create_index("ix_discovery_sources_source_id", "discovery_sources", ["source_id"], unique=True)
    op.create_index("ix_discovery_sources_org_status", "discovery_sources", ["organization_id", "status"])
    op.create_index("ix_discovery_sources_org_type", "discovery_sources", ["organization_id", "source_type"])

    # 2. discovery_runs
    op.create_table(
        "discovery_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.String(length=32), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=20), server_default="PENDING", nullable=False),
        sa.Column("trigger_type", sa.String(length=32), server_default="MANUAL", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resources_examined", sa.Integer(), server_default="0", nullable=False),
        sa.Column("candidates_found", sa.Integer(), server_default="0", nullable=False),
        sa.Column("known_matches", sa.Integer(), server_default="0", nullable=False),
        sa.Column("unmanaged_found", sa.Integer(), server_default="0", nullable=False),
        sa.Column("errors_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.Column("run_summary", sa.JSON(), server_default="{}", nullable=False),
        sa.ForeignKeyConstraint(["source_id"], ["discovery_sources.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id"),
    )
    op.create_index("ix_discovery_runs_run_id", "discovery_runs", ["run_id"], unique=True)
    op.create_index("ix_discovery_runs_source_status", "discovery_runs", ["source_id", "status"])
    op.create_index("ix_discovery_runs_org_started", "discovery_runs", ["organization_id", "started_at"])

    # 3. discovery_candidates
    op.create_table(
        "discovery_candidates",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("candidate_id", sa.String(length=32), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("external_resource_reference", sa.String(length=255), nullable=False),
        sa.Column("candidate_type", sa.String(length=64), server_default="WORKLOAD", nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column("environment", sa.String(length=32), server_default="unknown", nullable=False),
        sa.Column("location_reference", sa.String(length=255), server_default="", nullable=False),
        sa.Column("confidence_score", sa.Integer(), server_default="0", nullable=False),
        sa.Column("confidence_level", sa.String(length=16), server_default="LOW", nullable=False),
        sa.Column("confidence_reasons", sa.JSON(), server_default="[]", nullable=False),
        sa.Column("status", sa.String(length=32), server_default="NEW", nullable=False),
        sa.Column("matched_agent_id", sa.Uuid(), nullable=True),
        sa.Column("match_type", sa.String(length=32), nullable=True),
        sa.Column("match_reasons", sa.JSON(), server_default="[]", nullable=False),
        sa.Column("suggested_owner_id", sa.Uuid(), nullable=True),
        sa.Column("suggested_owner_type", sa.String(length=32), nullable=True),
        sa.Column("suggested_owner_name", sa.String(length=128), nullable=True),
        sa.Column("suggested_owner_confidence", sa.String(length=16), nullable=True),
        sa.Column("suggested_owner_reasons", sa.JSON(), server_default="[]", nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("ignored_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ignore_reason", sa.String(length=255), nullable=True),
        sa.Column("false_positive_reason", sa.String(length=255), nullable=True),
        sa.Column("evidence_summary", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("relationships", sa.JSON(), server_default="[]", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_id"], ["discovery_sources.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["matched_agent_id"], ["agents.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["suggested_owner_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("candidate_id"),
    )
    op.create_index("ix_discovery_candidates_candidate_id", "discovery_candidates", ["candidate_id"], unique=True)
    op.create_index("ix_discovery_candidates_org_status", "discovery_candidates", ["organization_id", "status"])
    op.create_index("ix_discovery_candidates_fingerprint", "discovery_candidates", ["organization_id", "fingerprint"])
    op.create_index("ix_discovery_candidates_confidence", "discovery_candidates", ["organization_id", "confidence_score"])
    op.create_index("ix_discovery_candidates_matched_agent", "discovery_candidates", ["matched_agent_id"])

    # 4. discovery_evidence
    op.create_table(
        "discovery_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.String(length=32), nullable=False),
        sa.Column("candidate_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_type", sa.String(length=64), nullable=False),
        sa.Column("category", sa.String(length=32), server_default="METADATA", nullable=False),
        sa.Column("strength", sa.String(length=16), server_default="WEAK", nullable=False),
        sa.Column("details", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["candidate_id"], ["discovery_candidates.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_id"], ["discovery_sources.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("evidence_id"),
    )
    op.create_index("ix_discovery_evidence_evidence_id", "discovery_evidence", ["evidence_id"], unique=True)
    op.create_index("ix_discovery_evidence_candidate", "discovery_evidence", ["candidate_id"])
    op.create_index("ix_discovery_evidence_type", "discovery_evidence", ["evidence_type"])


def downgrade() -> None:
    op.drop_table("discovery_evidence")
    op.drop_table("discovery_candidates")
    op.drop_table("discovery_runs")
    op.drop_table("discovery_sources")
