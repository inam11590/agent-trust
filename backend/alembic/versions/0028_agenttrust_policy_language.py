"""Create AgentTrust Policy Language tables (Step 27).

Revision ID: 0028
Revises: 0027
Create Date: 2026-09-22
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0028"
down_revision: Union[str, None] = "0027"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. policies
    op.create_table(
        "policies",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("policy_id", sa.String(length=64), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.String(length=512), server_default="", nullable=False),
        sa.Column("scope_type", sa.String(length=32), server_default="organization", nullable=False),
        sa.Column("scope_id", sa.String(length=64), nullable=True),
        sa.Column("environment", sa.String(length=32), server_default="all", nullable=False),
        sa.Column("status", sa.String(length=32), server_default="DRAFT", nullable=False),
        sa.Column("current_version_id", sa.Uuid(), nullable=True),
        sa.Column("is_shadow", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_policies_policy_id", "policies", ["policy_id"], unique=True)
    op.create_index("ix_policies_org_status", "policies", ["organization_id", "status"])
    op.create_index("ix_policies_scope", "policies", ["scope_type", "scope_id"])

    # 2. policy_versions
    op.create_table(
        "policy_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("policy_id", sa.Uuid(), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("source_format", sa.String(length=16), server_default="yaml", nullable=False),
        sa.Column("source_document", sa.Text(), nullable=False),
        sa.Column("normalized_document", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="DRAFT", nullable=False),
        sa.Column("rule_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("reviewed_by", sa.Uuid(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_comment", sa.String(length=512), nullable=True),
        sa.Column("published_by", sa.Uuid(), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["policy_id"], ["policies.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("policy_id", "version_number", name="uq_policy_version_number"),
    )
    op.create_index("ix_policy_versions_content_hash", "policy_versions", ["content_hash"])
    op.create_index("ix_policy_versions_status", "policy_versions", ["status"])

    # 3. policy_bindings
    op.create_table(
        "policy_bindings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("policy_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("scope_type", sa.String(length=32), server_default="organization", nullable=False),
        sa.Column("scope_id", sa.String(length=64), nullable=True),
        sa.Column("environment", sa.String(length=32), server_default="all", nullable=False),
        sa.Column("priority", sa.Integer(), server_default="100", nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["policy_id"], ["policies.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_policy_bindings_lookup", "policy_bindings", ["organization_id", "scope_type", "scope_id", "environment"])

    # 4. policy_test_cases
    op.create_table(
        "policy_test_cases",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("policy_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("input_context", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("expected_decision", sa.String(length=32), nullable=False),
        sa.Column("expected_rule_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["policy_id"], ["policies.id"], ondelete="CASCADE"),
    )


def downgrade() -> None:
    op.drop_table("policy_test_cases")
    op.drop_table("policy_bindings")
    op.drop_table("policy_versions")
    op.drop_table("policies")
