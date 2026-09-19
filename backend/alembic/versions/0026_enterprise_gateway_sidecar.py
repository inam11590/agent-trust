"""Create Enterprise Gateways and Configuration Bundles tables (Step 23).

Revision ID: 0026
Revises: 0025
Create Date: 2026-09-19
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0026"
down_revision: Union[str, None] = "0025"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. enterprise_gateways
    op.create_table(
        "enterprise_gateways",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("gateway_id", sa.String(length=64), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("deployment_type", sa.String(length=32), server_default="SELF_HOSTED_GATEWAY", nullable=False),
        sa.Column("environment", sa.String(length=32), server_default="PRODUCTION", nullable=False),
        sa.Column("status", sa.String(length=32), server_default="ENROLLING", nullable=False),
        sa.Column("version", sa.String(length=32), server_default="1.0.0", nullable=False),
        sa.Column("public_key", sa.String(length=64), nullable=True),
        sa.Column("fingerprint", sa.String(length=64), nullable=True),
        sa.Column("enrollment_token_hash", sa.String(length=64), nullable=True),
        sa.Column("enrollment_token_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("config_version", sa.Integer(), server_default="0", nullable=False),
        sa.Column("labels", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("offline_policy", sa.String(length=32), server_default="FAIL_CLOSED", nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_heartbeat_data", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("suspended_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("gateway_id"),
    )
    op.create_index("ix_enterprise_gateways_gateway_id", "enterprise_gateways", ["gateway_id"], unique=True)
    op.create_index("ix_enterprise_gateways_org_env", "enterprise_gateways", ["organization_id", "environment"])
    op.create_index("ix_enterprise_gateways_status", "enterprise_gateways", ["status"])
    op.create_index("ix_enterprise_gateways_last_seen", "enterprise_gateways", ["last_seen_at"])

    # 2. gateway_config_bundles
    op.create_table(
        "gateway_config_bundles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("environment", sa.String(length=32), server_default="production", nullable=False),
        sa.Column("config_version", sa.Integer(), nullable=False),
        sa.Column("bundle_json", sa.JSON(), nullable=False),
        sa.Column("bundle_sha256", sa.String(length=64), nullable=False),
        sa.Column("signature", sa.String(length=128), nullable=False),
        sa.Column("signing_key_id", sa.String(length=64), nullable=False),
        sa.Column("published_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["published_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_config_bundles_org_ver",
        "gateway_config_bundles",
        ["organization_id", "config_version"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_config_bundles_org_ver", table_name="gateway_config_bundles")
    op.drop_table("gateway_config_bundles")

    op.drop_index("ix_enterprise_gateways_last_seen", table_name="enterprise_gateways")
    op.drop_index("ix_enterprise_gateways_status", table_name="enterprise_gateways")
    op.drop_index("ix_enterprise_gateways_org_env", table_name="enterprise_gateways")
    op.drop_index("ix_enterprise_gateways_gateway_id", table_name="enterprise_gateways")
    op.drop_table("enterprise_gateways")
