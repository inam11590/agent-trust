"""Create Trust Registry and Agent Credentials tables (Step 22).

Revision ID: 0025
Revises: 0024
Create Date: 2026-09-19
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0025"
down_revision: Union[str, None] = "0024"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. credential_issuers
    op.create_table(
        "credential_issuers",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("issuer_id", sa.String(length=32), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="ACTIVE"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("suspended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("issuer_id"),
    )
    op.create_index("ix_issuers_org_status", "credential_issuers", ["organization_id", "status"])
    op.create_index("ix_issuers_issuer_id", "credential_issuers", ["issuer_id"], unique=True)

    # 2. issuer_signing_keys
    op.create_table(
        "issuer_signing_keys",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("key_id", sa.String(length=64), nullable=False),
        sa.Column("issuer_id", sa.Uuid(), nullable=False),
        sa.Column("algorithm", sa.String(length=20), nullable=False, server_default="Ed25519"),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="ACTIVE"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotated_from_key_id", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(["issuer_id"], ["credential_issuers.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_id"),
    )
    op.create_index("ix_issuer_keys_issuer_status", "issuer_signing_keys", ["issuer_id", "status"])
    op.create_index("ix_issuer_keys_key_id", "issuer_signing_keys", ["key_id"], unique=True)

    # 3. agent_credentials
    op.create_table(
        "agent_credentials",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("credential_id", sa.String(length=64), nullable=False),
        sa.Column("issuer_id", sa.Uuid(), nullable=False),
        sa.Column("subject_agent_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("credential_type", sa.String(length=64), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False, server_default="ATC/1.0"),
        sa.Column("environment", sa.String(length=16), nullable=False, server_default="production"),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="ACTIVE"),
        sa.Column("signing_key_id", sa.String(length=64), nullable=False),
        sa.Column("claims_json", sa.JSON(), nullable=False),
        sa.Column("claims_hash", sa.String(length=64), nullable=False),
        sa.Column("signature_value", sa.Text(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason_code", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["issuer_id"], ["credential_issuers.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["subject_agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("credential_id"),
    )
    op.create_index("ix_agent_credentials_cred_id", "agent_credentials", ["credential_id"], unique=True)
    op.create_index("ix_agent_credentials_issuer", "agent_credentials", ["issuer_id"])
    op.create_index("ix_agent_credentials_subject", "agent_credentials", ["subject_agent_id", "status"])
    op.create_index("ix_agent_credentials_org", "agent_credentials", ["organization_id"])
    op.create_index("ix_agent_credentials_status_expires", "agent_credentials", ["status", "expires_at"])
    op.create_index("ix_agent_credentials_signing_key", "agent_credentials", ["signing_key_id"])

    # 4. Add required_credential_types to target_organization_policies
    op.add_column(
        "target_organization_policies",
        sa.Column("required_credential_types", sa.JSON(), nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("target_organization_policies", "required_credential_types")
    op.drop_table("agent_credentials")
    op.drop_table("issuer_signing_keys")
    op.drop_table("credential_issuers")
