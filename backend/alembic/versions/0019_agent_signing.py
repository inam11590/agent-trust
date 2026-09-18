"""Public agent signing keys, replay fallback, and safe audit metadata."""

from alembic import op
import sqlalchemy as sa

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_signing_keys",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("key_id", sa.String(31), nullable=False, unique=True),
        sa.Column("agent_id", sa.Uuid(), sa.ForeignKey("agents.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id", ondelete="RESTRICT")),
        sa.Column("algorithm", sa.String(16), nullable=False),
        sa.Column("public_key", sa.String(44), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False, unique=True),
        sa.Column("status", sa.Enum("ACTIVE", "ROTATING", "REVOKED", "EXPIRED", name="agent_signing_key_status", native_enum=False, create_constraint=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("rotated_from_key_id", sa.String(31)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_agent_signing_keys_agent_status", "agent_signing_keys", ["agent_id", "status"])
    op.create_index("ix_agent_signing_keys_org_status", "agent_signing_keys", ["organization_id", "status"])
    op.create_index("ix_agent_signing_keys_expires", "agent_signing_keys", ["expires_at"])
    op.create_table(
        "agent_request_nonces",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("key_id", sa.String(31), nullable=False),
        sa.Column("nonce_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("key_id", "nonce_hash", name="uq_agent_request_nonce"),
    )
    op.create_index("ix_agent_request_nonces_expires", "agent_request_nonces", ["expires_at"])
    for table in ("audit_logs", "authorization_requests"):
        op.add_column(table, sa.Column("signature_verified", sa.Boolean(), nullable=False, server_default=sa.false()))
        op.add_column(table, sa.Column("signing_key_id", sa.String(31)))
        op.add_column(table, sa.Column("signature_version", sa.String(8)))


def downgrade() -> None:
    for table in ("authorization_requests", "audit_logs"):
        op.drop_column(table, "signature_version")
        op.drop_column(table, "signing_key_id")
        op.drop_column(table, "signature_verified")
    op.drop_index("ix_agent_request_nonces_expires", table_name="agent_request_nonces")
    op.drop_table("agent_request_nonces")
    op.drop_index("ix_agent_signing_keys_expires", table_name="agent_signing_keys")
    op.drop_index("ix_agent_signing_keys_org_status", table_name="agent_signing_keys")
    op.drop_index("ix_agent_signing_keys_agent_status", table_name="agent_signing_keys")
    op.drop_table("agent_signing_keys")
