"""Step 18: Developer Platform, Sandbox environment separation, and production access foundation."""

from alembic import op
import sqlalchemy as sa

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add environment column to api_keys
    op.add_column(
        "api_keys",
        sa.Column("environment", sa.String(16), nullable=False, server_default="production"),
    )
    op.create_index("ix_api_keys_org_env", "api_keys", ["organization_id", "environment"])

    # Add environment column to agents
    op.add_column(
        "agents",
        sa.Column("environment", sa.String(16), nullable=False, server_default="production"),
    )
    op.create_index("ix_agents_org_env", "agents", ["organization_id", "environment"])

    # Add environment column to authorization_requests
    op.add_column(
        "authorization_requests",
        sa.Column("environment", sa.String(16), nullable=False, server_default="production"),
    )

    # Add environment column to audit_logs
    op.add_column(
        "audit_logs",
        sa.Column("environment", sa.String(16), nullable=False, server_default="production"),
    )
    op.create_index("ix_audit_logs_org_env", "audit_logs", ["organization_id", "environment"])

    # Add environment column to webhook_endpoints
    op.add_column(
        "webhook_endpoints",
        sa.Column("environment", sa.String(16), nullable=False, server_default="production"),
    )

    # Add delivery details to webhook_deliveries
    op.add_column(
        "webhook_deliveries",
        sa.Column("is_test", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "webhook_deliveries",
        sa.Column("response_status", sa.Integer(), nullable=True),
    )
    op.add_column(
        "webhook_deliveries",
        sa.Column("response_body", sa.Text(), nullable=True),
    )

    # Add production access foundation to organizations
    op.add_column(
        "organizations",
        sa.Column("production_access_status", sa.String(20), nullable=False, server_default="NOT_REQUESTED"),
    )
    op.add_column(
        "organizations",
        sa.Column("production_requested_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "organizations",
        sa.Column("production_approved_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("organizations", "production_approved_at")
    op.drop_column("organizations", "production_requested_at")
    op.drop_column("organizations", "production_access_status")

    op.drop_column("webhook_deliveries", "response_body")
    op.drop_column("webhook_deliveries", "response_status")
    op.drop_column("webhook_deliveries", "is_test")

    op.drop_column("webhook_endpoints", "environment")

    op.drop_index("ix_audit_logs_org_env", table_name="audit_logs")
    op.drop_column("audit_logs", "environment")

    op.drop_column("authorization_requests", "environment")

    op.drop_index("ix_agents_org_env", table_name="agents")
    op.drop_column("agents", "environment")

    op.drop_index("ix_api_keys_org_env", table_name="api_keys")
    op.drop_column("api_keys", "environment")
