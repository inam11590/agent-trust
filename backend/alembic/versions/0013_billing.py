"""Add subscription plans, organization billing, usage, and provider events.

Revision ID: 0013
Revises: 0012
"""

from alembic import op
import sqlalchemy as sa

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None

FREE_ID = "10000000-0000-0000-0000-000000000001"
STARTER_ID = "10000000-0000-0000-0000-000000000002"
BUSINESS_ID = "10000000-0000-0000-0000-000000000003"
ENTERPRISE_ID = "10000000-0000-0000-0000-000000000004"


def upgrade() -> None:
    op.create_table(
        "subscription_plans",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("name", sa.String(80), nullable=False),
        sa.Column("code", sa.String(32), nullable=False), sa.Column("description", sa.String(255), nullable=False),
        sa.Column("monthly_price", sa.Numeric(10, 2), nullable=True), sa.Column("yearly_price", sa.Numeric(10, 2), nullable=True),
        sa.Column("currency", sa.String(3), server_default="USD", nullable=False),
        sa.Column("max_organizations", sa.Integer(), nullable=True), sa.Column("max_members", sa.Integer(), nullable=True),
        sa.Column("max_agents", sa.Integer(), nullable=True), sa.Column("max_api_keys", sa.Integer(), nullable=True),
        sa.Column("max_authorization_requests_monthly", sa.Integer(), nullable=True), sa.Column("max_webhooks", sa.Integer(), nullable=True),
        sa.Column("risk_engine_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("advanced_risk_controls", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("advanced_notifications_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("priority_support", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("monthly_price IS NULL OR monthly_price >= 0", name="monthly_price_nonnegative"),
        sa.CheckConstraint("yearly_price IS NULL OR yearly_price >= 0", name="yearly_price_nonnegative"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("code"),
    )
    plans = sa.table(
        "subscription_plans", sa.column("id", sa.Uuid()), sa.column("name", sa.String()), sa.column("code", sa.String()),
        sa.column("description", sa.String()), sa.column("monthly_price", sa.Numeric()), sa.column("currency", sa.String()),
        sa.column("max_organizations", sa.Integer()), sa.column("max_members", sa.Integer()), sa.column("max_agents", sa.Integer()),
        sa.column("max_api_keys", sa.Integer()), sa.column("max_authorization_requests_monthly", sa.Integer()),
        sa.column("max_webhooks", sa.Integer()), sa.column("risk_engine_enabled", sa.Boolean()),
        sa.column("advanced_risk_controls", sa.Boolean()), sa.column("advanced_notifications_enabled", sa.Boolean()),
        sa.column("priority_support", sa.Boolean()), sa.column("is_active", sa.Boolean()),
    )
    op.bulk_insert(plans, [
        {"id": FREE_ID, "name": "Free", "code": "free", "description": "For testing AgentTrust with a small team.", "monthly_price": 0, "currency": "USD", "max_organizations": 1, "max_members": 3, "max_agents": 3, "max_api_keys": 2, "max_authorization_requests_monthly": 1000, "max_webhooks": 1, "risk_engine_enabled": True, "advanced_risk_controls": False, "advanced_notifications_enabled": False, "priority_support": False, "is_active": True},
        {"id": STARTER_ID, "name": "Starter", "code": "starter", "description": "For startups using agents in production.", "monthly_price": 29, "currency": "USD", "max_organizations": 3, "max_members": 10, "max_agents": 10, "max_api_keys": 10, "max_authorization_requests_monthly": 20000, "max_webhooks": 5, "risk_engine_enabled": True, "advanced_risk_controls": False, "advanced_notifications_enabled": True, "priority_support": False, "is_active": True},
        {"id": BUSINESS_ID, "name": "Business", "code": "business", "description": "For larger teams with advanced controls.", "monthly_price": 149, "currency": "USD", "max_organizations": 10, "max_members": 50, "max_agents": 100, "max_api_keys": 50, "max_authorization_requests_monthly": 500000, "max_webhooks": 25, "risk_engine_enabled": True, "advanced_risk_controls": True, "advanced_notifications_enabled": True, "priority_support": True, "is_active": True},
        {"id": ENTERPRISE_ID, "name": "Enterprise", "code": "enterprise", "description": "Custom limits and support for large organizations.", "monthly_price": None, "currency": "USD", "max_organizations": None, "max_members": None, "max_agents": None, "max_api_keys": None, "max_authorization_requests_monthly": None, "max_webhooks": None, "risk_engine_enabled": True, "advanced_risk_controls": True, "advanced_notifications_enabled": True, "priority_support": True, "is_active": True},
    ])
    op.create_table(
        "organization_subscriptions",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("plan_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.Enum("trialing", "active", "past_due", "canceled", "incomplete", "suspended", name="subscription_status", native_enum=False, create_constraint=True, length=32), server_default="active", nullable=False),
        sa.Column("billing_provider", sa.String(32), server_default="test", nullable=False),
        sa.Column("provider_customer_id", sa.String(80), nullable=True), sa.Column("provider_subscription_id", sa.String(80), nullable=True),
        sa.Column("current_period_start", sa.DateTime(timezone=True), nullable=False), sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cancel_at_period_end", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("trial_ends_at", sa.DateTime(timezone=True), nullable=True), sa.Column("grace_ends_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("canceled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["plan_id"], ["subscription_plans.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("organization_id"),
    )
    op.execute(sa.text(
        "INSERT INTO organization_subscriptions (id, organization_id, plan_id, status, billing_provider, current_period_start, current_period_end) "
        "SELECT gen_random_uuid(), id, CAST(:free_id AS uuid), 'active', 'test', date_trunc('month', now()), date_trunc('month', now()) + interval '1 month' "
        "FROM organizations ON CONFLICT (organization_id) DO NOTHING"
    ).bindparams(free_id=FREE_ID))
    op.create_table(
        "usage_records",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("metric", sa.Enum("authorization_requests", "api_requests", "active_agents", "api_keys", "team_members", "webhook_deliveries", "push_notifications", name="usage_metric", native_enum=False, create_constraint=True, length=32), nullable=False),
        sa.Column("period_start", sa.Date(), nullable=False), sa.Column("period_end", sa.Date(), nullable=False),
        sa.Column("quantity", sa.Integer(), server_default="0", nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("quantity >= 0", name="quantity_nonnegative"), sa.CheckConstraint("period_end > period_start", name="period_valid"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("organization_id", "metric", "period_start", name="uq_usage_org_metric_period"),
    )
    op.create_index("ix_usage_records_org_period", "usage_records", ["organization_id", "period_start", "period_end"])
    op.create_table(
        "billing_events",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("organization_id", sa.Uuid(), nullable=True),
        sa.Column("provider_event_id", sa.String(100), nullable=False), sa.Column("event_type", sa.String(80), nullable=False),
        sa.Column("status", sa.Enum("processed", "ignored", "failed", name="billing_event_status", native_enum=False, create_constraint=True, length=32), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("provider_event_id"),
    )
    op.create_index("ix_billing_events_org_created", "billing_events", ["organization_id", "created_at"])
    op.create_table(
        "billing_checkouts",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("plan_id", sa.Uuid(), nullable=False), sa.Column("created_by_user_id", sa.Uuid(), nullable=False),
        sa.Column("provider_session_id", sa.String(100), nullable=False), sa.Column("status", sa.String(24), server_default="pending", nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["plan_id"], ["subscription_plans.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("provider_session_id"),
    )
    op.create_index("ix_billing_checkouts_org_created", "billing_checkouts", ["organization_id", "created_at"])
    op.drop_constraint(op.f("ck_notifications_notification_type"), "notifications", type_="check")
    op.create_check_constraint(
        "notification_type", "notifications",
        "type IN ('authorization_pending','authorization_approved','authorization_rejected','permission_expiring','permission_expired','agent_suspended','agent_revoked','api_key_revoked','security_alert','team_invitation','high_risk_approval_required','billing_usage_warning','billing_plan_changed','billing_payment_failed','billing_canceling')",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_notifications_notification_type"), "notifications", type_="check")
    op.create_check_constraint(
        "notification_type", "notifications",
        "type IN ('authorization_pending','authorization_approved','authorization_rejected','permission_expiring','permission_expired','agent_suspended','agent_revoked','api_key_revoked','security_alert','team_invitation','high_risk_approval_required')",
    )
    op.drop_index("ix_billing_checkouts_org_created", table_name="billing_checkouts")
    op.drop_table("billing_checkouts")
    op.drop_index("ix_billing_events_org_created", table_name="billing_events")
    op.drop_table("billing_events")
    op.drop_index("ix_usage_records_org_period", table_name="usage_records")
    op.drop_table("usage_records")
    op.drop_table("organization_subscriptions")
    op.drop_table("subscription_plans")
