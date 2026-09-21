"""Create Enterprise SOC and Observability tables (Step 26).

Revision ID: 0027
Revises: 0026
Create Date: 2026-09-21
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0027"
down_revision: Union[str, None] = "0026"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add normalized columns to security_events if not present
    conn = op.get_bind()
    # Using batch / raw checks or add_column
    for col_name, col_type in [
        ("event_id", sa.String(length=64)),
        ("category", sa.String(length=64)),
        ("source_type", sa.String(length=64)),
        ("source_id", sa.String(length=128)),
        ("agent_id", sa.Uuid()),
        ("gateway_id", sa.Uuid()),
        ("credential_id", sa.Uuid()),
        ("request_id", sa.String(length=128)),
        ("trace_id", sa.String(length=128)),
        ("correlation_id", sa.String(length=128)),
        ("actor_type", sa.String(length=64)),
        ("actor_id", sa.String(length=128)),
        ("target_type", sa.String(length=64)),
        ("target_id", sa.String(length=128)),
        ("action", sa.String(length=128)),
        ("decision", sa.String(length=64)),
        ("risk_level", sa.String(length=32)),
        ("region", sa.String(length=64)),
        ("environment", sa.String(length=32)),
    ]:
        try:
            op.add_column("security_events", sa.Column(col_name, col_type, nullable=True))
        except Exception:
            pass

    # 2. detection_rules
    op.create_table(
        "detection_rules",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.String(length=512), nullable=False),
        sa.Column("event_type", sa.String(length=80), nullable=True),
        sa.Column("category", sa.String(length=64), nullable=True),
        sa.Column("conditions", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("threshold", sa.Integer(), server_default="1", nullable=False),
        sa.Column("window_seconds", sa.Integer(), server_default="300", nullable=False),
        sa.Column("severity", sa.String(length=16), server_default="HIGH", nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_detection_rules_rule_id", "detection_rules", ["rule_id"], unique=True)
    op.create_index("ix_detection_rules_org_enabled", "detection_rules", ["organization_id", "enabled"])

    # 3. security_alerts
    op.create_table(
        "security_alerts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("alert_id", sa.String(length=64), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("fingerprint", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=20), server_default="OPEN", nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=1024), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("event_count", sa.Integer(), server_default="1", nullable=False),
        sa.Column("assigned_to", sa.Uuid(), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", sa.Uuid(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.Uuid(), nullable=True),
        sa.Column("resolution_note", sa.String(length=1024), nullable=True),
        sa.Column("metadata_json", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["assigned_to"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["acknowledged_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["resolved_by"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_security_alerts_alert_id", "security_alerts", ["alert_id"], unique=True)
    op.create_index("ix_security_alerts_org_status", "security_alerts", ["organization_id", "status"])
    op.create_index("ix_security_alerts_fingerprint", "security_alerts", ["fingerprint"])

    # 4. security_export_destinations
    op.create_table(
        "security_export_destinations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("destination_id", sa.String(length=64), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("destination_type", sa.String(length=32), nullable=False),
        sa.Column("endpoint_url", sa.String(length=1024), nullable=True),
        sa.Column("secret_ref", sa.String(length=255), nullable=True),
        sa.Column("min_severity", sa.String(length=16), server_default="INFO", nullable=False),
        sa.Column("categories", sa.JSON(), server_default="[]", nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("status", sa.String(length=32), server_default="HEALTHY", nullable=False),
        sa.Column("last_export_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_error", sa.String(length=1024), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_security_exports_destination_id", "security_export_destinations", ["destination_id"], unique=True)
    op.create_index("ix_security_exports_org_enabled", "security_export_destinations", ["organization_id", "enabled"])

    # 5. security_export_dead_letters
    op.create_table(
        "security_export_dead_letters",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("destination_id", sa.String(length=64), nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("event_payload", sa.JSON(), nullable=False),
        sa.Column("error_message", sa.String(length=1024), nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="5", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    )

    # 6. security_investigations
    op.create_table(
        "security_investigations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.String(length=64), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="OPEN", nullable=False),
        sa.Column("severity", sa.String(length=16), server_default="HIGH", nullable=False),
        sa.Column("assigned_to", sa.Uuid(), nullable=True),
        sa.Column("related_alert_ids", sa.JSON(), server_default="[]", nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["assigned_to"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_security_investigations_case_id", "security_investigations", ["case_id"], unique=True)
    op.create_index("ix_security_investigations_org_status", "security_investigations", ["organization_id", "status"])


def downgrade() -> None:
    op.drop_table("security_investigations")
    op.drop_table("security_export_dead_letters")
    op.drop_table("security_export_destinations")
    op.drop_table("security_alerts")
    op.drop_table("detection_rules")
