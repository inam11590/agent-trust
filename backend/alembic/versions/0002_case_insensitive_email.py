"""Enforce case-insensitive unique account email addresses.

Revision ID: 0002
Revises: 0001
"""

from alembic import context, op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if not context.is_offline_mode():
        duplicate = op.get_bind().scalar(sa.text(
            "SELECT 1 FROM users GROUP BY lower(email) HAVING count(*) > 1 LIMIT 1"
        ))
        if duplicate is not None:
            raise RuntimeError(
                "Case-insensitive duplicate emails exist. Resolve these accounts before migration; "
                "no accounts have been modified."
            )
    op.create_index("uq_users_email_lower", "users", [sa.text("lower(email)")], unique=True)


def downgrade() -> None:
    op.drop_index("uq_users_email_lower", table_name="users")
