"""Server alert policies and GoAccess polling history."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "servers", sa.Column("alert_settings", JSONB(), nullable=False, server_default="{}")
    )
    op.alter_column("servers", "alert_settings", server_default=None)
    op.create_table(
        "service_checks",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("service_id", sa.Uuid(), sa.ForeignKey("services.id"), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
    )
    for name in ("service_id", "observed_at"):
        op.create_index("ix_service_checks_" + name, "service_checks", [name])


def downgrade():
    op.drop_table("service_checks")
    op.drop_column("servers", "alert_settings")
