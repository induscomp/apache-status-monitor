"""MRTG discovery, metric configuration and observations."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "mrtg_discoveries",
        sa.Column("service_id", sa.Uuid(), sa.ForeignKey("services.id"), primary_key=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("attempted_at", sa.DateTime(timezone=True)),
        sa.Column("succeeded_at", sa.DateTime(timezone=True)),
        sa.Column("requested", sa.Boolean(), nullable=False),
        sa.Column("error", sa.Text()),
    )
    op.create_table(
        "mrtg_metrics",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("service_id", sa.Uuid(), sa.ForeignKey("services.id"), nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("selected", sa.Boolean(), nullable=False),
        sa.Column("present", sa.Boolean(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("configuration", pg.JSONB(), nullable=False),
        sa.UniqueConstraint("service_id", "url"),
    )
    op.create_index("ix_mrtg_metrics_service_id", "mrtg_metrics", ["service_id"])
    op.create_table(
        "mrtg_observations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("metric_id", sa.Uuid(), sa.ForeignKey("mrtg_metrics.id"), nullable=False),
        sa.Column("service_id", sa.Uuid(), sa.ForeignKey("services.id"), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("metric_revision", sa.Integer(), nullable=False),
        sa.Column("configuration", pg.JSONB(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_at", sa.DateTime(timezone=True)),
        sa.Column("source_time_text", sa.String(200)),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("values", pg.JSONB(), nullable=False),
        sa.Column("warnings", pg.JSONB(), nullable=False),
        sa.Column("raw_encrypted", sa.Text()),
    )
    for column in ("metric_id", "service_id", "observed_at"):
        op.create_index("ix_mrtg_observations_" + column, "mrtg_observations", [column])


def downgrade():
    for table in ("mrtg_observations", "mrtg_metrics", "mrtg_discoveries"):
        op.drop_table(table)
