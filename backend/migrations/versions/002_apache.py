"""Apache observations, normalized workers and short-lived encrypted originals."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "apache_observations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("service_id", sa.Uuid(), sa.ForeignKey("services.id"), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("metrics", pg.JSONB(), nullable=False),
        sa.Column("warnings", pg.JSONB(), nullable=False),
        sa.Column("workers", pg.JSONB(), nullable=True),
        sa.Column("raw_encrypted", sa.Text(), nullable=True),
    )
    op.create_index("ix_apache_observations_service_id", "apache_observations", ["service_id"])
    op.create_index("ix_apache_observations_observed_at", "apache_observations", ["observed_at"])


def downgrade():
    op.drop_table("apache_observations")
