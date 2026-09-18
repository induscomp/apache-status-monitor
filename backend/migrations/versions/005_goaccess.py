"""Optional GoAccess reports and independent polling state."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "goaccess_reports",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("service_id", sa.Uuid(), sa.ForeignKey("services.id"), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True)),
        sa.Column("summary", JSONB(), nullable=False),
        sa.Column("panels", JSONB(), nullable=False),
        sa.UniqueConstraint("service_id", "revision", "fingerprint"),
    )
    for name in ("service_id", "observed_at"):
        op.create_index("ix_goaccess_reports_" + name, "goaccess_reports", [name])
    op.create_table(
        "goaccess_states",
        sa.Column("service_id", sa.Uuid(), sa.ForeignKey("services.id"), primary_key=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("report_id", sa.Uuid(), sa.ForeignKey("goaccess_reports.id")),
        sa.Column("warnings", JSONB(), nullable=False),
    )


def downgrade():
    op.drop_table("goaccess_states")
    op.drop_table("goaccess_reports")
