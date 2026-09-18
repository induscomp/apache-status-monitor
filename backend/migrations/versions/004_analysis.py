"""Correlated server frames, incidents, anomaly state and private notifications."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "server_frames",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("observation_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column("server_id", sa.Uuid(), sa.ForeignKey("servers.id"), nullable=False),
        sa.Column("service_id", sa.Uuid(), sa.ForeignKey("services.id"), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid", sa.Boolean(), nullable=False),
        sa.Column("metrics", pg.JSONB(), nullable=False),
        sa.Column("domains", pg.JSONB(), nullable=False),
        sa.Column("details", pg.JSONB()),
        sa.Column("resources", pg.JSONB(), nullable=False),
        sa.Column("warnings", pg.JSONB(), nullable=False),
    )
    for column in ("server_id", "service_id", "observed_at"):
        op.create_index("ix_server_frames_" + column, "server_frames", [column])
    op.create_table(
        "incidents",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("server_id", sa.Uuid(), sa.ForeignKey("servers.id"), nullable=False),
        sa.Column("service_id", sa.Uuid(), sa.ForeignKey("services.id"), nullable=False),
        sa.Column("subject", sa.String(300), nullable=False),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column("evidence", pg.JSONB(), nullable=False),
    )
    for column in ("server_id", "opened_at"):
        op.create_index("ix_incidents_" + column, "incidents", [column])
    op.create_table(
        "anomaly_states",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("service_id", sa.Uuid(), sa.ForeignKey("services.id"), nullable=False),
        sa.Column("subject", sa.String(300), nullable=False),
        sa.Column("last_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("bad", sa.Integer(), nullable=False),
        sa.Column("good", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), sa.ForeignKey("incidents.id")),
        sa.UniqueConstraint("service_id", "subject"),
    )
    op.create_table(
        "notification_config",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("encrypted", sa.Text(), nullable=False),
    )
    op.create_table(
        "email_deliveries",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("incident_id", sa.Uuid(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("transition", sa.String(30), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("error", sa.String(200)),
    )


def downgrade():
    for table in (
        "email_deliveries",
        "notification_config",
        "anomaly_states",
        "incidents",
        "server_frames",
    ):
        op.drop_table(table)
