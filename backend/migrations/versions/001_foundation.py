"""SMON-001: accounts, sessions, servers, services and configuration history."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "admins",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(254), nullable=False, unique=True),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("totp_encrypted", sa.Text(), nullable=False),
        sa.Column("last_totp_step", sa.Integer(), nullable=False),
        sa.Column("recovery_hashes", pg.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id = 1", name="single_administrator"),
    )
    op.create_table(
        "auth_sessions",
        sa.Column("token_hash", sa.String(64), primary_key=True),
        sa.Column(
            "admin_id", sa.Integer(), sa.ForeignKey("admins.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("csrf_token", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_auth_sessions_expires_at", "auth_sessions", ["expires_at"])
    op.create_table(
        "rate_buckets",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("window", sa.Integer(), primary_key=True),
        sa.Column("count", sa.Integer(), nullable=False),
    )
    op.create_table(
        "servers",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("description", sa.String(1000), nullable=False),
        sa.Column("tags", pg.JSONB(), nullable=False),
        sa.Column("archived", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "services",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("server_id", sa.Uuid(), sa.ForeignKey("servers.id"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("archived", sa.Boolean(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("options", pg.JSONB(), nullable=False),
        sa.Column("credentials_encrypted", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("server_id", "name"),
    )
    op.create_index("ix_services_server_id", "services", ["server_id"])
    op.create_table(
        "service_revisions",
        sa.Column("service_id", sa.Uuid(), sa.ForeignKey("services.id"), primary_key=True),
        sa.Column("revision", sa.Integer(), primary_key=True),
        sa.Column("configuration", pg.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("action", sa.String(60), nullable=False),
        sa.Column("target_id", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])
    op.create_table(
        "component_heartbeats",
        sa.Column("name", sa.String(30), primary_key=True),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade():
    for table in (
        "component_heartbeats",
        "audit_events",
        "service_revisions",
        "services",
        "servers",
        "rate_buckets",
        "auth_sessions",
        "admins",
    ):
        op.drop_table(table)
