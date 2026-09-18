"""Manual support email drafts and durable send attempts."""

import sqlalchemy as sa
from alembic import op

revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "support_reports",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("server_id", sa.Uuid(), sa.ForeignKey("servers.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("encrypted", sa.Text(), nullable=False),
        sa.Column("error", sa.String(200), nullable=True),
    )
    for name in ("server_id", "created_at"):
        op.create_index("ix_support_reports_" + name, "support_reports", [name])


def downgrade():
    op.drop_table("support_reports")
