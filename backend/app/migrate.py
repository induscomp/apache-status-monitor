"""Provision the restricted runtime role, then apply versioned migrations.

Only the one-shot migration container receives the owner credential.
"""

from pathlib import Path

import psycopg
from alembic import command
from alembic.config import Config
from psycopg import sql

from app.config import get_settings


def main():
    settings = get_settings()
    owner_password = settings.database_password_file.read_text().strip()
    with psycopg.connect(
        host=settings.database_host,
        dbname=settings.database_name,
        user=settings.database_user,
        password=owner_password,
        autocommit=True,
    ) as db:
        if not db.execute("SELECT 1 FROM pg_roles WHERE rolname = 'smon'").fetchone():
            password = Path("/run/secrets/db_password").read_text().strip()
            db.execute(
                sql.SQL(
                    "CREATE ROLE smon LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD {}"
                ).format(sql.Literal(password))
            )
        db.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        db.execute("GRANT USAGE ON SCHEMA public TO smon")
    command.upgrade(Config("alembic.ini"), "head")
    with psycopg.connect(
        host=settings.database_host,
        dbname=settings.database_name,
        user=settings.database_user,
        password=owner_password,
        autocommit=True,
    ) as db:
        db.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO smon")
        db.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO smon")
        db.execute("REVOKE ALL ON alembic_version FROM smon")


if __name__ == "__main__":
    main()
