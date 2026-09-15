"""Synthetic administrator, exclusively for the isolated E2E database."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pyotp

from app.config import get_settings
from app.db import session_factory
from app.models import Admin
from app.security import PASSWORDS, digest

if get_settings().environment != "testing" or "smon_test" not in os.environ["SMON_DATABASE_URL"]:
    raise SystemExit("Refusing to seed a non-test database")
with session_factory()() as db:
    db.add(
        Admin(
            id=1,
            email="admin@example.test",
            password_hash=PASSWORDS.hash(os.environ["SMON_E2E_PASSWORD"]),
            totp_encrypted=get_settings().cipher().encrypt(pyotp.random_base32().encode()).decode(),
            recovery_hashes=[digest("e2e-recovery-fixture")],
        )
    )
    db.commit()
