import os
import secrets

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.config import get_settings
from app.db import session_factory
from app.main import create_app
from app.models import Admin
from app.security import PASSWORDS, digest


@pytest.fixture(autouse=True)
def clean_database():
    settings = get_settings()
    if settings.environment != "testing" or "smon_test" not in os.environ.get(
        "SMON_DATABASE_URL", ""
    ):
        pytest.fail("Tests require an isolated smon_test PostgreSQL database")
    with session_factory()() as db:
        db.execute(
            text(
                "TRUNCATE admins, servers, audit_events, rate_buckets, component_heartbeats CASCADE"
            )
        )
        db.commit()


@pytest.fixture
def client():
    with TestClient(create_app(), base_url=get_settings().public_origin) as client:
        client.headers["origin"] = get_settings().public_origin
        yield client


@pytest.fixture
def account():
    secret = pyotp.random_base32()
    password = secrets.token_urlsafe(30)
    recovery = secrets.token_hex(12)
    with session_factory()() as db:
        db.add(
            Admin(
                id=1,
                email="admin@example.test",
                password_hash=PASSWORDS.hash(password),
                totp_encrypted=get_settings().cipher().encrypt(secret.encode()).decode(),
                recovery_hashes=[digest(recovery)],
            )
        )
        db.commit()
    return {
        "email": "admin@example.test",
        "password": password,
        "secret": secret,
        "recovery": recovery,
    }


@pytest.fixture
def logged_in(client, account):
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": account["email"],
            "password": account["password"],
            "code": pyotp.TOTP(account["secret"]).now(),
        },
    )
    assert response.status_code == 200
    client.headers["x-csrf-token"] = response.json()["csrf_token"]
    return client
