from datetime import timedelta

import pyotp
from sqlalchemy import select

from app.config import get_settings
from app.db import session_factory
from app.models import AuthSession, now


def credentials(account, code=None):
    return {
        "email": account["email"],
        "password": account["password"],
        "code": code or pyotp.TOTP(account["secret"]).now(),
    }


def test_private_endpoints_require_session(client):
    for path in ("/servers", "/connectors", "/health", "/auth/session"):
        assert client.get("/api/v1" + path).status_code == 401
    assert client.get("/health/live").json() == {"status": "ok"}
    assert client.get("/health/ready").json() == {"status": "ok"}


def test_login_origin_and_invalid_credentials(client, account):
    body = credentials(account)
    assert (
        client.post(
            "/api/v1/auth/login", json=body, headers={"origin": "https://evil.example"}
        ).status_code
        == 403
    )
    assert (
        client.post("/api/v1/auth/login", json={**body, "password": "incorrect"}).status_code == 401
    )
    assert client.post("/api/v1/auth/login", json={**body, "code": "éééééé"}).status_code == 401


def test_totp_replay_and_recovery_code_single_use(client, account):
    body = credentials(account)
    response = client.post("/api/v1/auth/login", json=body)
    assert response.status_code == 200
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "SameSite=strict" in response.headers["set-cookie"]
    assert client.post("/api/v1/auth/login", json=body).status_code == 401
    recovered = credentials(account, account["recovery"])
    assert client.post("/api/v1/auth/login", json=recovered).status_code == 200
    assert client.post("/api/v1/auth/login", json=recovered).status_code == 401


def test_csrf_logout_and_hashed_session(logged_in):
    token = logged_in.cookies.get(get_settings().cookie_name)
    with session_factory()() as db:
        session = db.scalar(select(AuthSession))
        assert session.token_hash != token
        assert len(session.token_hash) == 64
    assert (
        logged_in.post(
            "/api/v1/servers", json={"name": "one"}, headers={"x-csrf-token": "bad"}
        ).status_code
        == 403
    )
    assert logged_in.post("/api/v1/auth/logout").status_code == 204
    assert logged_in.get("/api/v1/servers").status_code == 401


def test_expired_and_revoked_sessions(logged_in):
    with session_factory()() as db:
        db.scalar(select(AuthSession)).expires_at = now() - timedelta(seconds=1)
        db.commit()
    assert logged_in.get("/api/v1/auth/session").status_code == 401


def test_revoke_all_sessions(logged_in):
    assert logged_in.post("/api/v1/auth/revoke-sessions").status_code == 204
    assert logged_in.get("/api/v1/auth/session").status_code == 401


def test_rate_limit_persists_across_failed_transactions(client, account):
    body = {**credentials(account), "password": "wrong"}
    for _ in range(5):
        assert client.post("/api/v1/auth/login", json=body).status_code == 401
    response = client.post("/api/v1/auth/login", json=credentials(account))
    assert response.status_code == 429
    assert response.headers["retry-after"] == "300"


def test_errors_do_not_echo_passwords_and_body_is_bounded(client):
    secret = "input-that-must-not-be-reflected"
    response = client.post("/api/v1/auth/login", json={"password": secret, "unexpected": secret})
    assert response.status_code == 422
    assert secret not in response.text
    oversized = client.post("/api/v1/auth/login", content=b"x" * 17000)
    assert oversized.status_code == 413
    chunked = client.post("/api/v1/auth/login", content=iter([b"x" * 9000, b"x" * 9000]))
    assert chunked.status_code == 413


def test_unexpected_errors_do_not_leak_exception_text(client, caplog):
    from app.db import get_db

    secret = "private-database-parameter"

    def broken_database():
        raise RuntimeError(secret)

    client.app.dependency_overrides[get_db] = broken_database
    response = client.get("/api/v1/servers")
    assert response.status_code == 500
    assert secret not in response.text
    assert secret not in caplog.text
    assert '"type": "RuntimeError"' in caplog.text
