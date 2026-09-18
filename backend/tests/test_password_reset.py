import secrets
from concurrent.futures import ThreadPoolExecutor

import jwt
import pyotp
import pytest
from sqlalchemy import func, select
from test_access import access_keys as access_keys_fixture
from test_auth import credentials

from app.db import session_factory
from app.models import Admin, AuditEvent, AuthSession
from app.security import digest, password_valid

access_keys = access_keys_fixture

URL = "/api/v1/auth/password-reset"


@pytest.fixture
def access_client(client, account, access_keys, monkeypatch):
    import app.security as security
    from app.config import get_settings

    key, verifier, claims, settings = access_keys
    settings.public_origin = get_settings().public_origin
    monkeypatch.setattr(security, "get_settings", lambda: settings)
    client.app.state.access_verifier = verifier
    client.headers["cf-access-jwt-assertion"] = jwt.encode(
        claims, key, algorithm="RS256", headers={"kid": "fixture-key"}
    )
    return client


def body(account, code=None):
    return {
        "password": secrets.token_urlsafe(24),
        "code": code or pyotp.TOTP(account["secret"]).now(),
    }


def test_reset_unavailable_without_verified_access(client, account):
    assert client.get(URL).json() == {"available": False}
    assert client.post(URL, json=body(account)).status_code == 403
    with session_factory()() as db:
        assert password_valid(db.get(Admin, 1).password_hash, account["password"])


def test_reset_requires_correct_access_and_origin(access_client, account, access_keys):
    client = access_client
    payload = body(account)
    assert client.get(URL).json() == {"available": True}
    assert (
        client.post(URL, json=payload, headers={"origin": "https://evil.example"}).status_code
        == 403
    )
    key, _, claims, _ = access_keys
    for change in [{"email": "other@example.test"}, {"aud": "other-app"}, {"exp": 1}]:
        token = jwt.encode(
            {**claims, **change}, key, algorithm="RS256", headers={"kid": "fixture-key"}
        )
        assert (
            client.post(URL, json=payload, headers={"cf-access-jwt-assertion": token}).status_code
            == 403
        )
    client.headers.pop("cf-access-jwt-assertion")
    assert client.post(URL, json=payload).status_code == 403
    with session_factory()() as db:
        assert password_valid(db.get(Admin, 1).password_hash, account["password"])


def test_reset_revokes_sessions_consumes_recovery_and_preserves_mfa(access_client, account):
    client = access_client
    assert client.post("/api/v1/auth/login", json=credentials(account)).status_code == 200
    with session_factory()() as db:
        admin = db.get(Admin, 1)
        original_mfa = admin.totp_encrypted
        extra = secrets.token_hex(12)
        admin.recovery_hashes = [*admin.recovery_hashes, digest(extra)]
        db.commit()
    payload = body(account, account["recovery"])
    response = client.post(URL, json=payload)
    assert response.status_code == 204
    assert "Max-Age=0" in response.headers["set-cookie"]
    assert payload["password"] not in response.text
    with session_factory()() as db:
        admin = db.get(Admin, 1)
        assert password_valid(admin.password_hash, payload["password"])
        assert not password_valid(admin.password_hash, account["password"])
        assert admin.totp_encrypted == original_mfa
        assert digest(account["recovery"]) not in admin.recovery_hashes
        assert db.scalar(select(func.count()).select_from(AuthSession)) == 0
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "auth.password_reset"))
    assert client.post(URL, json=payload).status_code == 403
    assert client.post("/api/v1/auth/login", json=credentials(account, extra)).status_code == 401
    assert (
        client.post(
            "/api/v1/auth/login",
            json={**credentials(account, extra), "password": payload["password"]},
        ).status_code
        == 200
    )


def test_reset_limits_failures_and_does_not_disclose_password(access_client, account):
    client = access_client
    payload = body(account, "invalid-code")
    assert client.post(URL, json={**payload, "password": "short"}).status_code == 422
    for _ in range(5):
        response = client.post(URL, json=payload)
        assert response.status_code == 403
        assert payload["password"] not in response.text
    assert client.post(URL, json=body(account)).status_code == 429
    with session_factory()() as db:
        assert password_valid(db.get(Admin, 1).password_hash, account["password"])


def test_concurrent_totp_reset_is_single_use(access_client, account):
    payload = body(account)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda _: access_client.post(URL, json=payload).status_code, range(2))
        )
    assert sorted(results) == [204, 403]
    with session_factory()() as db:
        assert (
            db.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == "auth.password_reset")
            )
            == 1
        )
