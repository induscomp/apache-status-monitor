import json
import secrets
import time
from concurrent.futures import ThreadPoolExecutor

import pyotp
import pytest
from sqlalchemy import select

from app.config import get_settings
from app.db import session_factory
from app.models import Admin, AuditEvent
from app.security import AccessVerifier, access_identity


@pytest.fixture
def installation(tmp_path, monkeypatch):
    token = secrets.token_urlsafe(32)
    path = tmp_path / "setup_token"
    path.write_text(token)
    monkeypatch.setattr(get_settings(), "setup_token_file", path)
    return {"token": token, "email": "owner@example.test", "password": secrets.token_urlsafe(24)}


def begin(client, installation):
    response = client.post("/api/v1/setup/start", json=installation)
    assert response.status_code == 200
    body = response.json()
    data = json.loads(get_settings().cipher().decrypt(body["ticket"].encode()))
    return body, data


def completion(installation, body, data):
    return {
        "token": installation["token"],
        "ticket": body["ticket"],
        "code": pyotp.TOTP(data["secret"]).now(),
    }


def test_web_setup_confirms_mfa_closes_and_can_login(client, installation):
    assert client.get("/api/v1/setup/status").json() == {"available": True}
    body, data = begin(client, installation)
    assert body["qr"].startswith("data:image/png;base64,iVBOR")
    assert body["manual_key"] == data["secret"]
    with session_factory()() as db:
        assert db.get(Admin, 1) is None
    payload = completion(installation, body, data)
    response = client.post("/api/v1/setup/finish", json=payload)
    assert response.status_code == 201
    codes = response.json()["recovery_codes"]
    assert len(set(codes)) == 8
    assert response.headers["cache-control"] == "no-store"
    assert client.get("/api/v1/setup/status").json() == {"available": False}
    assert client.post("/api/v1/setup/start", json=installation).status_code == 409
    assert client.post("/api/v1/setup/finish", json=payload).status_code == 409
    with session_factory()() as db:
        admin = db.get(Admin, 1)
        assert admin.password_hash != installation["password"]
        assert admin.totp_encrypted != body["manual_key"]
        assert not set(codes) & set(admin.recovery_hashes)
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "admin.web-setup"))
    credentials = {k: installation[k] for k in ("email", "password")}
    assert (
        client.post("/api/v1/auth/login", json={**credentials, "code": payload["code"]}).status_code
        == 200
    )


def test_setup_requires_owner_token_and_same_origin(client, installation):
    assert (
        client.post(
            "/api/v1/setup/start", json=installation, headers={"origin": "https://evil.test"}
        ).status_code
        == 403
    )
    assert (
        client.post("/api/v1/setup/start", json={**installation, "token": "x" * 43}).status_code
        == 403
    )
    get_settings().setup_token_file.unlink()
    assert client.get("/api/v1/setup/status").json() == {"available": False}
    assert client.post("/api/v1/setup/start", json=installation).status_code == 403


@pytest.mark.parametrize("invalid", ["expired", "tampered", "rotated", "code"])
def test_setup_rejects_invalid_completion_without_creating_admin(client, installation, invalid):
    body, data = begin(client, installation)
    payload = completion(installation, body, data)
    if invalid == "expired":
        payload["ticket"] = (
            get_settings()
            .cipher()
            .encrypt_at_time(json.dumps(data).encode(), int(time.time()) - 601)
            .decode()
        )
    elif invalid == "tampered":
        payload["ticket"] = "invalid"
    elif invalid == "rotated":
        token = secrets.token_urlsafe(32)
        get_settings().setup_token_file.write_text(token)
        payload["token"] = token
    else:
        totp = pyotp.TOTP(data["secret"])
        valid = {totp.at(time.time() + offset) for offset in (-30, 0, 30)}
        payload["code"] = next(f"{n:06d}" for n in range(10) if f"{n:06d}" not in valid)
    assert client.post("/api/v1/setup/finish", json=payload).status_code == 400
    with session_factory()() as db:
        assert db.get(Admin, 1) is None


def test_existing_cli_admin_disables_setup(client, account, installation):
    assert client.get("/api/v1/setup/status").json() == {"available": False}
    assert client.post("/api/v1/setup/start", json=installation).status_code == 409


def test_setup_requires_matching_access_identity(client, installation):
    client.app.dependency_overrides[access_identity] = lambda: "different@example.test"
    assert client.post("/api/v1/setup/start", json=installation).status_code == 403
    client.app.dependency_overrides.clear()
    body, data = begin(client, installation)
    client.app.dependency_overrides[access_identity] = lambda: "different@example.test"
    assert (
        client.post("/api/v1/setup/finish", json=completion(installation, body, data)).status_code
        == 403
    )


def test_setup_production_requires_access_jwt(client, installation, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "cf_team_domain", "https://test.cloudflareaccess.com")
    client.app.state.access_verifier = AccessVerifier(settings)
    assert client.get("/api/v1/setup/status").status_code == 403
    assert client.post("/api/v1/setup/start", json=installation).status_code == 403


def test_setup_limits_bad_tokens(client, installation):
    for _ in range(10):
        assert (
            client.post("/api/v1/setup/start", json={**installation, "token": "x" * 43}).status_code
            == 403
        )
    assert client.post("/api/v1/setup/start", json=installation).status_code == 429


def test_concurrent_setup_completions_create_only_one_administrator(client, installation):
    first, first_data = begin(client, installation)
    second, second_data = begin(client, {**installation, "email": "second@example.test"})
    payloads = [
        completion(installation, first, first_data),
        completion(installation, second, second_data),
    ]

    def finish(payload):
        return client.post("/api/v1/setup/finish", json=payload).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(finish, payloads)) == [201, 409]
    with session_factory()() as db:
        assert len(db.scalars(select(Admin)).all()) == 1
        assert (
            len(db.scalars(select(AuditEvent).where(AuditEvent.action == "admin.web-setup")).all())
            == 1
        )
