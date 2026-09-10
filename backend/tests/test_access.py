import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from app.config import Settings, get_settings
from app.security import AccessVerifier


@pytest.fixture
def access_keys(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    public["kid"] = "fixture-key"
    settings = Settings(
        environment="production",
        public_origin="https://monitor.example.test",
        cf_team_domain="https://team.cloudflareaccess.com",
        cf_audience="aud-test",
    )
    verifier = AccessVerifier(settings)
    monkeypatch.setattr(
        verifier.client, "get_jwk_set", lambda: jwt.PyJWKSet.from_dict({"keys": [public]})
    )
    claims = {
        "sub": "test-user",
        "email": "admin@example.test",
        "iat": int(time.time()),
        "exp": int(time.time()) + 60,
        "aud": settings.cf_audience,
        "iss": settings.cf_team_domain,
    }
    return key, verifier, claims, settings


@pytest.mark.parametrize(
    "change",
    [
        {"aud": "different-app"},
        {"iss": "https://other.cloudflareaccess.com"},
        {"exp": 1},
        {"iat": int(time.time()) + 3600},
    ],
)
def test_invalid_access_claims_rejected(access_keys, change):
    key, verifier, claims, _ = access_keys
    token = jwt.encode({**claims, **change}, key, algorithm="RS256", headers={"kid": "fixture-key"})
    with pytest.raises(HTTPException) as error:
        verifier.verify(token)
    assert error.value.status_code == 403


def test_valid_access_and_unknown_key(access_keys):
    key, verifier, claims, _ = access_keys
    token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "fixture-key"})
    assert verifier.verify(token)["email"] == "admin@example.test"
    for token in (
        "",
        "not-a-jwt",
        jwt.encode(claims, key, algorithm="RS256", headers={"kid": "unknown"}),
    ):
        with pytest.raises(HTTPException):
            verifier.verify(token)


def test_access_cannot_replace_local_auth_or_use_another_identity(
    logged_in, access_keys, monkeypatch
):
    import app.security as security

    key, verifier, claims, settings = access_keys
    # Exercise the production Access dependency using the existing local session cookie.
    settings.public_origin = get_settings().public_origin
    monkeypatch.setattr(security, "get_settings", lambda: settings)
    logged_in.app.state.access_verifier = verifier
    assert logged_in.get("/api/v1/servers").status_code == 403
    token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "fixture-key"})
    assert (
        logged_in.get("/api/v1/servers", headers={"cf-access-jwt-assertion": token}).status_code
        == 200
    )
    token = jwt.encode(
        {**claims, "email": "other@example.test"},
        key,
        algorithm="RS256",
        headers={"kid": "fixture-key"},
    )
    assert (
        logged_in.get("/api/v1/servers", headers={"cf-access-jwt-assertion": token}).status_code
        == 403
    )


def test_production_fails_closed_without_access_configuration():
    with pytest.raises(ValueError):
        Settings(
            environment="production", public_origin="https://monitor.example.test", cf_audience=""
        )
    with pytest.raises(ValueError):
        Settings(environment="development", public_origin="https://public.example.test")
