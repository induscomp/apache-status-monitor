import hashlib
import hmac
import json
import secrets
import time
from datetime import timedelta
from urllib.error import URLError

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import get_db, session_factory
from app.models import Admin, AuthSession, RateBucket, now

PASSWORDS = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
DUMMY_HASH = PASSWORDS.hash(secrets.token_urlsafe(32))


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def password_valid(encoded: str, password: str) -> bool:
    try:
        return PASSWORDS.verify(encoded, password)
    except VerificationError:
        return False


def rate_limit(scope: str, maximum: int, period: int) -> None:
    # Separate committed transaction: a failed login must not roll back its limit.
    window = int(time.time()) // period * period
    with session_factory()() as db:
        statement = insert(RateBucket).values(key=digest(scope), window=window, count=1)
        statement = statement.on_conflict_do_update(
            index_elements=[RateBucket.key, RateBucket.window],
            set_={"count": RateBucket.count + 1},
        ).returning(RateBucket.count)
        count = db.scalar(statement)
        db.commit()
    if count > maximum:
        raise HTTPException(
            429,
            "Demasiados intentos. Espera antes de volver a intentarlo.",
            headers={"Retry-After": str(period)},
        )


class AccessVerifier:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.client = jwt.PyJWKClient(
            f"{settings.cf_team_domain}/cdn-cgi/access/certs",
            timeout=5,
            lifespan=300,
            cache_jwk_set=True,
        )

    def verify(self, token: str) -> dict:
        if not token or len(token) > 8192:
            raise HTTPException(403, "Se requiere Cloudflare Access.")
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256":
                raise ValueError("Unexpected algorithm")
            # Unknown kid does not force a new network request on every attacker input.
            keys = self.client.get_jwk_set().keys
            key = next(k for k in keys if k.key_id == header.get("kid"))
            return jwt.decode(
                token,
                key.key,
                algorithms=["RS256"],
                audience=self.settings.cf_audience,
                issuer=self.settings.cf_team_domain,
                options={"require": ["exp", "iat", "sub", "email", "aud", "iss"]},
                leeway=10,
            )
        except jwt.PyJWTError, URLError, ValueError, StopIteration:
            raise HTTPException(403, "Cloudflare Access no válido o no disponible.") from None


def access_identity(request: Request) -> str | None:
    settings = get_settings()
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        if request.headers.get("origin") != settings.public_origin:
            raise HTTPException(403, "Origen de la solicitud no permitido.")
    if settings.environment != "production":
        return None
    claims = request.app.state.access_verifier.verify(
        request.headers.get("cf-access-jwt-assertion", "")
    )
    email = claims.get("email")
    if not isinstance(email, str) or len(email) > 254:
        raise HTTPException(403, "Identidad de Access no válida.")
    return email.lower()


def authenticated(
    request: Request,
    db: Session = Depends(get_db),
    identity=Depends(access_identity),
) -> tuple[Admin, AuthSession]:
    token = request.cookies.get(get_settings().cookie_name, "")
    session = db.get(AuthSession, digest(token)) if len(token) <= 128 and token else None
    if not session or session.expires_at <= now():
        raise HTTPException(401, "Inicia sesión para continuar.")
    admin = db.get(Admin, session.admin_id)
    if not admin or (identity is not None and identity != admin.email):
        raise HTTPException(403, "La identidad de Access no coincide con la cuenta local.")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), session.csrf_token):
            raise HTTPException(403, "Token CSRF no válido.")
    return admin, session


def consume_second_factor(admin: Admin, code: str, settings: Settings) -> bool:
    # Caller holds FOR UPDATE on admin. Recovery codes and TOTP cannot be replayed.
    if not code.isascii():
        return False
    code_hash = digest(code)
    if any(hmac.compare_digest(code_hash, item) for item in admin.recovery_hashes):
        admin.recovery_hashes = [x for x in admin.recovery_hashes if x != code_hash]
        return True
    secret = settings.cipher().decrypt(admin.totp_encrypted.encode()).decode()
    totp = pyotp.TOTP(secret)
    step = int(time.time()) // 30
    for candidate in (step, step - 1, step + 1):
        if candidate > admin.last_totp_step and hmac.compare_digest(totp.at(candidate * 30), code):
            admin.last_totp_step = candidate
            return True
    return False


def new_session(admin: Admin, settings: Settings) -> tuple[str, AuthSession]:
    token = secrets.token_urlsafe(32)
    return token, AuthSession(
        token_hash=digest(token),
        admin_id=admin.id,
        csrf_token=secrets.token_urlsafe(32),
        expires_at=now() + timedelta(hours=settings.session_hours),
    )


def encrypt_credentials(credentials, settings: Settings) -> str:
    value = {"username": credentials.username, "password": credentials.password.get_secret_value()}
    return settings.cipher().encrypt(json.dumps(value).encode()).decode()


def locked_admin(db: Session, email: str) -> Admin | None:
    return db.scalar(select(Admin).where(Admin.email == email).with_for_update())
