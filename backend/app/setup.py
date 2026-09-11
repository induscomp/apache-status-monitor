"""Owner-authorized first installation; never a public registration endpoint."""

import base64
import hmac
import io
import json
import secrets

import pyotp
import segno
from cryptography.fernet import InvalidToken
from fastapi import APIRouter, Depends, HTTPException
from pydantic import Field, SecretStr, field_validator
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import Admin, AuditEvent
from app.schemas import StrictModel
from app.security import PASSWORDS, access_identity, digest, rate_limit

router = APIRouter(prefix="/setup", dependencies=[Depends(access_identity)])


class SetupStart(StrictModel):
    token: SecretStr = Field(min_length=32, max_length=128)
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    password: SecretStr = Field(min_length=14, max_length=1024)

    @field_validator("email")
    @classmethod
    def lower_email(cls, value):
        return value.lower()


class SetupFinish(StrictModel):
    token: SecretStr = Field(min_length=32, max_length=128)
    ticket: SecretStr = Field(min_length=1, max_length=4096)
    code: str = Field(pattern=r"^[0-9]{6}$")


def installation_token() -> str:
    try:
        token = get_settings().setup_token_file.read_text().strip()
    except OSError:
        return ""
    return token if 32 <= len(token) <= 128 and token.isascii() else ""


def require_setup(db: Session, supplied: str) -> str:
    if db.scalar(select(Admin.id).limit(1)) is not None:
        raise HTTPException(409, "La instalación ya está completada. Inicia sesión.")
    expected = installation_token()
    if not expected or not hmac.compare_digest(digest(supplied), digest(expected)):
        raise HTTPException(403, "Clave de instalación no válida o asistente deshabilitado.")
    return digest(expected)


@router.get("/status")
def status(db: Session = Depends(get_db)):
    return {
        "available": db.scalar(select(Admin.id).limit(1)) is None and bool(installation_token())
    }


@router.post("/start")
def start(payload: SetupStart, db: Session = Depends(get_db), identity=Depends(access_identity)):
    rate_limit("setup-start", 10, 300)
    binding = require_setup(db, payload.token.get_secret_value())
    if identity is not None and identity != payload.email:
        raise HTTPException(403, "Usa el mismo email que en Cloudflare Access.")
    secret = pyotp.random_base32()
    settings = get_settings()
    # An authenticated encrypted ticket expires after ten minutes. No partial administrator,
    # password, pending secret or QR is persisted before the second factor is confirmed.
    ticket = (
        settings.cipher()
        .encrypt(
            json.dumps(
                {
                    "purpose": "initial-setup",
                    "binding": binding,
                    "email": payload.email,
                    "password_hash": PASSWORDS.hash(payload.password.get_secret_value()),
                    "secret": secret,
                }
            ).encode()
        )
        .decode()
    )
    png = io.BytesIO()
    segno.make_qr(
        pyotp.TOTP(secret).provisioning_uri(name=payload.email, issuer_name="Apache Status Monitor")
    ).save(png, kind="png", scale=5, border=4)
    return {
        "ticket": ticket,
        "qr": "data:image/png;base64," + base64.b64encode(png.getvalue()).decode(),
        "manual_key": secret,
        "expires_in": 600,
    }


@router.post("/finish", status_code=201)
def finish(payload: SetupFinish, db: Session = Depends(get_db), identity=Depends(access_identity)):
    rate_limit("setup-finish", 10, 300)
    # Serialize concurrent web completions. The singleton PK also excludes a concurrent CLI signup.
    db.execute(text("SELECT pg_advisory_xact_lock(72419001)"))
    binding = require_setup(db, payload.token.get_secret_value())
    settings = get_settings()
    try:
        data = json.loads(
            settings.cipher().decrypt(payload.ticket.get_secret_value().encode(), ttl=600)
        )
    except InvalidToken, ValueError, UnicodeError:
        raise HTTPException(
            400, "La configuración ha caducado o no es válida. Vuelve a empezar."
        ) from None
    if data.get("purpose") != "initial-setup" or data.get("binding") != binding:
        raise HTTPException(400, "La configuración no es válida. Vuelve a empezar.")
    if identity is not None and identity != data["email"]:
        raise HTTPException(403, "Usa el mismo email que en Cloudflare Access.")
    if not pyotp.TOTP(data["secret"]).verify(payload.code, valid_window=1):
        raise HTTPException(400, "Código incorrecto. Introduce el código actual del autenticador.")
    recovery = [secrets.token_hex(12) for _ in range(8)]
    db.add(
        Admin(
            id=1,
            email=data["email"],
            password_hash=data["password_hash"],
            totp_encrypted=settings.cipher().encrypt(data["secret"].encode()).decode(),
            recovery_hashes=[digest(code) for code in recovery],
        )
    )
    db.add(AuditEvent(action="admin.web-setup", target_id="1"))
    db.commit()
    return {"recovery_codes": recovery}
