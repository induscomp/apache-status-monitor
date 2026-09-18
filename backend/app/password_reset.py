"""Password recovery requires Access identity plus the existing local second factor."""

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import Field, SecretStr
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import Admin, AuditEvent, AuthSession
from app.schemas import StrictModel
from app.security import PASSWORDS, access_identity, consume_second_factor, locked_admin, rate_limit

router = APIRouter(prefix="/auth/password-reset")


class PasswordReset(StrictModel):
    password: SecretStr = Field(min_length=14, max_length=1024)
    code: SecretStr = Field(min_length=6, max_length=64)


@router.get("")
def availability(identity=Depends(access_identity), db: Session = Depends(get_db)):
    # Development deliberately has no independent, verified identity proof.
    admin = db.scalar(select(Admin).where(Admin.email == identity)) if identity else None
    return {"available": admin is not None}


@router.post("", status_code=204)
def reset_password(
    payload: PasswordReset,
    response: Response,
    identity=Depends(access_identity),
    db: Session = Depends(get_db),
):
    if not identity:
        raise HTTPException(
            403, "La recuperación web requiere una identidad verificada por Cloudflare Access."
        )
    rate_limit("password-reset-global", 20, 300)
    rate_limit("password-reset:" + identity, 5, 300)
    admin = locked_admin(db, identity)
    settings = get_settings()
    if not admin or not consume_second_factor(admin, payload.code.get_secret_value(), settings):
        raise HTTPException(
            403,
            "No se pudo verificar la recuperación. Comprueba tu cuenta de Access y el código del monitor.",
        )
    admin.password_hash = PASSWORDS.hash(payload.password.get_secret_value())
    db.execute(delete(AuthSession).where(AuthSession.admin_id == admin.id))
    db.add(AuditEvent(action="auth.password_reset", target_id=str(admin.id)))
    db.commit()
    response.delete_cookie(
        settings.cookie_name,
        path="/",
        secure=settings.secure_cookie,
        httponly=True,
        samesite="strict",
    )
