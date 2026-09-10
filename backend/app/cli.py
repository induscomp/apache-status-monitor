import argparse
import getpass
import re
import secrets

import pyotp
from sqlalchemy import delete, select

from app.config import get_settings, require_local_terminal
from app.db import session_factory
from app.models import Admin, AuditEvent, AuthSession
from app.security import PASSWORDS, digest, password_valid


def enrol_totp(email: str) -> tuple[str, list[str]]:
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    print("Añade esta clave en tu aplicación autenticadora (no la compartas):")
    print(secret)
    print(totp.provisioning_uri(name=email, issuer_name="Apache Status Monitor"))
    if not totp.verify(getpass.getpass("Código actual de seis dígitos: ").strip(), valid_window=1):
        raise SystemExit("Código incorrecto. No se ha guardado ningún cambio.")
    recovery = [secrets.token_hex(12) for _ in range(8)]
    encrypted = get_settings().cipher().encrypt(secret.encode()).decode()
    return encrypted, recovery


def read_password() -> str:
    password = getpass.getpass("Contraseña nueva (mínimo 14 caracteres): ")
    if len(password) < 14 or len(password) > 1024:
        raise SystemExit("La contraseña debe tener entre 14 y 1024 caracteres.")
    if password != getpass.getpass("Repite la contraseña: "):
        raise SystemExit("Las contraseñas no coinciden.")
    return password


def main():
    parser = argparse.ArgumentParser(
        description="Administración local; requiere terminal interactivo"
    )
    parser.add_argument("command", choices=["create-admin", "reset-mfa", "change-password"])
    args = parser.parse_args()
    require_local_terminal()
    with session_factory()() as db:
        # The singleton row constraint also prevents concurrent bootstrap races.
        admin = db.scalar(select(Admin).with_for_update())
        if args.command == "create-admin":
            if admin:
                raise SystemExit("Ya existe un administrador.")
            email = input("Email (debe coincidir con Cloudflare Access): ").strip().lower()
            if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                raise SystemExit("Email no válido.")
            password = read_password()
            encrypted, recovery = enrol_totp(email)
            admin = Admin(
                id=1,
                email=email,
                password_hash=PASSWORDS.hash(password),
                totp_encrypted=encrypted,
                recovery_hashes=[digest(x) for x in recovery],
            )
            db.add(admin)
        else:
            if not admin or not password_valid(
                admin.password_hash, getpass.getpass("Contraseña actual: ")
            ):
                raise SystemExit("Credenciales no válidas.")
            recovery = []
            if args.command == "reset-mfa":
                encrypted, recovery = enrol_totp(admin.email)
                admin.totp_encrypted = encrypted
                admin.recovery_hashes = [digest(x) for x in recovery]
                admin.last_totp_step = -1
            else:
                admin.password_hash = PASSWORDS.hash(read_password())
            db.execute(delete(AuthSession).where(AuthSession.admin_id == admin.id))
        db.add(AuditEvent(action=f"admin.{args.command}", target_id="1"))
        db.commit()
    if recovery:
        print("Códigos de recuperación de un solo uso. Guárdalos en tu gestor de contraseñas:")
        print("\n".join(recovery))
    print("Operación completada.")


if __name__ == "__main__":
    main()
