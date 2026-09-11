#!/usr/bin/env python3
"""Create local secrets without overwriting existing keys or printing their contents."""
import base64
import os
from pathlib import Path
import secrets

root = Path(__file__).resolve().parents[1] / "secrets"
root.mkdir(mode=0o700, exist_ok=True)
for name, value in {
    "db_owner_password": secrets.token_urlsafe(40),
    "db_password": secrets.token_urlsafe(40),
    "setup_token": secrets.token_urlsafe(32),
    "encryption_key": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
}.items():
    try:
        descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        print(f"Conservado: secrets/{name}")
        continue
    with os.fdopen(descriptor, "w") as output:
        output.write(value + "\n")
    print(f"Creado: secrets/{name} (0600)")
