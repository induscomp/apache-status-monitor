import os
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SMON_", extra="ignore")

    environment: Literal["production", "development", "testing"] = "production"
    public_origin: str = "https://monitor.example.com"
    database_url: str | None = Field(default=None, repr=False)
    database_host: str = "postgres"
    database_name: str = "smon"
    database_user: str = "smon"
    database_password_file: Path = Path("/run/secrets/db_password")
    encryption_key_file: Path = Path("/run/secrets/encryption_key")
    setup_token_file: Path = Path("/run/secrets/setup_token")
    cf_team_domain: str = ""
    cf_audience: str = ""
    allowed_monitor_origins: list[str] = []
    allowed_http_origins: list[str] = []
    session_hours: int = Field(default=8, ge=1, le=24)

    @model_validator(mode="after")
    def validate_boundaries(self):
        origin = urlsplit(self.public_origin)
        if origin.scheme not in {"http", "https"} or not origin.hostname:
            raise ValueError("SMON_PUBLIC_ORIGIN must be an absolute HTTP(S) origin")
        if origin.path or origin.query or origin.fragment or origin.username or origin.password:
            raise ValueError("SMON_PUBLIC_ORIGIN must contain only scheme and authority")
        if self.environment == "production":
            if origin.scheme != "https" or not self.cf_audience:
                raise ValueError("Production requires HTTPS and Cloudflare Access audience")
            team = urlsplit(self.cf_team_domain)
            if (
                team.scheme != "https"
                or not team.hostname
                or not team.hostname.endswith(".cloudflareaccess.com")
                or team.path
                or team.query
                or team.fragment
                or team.username
                or team.port
            ):
                raise ValueError("Invalid Cloudflare Access team origin")
        elif origin.hostname not in {"localhost", "127.0.0.1", "testserver"}:
            raise ValueError("Development/testing is restricted to a loopback origin")
        from app.connectors.policy import canonical_origin

        self.allowed_monitor_origins = [canonical_origin(x) for x in self.allowed_monitor_origins]
        self.allowed_http_origins = [canonical_origin(x) for x in self.allowed_http_origins]
        if not set(self.allowed_http_origins) <= set(self.allowed_monitor_origins):
            raise ValueError("HTTP exceptions must also be allowed monitor origins")
        return self

    @property
    def secure_cookie(self) -> bool:
        return self.public_origin.startswith("https://")

    @property
    def cookie_name(self) -> str:
        return "__Host-smon" if self.secure_cookie else "smon_dev"

    def cipher(self) -> Fernet:
        return Fernet(self.encryption_key_file.read_bytes().strip())

    def db_url(self) -> str | URL:
        if self.database_url:
            if not self.database_url.startswith("postgresql+psycopg://"):
                raise ValueError("Only PostgreSQL with psycopg is supported")
            return self.database_url
        return URL.create(
            "postgresql+psycopg",
            username=self.database_user,
            password=self.database_password_file.read_text().strip(),
            host=self.database_host,
            database=self.database_name,
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()


def require_local_terminal() -> None:
    if not os.isatty(0) or not os.isatty(1):
        raise SystemExit("Use an interactive terminal: docker compose run --rm backend ...")
