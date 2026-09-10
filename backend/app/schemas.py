from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

Name = Annotated[str, Field(min_length=1, max_length=100, pattern=r"\S")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Login(StrictModel):
    email: str = Field(min_length=3, max_length=254)
    password: SecretStr = Field(min_length=1, max_length=1024)
    code: SecretStr = Field(min_length=6, max_length=64)

    @field_validator("email")
    @classmethod
    def lower_email(cls, value):
        return value.lower()


class ServerInput(StrictModel):
    name: Name
    description: str = Field(default="", max_length=1000)
    tags: list[Annotated[str, Field(min_length=1, max_length=30)]] = Field(
        default=[], max_length=10
    )


class ServerUpdate(ServerInput):
    archived: bool = False


class Credentials(StrictModel):
    username: str = Field(min_length=1, max_length=200)
    password: SecretStr = Field(min_length=1, max_length=1024)


class ServiceOptions(StrictModel):
    # Selected connector options, never arbitrary headers or proxy configuration.
    apache_auto: bool = True


class ServiceInput(StrictModel):
    name: Name
    kind: Literal["apache_status", "mrtg"]
    url: str = Field(min_length=1, max_length=2048)
    interval_seconds: int = Field(default=300, ge=60, le=86400)
    enabled: bool = True
    options: ServiceOptions = ServiceOptions()
    credentials: Credentials | None = None


class ServiceUpdate(StrictModel):
    name: Name
    url: str = Field(min_length=1, max_length=2048)
    interval_seconds: int = Field(default=300, ge=60, le=86400)
    enabled: bool = True
    archived: bool = False
    options: ServiceOptions = ServiceOptions()
    credentials: Credentials | None = None
    clear_credentials: bool = False
