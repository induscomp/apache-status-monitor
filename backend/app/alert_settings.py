"""Validated server-scoped sensitivity; memory severity remains evidence-based."""

import ipaddress

from pydantic import Field, field_validator

from app.schemas import StrictModel


class AlertSettings(StrictModel):
    domain_multiplier: float = Field(3, ge=1.1, le=100, allow_inf_nan=False)
    domain_min_increase: int = Field(5, ge=1, le=10000)
    memory_drop_percent: float = Field(50, ge=1, le=99, allow_inf_nan=False)
    resource_multiplier: float = Field(2, ge=1.1, le=100, allow_inf_nan=False)
    open_samples: int = Field(2, ge=2, le=12)
    recovery_samples: int = Field(3, ge=2, le=12)
    multidomain_min_domains: int = Field(3, ge=3, le=100)
    multidomain_trusted_ips: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("multidomain_trusted_ips")
    @classmethod
    def validate_trusted(cls, values):
        return sorted({str(ipaddress.ip_network(value.strip(), strict=False)) for value in values})


def settings_for(server):
    return AlertSettings.model_validate(
        {k: v for k, v in (server.alert_settings or {}).items() if k != "revision"}
    ).model_dump()
