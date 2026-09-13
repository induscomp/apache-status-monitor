from datetime import timedelta
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session, defer

from app.db import get_db
from app.models import AuditEvent, MrtgDiscovery, MrtgMetric, MrtgObservation, Service, now
from app.mrtg_collection import latest_metric
from app.schemas import StrictModel
from app.security import authenticated, rate_limit

router = APIRouter()


class MetricConfig(StrictModel):
    selected: bool
    verified: bool = False
    unit: str = Field(default="", max_length=40)
    factor: float = Field(default=1, gt=0, le=1e12, allow_inf_nan=False)
    capacity: float | None = Field(default=None, gt=0, allow_inf_nan=False)
    timezone: str | None = Field(default=None, max_length=80)

    @field_validator("timezone")
    @classmethod
    def timezone_exists(cls, value):
        if value:
            try:
                ZoneInfo(value)
            except ZoneInfoNotFoundError, ValueError:
                raise ValueError("Zona horaria IANA no válida") from None
        return value or None

    @model_validator(mode="after")
    def require_unit(self):
        if self.verified and not self.unit:
            raise ValueError("Especifica una unidad para confirmar la interpretación")
        if self.capacity is not None and not self.verified:
            raise ValueError("Confirma la unidad antes de configurar la capacidad total")
        return self


def sample_result(item):
    return {
        "id": item.id,
        "metric_id": item.metric_id,
        "service_id": item.service_id,
        "revision": item.revision,
        "metric_revision": item.metric_revision,
        "configuration": item.configuration,
        "observed_at": item.observed_at,
        "source_at": item.source_at,
        "source_time_text": item.source_time_text,
        "status": item.status,
        "values": item.values,
        "warnings": item.warnings,
    }


@router.get("/services/{service_id}/mrtg")
def metrics(service_id: UUID, auth=Depends(authenticated), db: Session = Depends(get_db)):
    service = db.get(Service, str(service_id))
    if not service or service.kind != "mrtg":
        raise HTTPException(404, "Servicio MRTG no encontrado.")
    discovery = db.get(MrtgDiscovery, service.id)
    items = db.scalars(
        select(MrtgMetric)
        .where(MrtgMetric.service_id == service.id)
        .order_by(MrtgMetric.present.desc(), MrtgMetric.name)
        .limit(500)
    ).all()
    return {
        "discovery": {
            "attempted_at": discovery.attempted_at,
            "succeeded_at": discovery.succeeded_at,
            "requested": discovery.requested,
            "error": discovery.error,
        }
        if discovery
        else None,
        "items": [
            {
                "id": m.id,
                "name": m.name,
                "url": m.url,
                "selected": m.selected,
                "present": m.present,
                "revision": m.revision,
                "configuration": m.configuration,
                "latest": sample_result(last)
                if (last := latest_metric(db, m.id))
                and last.observed_at >= now() - timedelta(days=90)
                else None,
            }
            for m in items
        ],
    }


@router.post("/services/{service_id}/mrtg/discover", status_code=202)
def rediscover(service_id: UUID, auth=Depends(authenticated), db: Session = Depends(get_db)):
    rate_limit("mrtg-rediscovery", 5, 300)
    service = db.scalar(select(Service).where(Service.id == str(service_id)).with_for_update())
    if not service or service.kind != "mrtg":
        raise HTTPException(404, "Servicio MRTG no encontrado.")
    state = db.get(MrtgDiscovery, service.id)
    if state:
        state.requested = True
    else:
        db.add(MrtgDiscovery(service_id=service.id, requested=True))
    db.add(AuditEvent(action="mrtg.discovery-request", target_id=service.id))
    db.commit()
    return {"queued": True}


@router.put("/mrtg/metrics/{metric_id}")
def configure(
    metric_id: UUID,
    payload: MetricConfig,
    auth=Depends(authenticated),
    db: Session = Depends(get_db),
):
    metric = db.scalar(select(MrtgMetric).where(MrtgMetric.id == str(metric_id)).with_for_update())
    if not metric:
        raise HTTPException(404, "Métrica no encontrada.")
    metric.selected = payload.selected
    metric.configuration = payload.model_dump(exclude={"selected"})
    metric.revision += 1
    db.add(AuditEvent(action="mrtg.metric-update", target_id=metric.id))
    db.commit()
    return {"revision": metric.revision}


@router.get("/mrtg/metrics/{metric_id}/observations")
def history(
    metric_id: UUID,
    auth=Depends(authenticated),
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    items = db.scalars(
        select(MrtgObservation)
        .options(defer(MrtgObservation.raw_encrypted))
        .where(
            MrtgObservation.metric_id == str(metric_id),
            MrtgObservation.observed_at >= now() - timedelta(days=90),
        )
        .order_by(MrtgObservation.observed_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return {"items": [sample_result(item) for item in items]}
