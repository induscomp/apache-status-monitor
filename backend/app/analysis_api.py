import json
import re
from datetime import timedelta
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field, SecretStr, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis import correlate
from app.config import get_settings
from app.db import get_db
from app.evidence import domain_evidence
from app.geo import availability, enrich
from app.incident_summary import summarize
from app.models import (
    AnomalyState,
    ComponentHeartbeat,
    EmailDelivery,
    Incident,
    NotificationConfig,
    Server,
    ServerFrame,
    Service,
    now,
)
from app.notifications import configuration
from app.presentation import ResourcePresentation
from app.schemas import StrictModel
from app.security import authenticated, rate_limit
from app.workspace_api import mrtg_only_series, source_summary

router = APIRouter()


def backup_status(db):
    heartbeat = db.get(ComponentHeartbeat, "backup")
    return {
        "state": "ok"
        if heartbeat and now() - heartbeat.seen_at < timedelta(hours=26)
        else "missing",
        "last_at": heartbeat.seen_at if heartbeat else None,
    }


def incident_progress(db, incident):
    state = db.scalar(select(AnomalyState).where(AnomalyState.incident_id == incident.id))
    phase = "resolved" if incident.status == "resolved" else "awaiting"
    if incident.status == "open" and state and now() - state.last_at < timedelta(minutes=10):
        phase = "recovering" if state.good else "anomalous" if state.bad else "awaiting"
    return {
        "phase": phase,
        "recovery_samples": state.good if state else 0,
        "required_recovery_samples": 3,
        "last_evaluated_at": incident.resolved_at
        if incident.status == "resolved"
        else state.last_at
        if state
        else None,
    }


@router.get("/servers/{server_id}/analysis")
def server_state(
    server_id: UUID,
    service_id: UUID | None = None,
    hours: int = Query(24, ge=1, le=72),
    domain: str | None = Query(None, max_length=254),
    auth=Depends(authenticated),
    db: Session = Depends(get_db),
):
    server = db.get(Server, str(server_id))
    if not server:
        raise HTTPException(404, "Servidor no encontrado.")
    services = db.scalars(
        select(Service)
        .where(Service.server_id == server.id, Service.kind == "apache_status")
        .order_by(Service.created_at)
    ).all()
    chosen = (
        next((s for s in services if s.id == str(service_id)), None)
        if service_id
        else next((s for s in services if s.enabled and not s.archived), next(iter(services), None))
    )
    if service_id and chosen is None:
        raise HTTPException(404, "Servicio Apache no encontrado en este servidor.")
    frames = (
        db.scalars(
            select(ServerFrame)
            .where(
                ServerFrame.service_id == chosen.id,
                ServerFrame.observed_at >= now() - timedelta(hours=hours),
            )
            .order_by(ServerFrame.observed_at)
            .limit(1000)
        ).all()
        if chosen
        else []
    )
    last = frames[-1] if frames else None
    all_sources = db.scalars(
        select(Service).where(Service.server_id == server.id).order_by(Service.created_at)
    ).all()
    independent_resources, independent_warnings = (
        correlate(db, server.id, now()) if not chosen else ({}, [])
    )
    incidents = db.scalars(
        select(Incident)
        .where(Incident.server_id == server.id, Incident.status == "open")
        .order_by(Incident.updated_at.desc())
    ).all()
    quality_count = len(
        {
            int(f.observed_at.timestamp()) // 300
            for f in frames
            if f.valid
            and last
            and f.revision == last.revision
            and last.observed_at - timedelta(hours=24)
            <= f.observed_at
            <= last.observed_at - timedelta(minutes=30)
        }
    )
    state = "learning"
    if not last or now() - last.observed_at > timedelta(minutes=10):
        state = "insufficient"
    elif any(i.kind == "resources" for i in incidents):
        state = "resource_pressure"
    elif incidents:
        state = "anomaly"
    elif not last.valid or not {"ram_free", "swap_free", "load"} <= set(last.resources):
        state = "insufficient"
    elif quality_count >= 170:
        state = "observing"
    if chosen is None:
        state = "sources_only" if all_sources else "unconfigured"
    presentation = ResourcePresentation(db)
    series = []
    previous = None
    previous_basis = None
    totals = {}
    for frame in frames:
        if frame.valid:
            for name, counts in frame.domains.items():
                totals[name] = totals.get(name, 0) + counts.get("appearances", 0)
        basis = (frame.revision, sorted((k, v["basis"]) for k, v in frame.resources.items()))
        if previous and previous_basis != basis:
            series.append({"at": (frame.observed_at - timedelta(seconds=1)).isoformat()})
        previous_basis = basis
        if previous and frame.observed_at - previous > timedelta(minutes=10):
            series.append({"at": (previous + timedelta(minutes=5)).isoformat()})
        series.append(
            {
                "at": frame.observed_at.isoformat(),
                **(frame.metrics if frame.valid else {}),
                **(
                    {
                        "domain_active": frame.domains.get(domain, {}).get("active", 0),
                        "domain_appearances": frame.domains.get(domain, {}).get("appearances", 0),
                    }
                    if domain and frame.valid
                    else {}
                ),
                **{
                    key: value.get("display_bytes")
                    if key in {"ram_free", "swap_free"}
                    else value["value"]
                    for key, value in presentation.resources(frame.resources).items()
                },
            }
        )
        previous = frame.observed_at
    return {
        "state": state,
        "server": server.name,
        "sources": [source_summary(db, s, server.archived) for s in all_sources],
        "has_apache": chosen is not None,
        "services": [{"id": s.id, "name": s.name} for s in services],
        "service_id": chosen.id if chosen else None,
        "last_at": last.observed_at if last else None,
        "learning": {
            "valid_baseline_samples": quality_count,
            "required_samples": 170,
            "window_hours": 24,
            "excluded_recent_minutes": 30,
        },
        "series": series if chosen else mrtg_only_series(db, server.id, hours),
        "resources": presentation.resources(last.resources if last else independent_resources),
        "metrics": last.metrics if last else {},
        "period_rankings": [
            {"domain": d, "appearances": n}
            for d, n in sorted(totals.items(), key=lambda item: item[1], reverse=True)[:100]
        ],
        "domains": sorted(
            [dict(domain=d, **v) for d, v in (last.domains if last else {}).items()],
            key=lambda v: v["active"],
            reverse=True,
        )[:100],
        "rankings": enrich(last.details or {})
        if last and last.observed_at >= now() - timedelta(days=30)
        else {},
        "warnings": last.warnings
        if last
        else independent_warnings
        + ["Sin muestras Apache comparables. Solo se muestran las fuentes configuradas."],
        "open_incidents": len(incidents),
        "open_subjects": [i.subject for i in incidents],
        "incident_summary": summarize(db, server.id),
        "backup": backup_status(db),
        "geoip": availability(),
        "limitation": "Slots libres no prueban salud. Apache Status y MRTG no confirman errores HTTP 500 ni visitas totales por dominio. GoAccess refleja únicamente el periodo y la fecha de su informe.",
    }


@router.get("/servers/{server_id}/incidents")
def incident_list(
    server_id: UUID,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    auth=Depends(authenticated),
    db: Session = Depends(get_db),
):
    rows = db.scalars(
        select(Incident)
        .where(Incident.server_id == str(server_id))
        .order_by(Incident.opened_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    presentation = ResourcePresentation(db)
    return {
        "items": [
            {
                "id": i.id,
                "service_id": i.service_id,
                "subject": i.subject,
                "kind": i.kind,
                "status": i.status,
                "severity": i.severity,
                "opened_at": i.opened_at,
                "updated_at": i.updated_at,
                "resolved_at": i.resolved_at,
                "progress": incident_progress(db, i),
                "evidence": {
                    **i.evidence,
                    "resources": presentation.resources(i.evidence.get("resources", {})),
                    "coincidences": enrich(
                        domain_evidence(
                            db,
                            db.get(ServerFrame, i.evidence.get("frame_id")),
                            i.subject.removeprefix("domain:"),
                        )
                        if i.kind == "domain" and i.evidence.get("frame_id")
                        else (
                            i.evidence.get("coincidences", {})
                            if i.kind != "domain"
                            else {"scope": "unavailable"}
                        )
                    )
                    if i.updated_at >= now() - timedelta(days=30)
                    else {},
                },
            }
            for i in rows
        ]
    }


class MailSettings(StrictModel):
    security: Literal["tls", "starttls"] = "tls"
    enabled: bool = False
    host: str = Field(default="", max_length=253, pattern=r"^[a-zA-Z0-9.-]*$")
    port: int = Field(default=465, ge=1, le=65535)
    username: str = Field(default="", max_length=254)
    password: SecretStr | None = Field(default=None, max_length=1024)
    sender: str = Field(default="", max_length=254)
    recipient: str = Field(default="", max_length=254)

    @model_validator(mode="after")
    def validate_delivery(self):
        for value in (self.sender, self.recipient):
            if value and not re.fullmatch(r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+", value):
                raise ValueError("Email no válido")
        if self.enabled and not all((self.host, self.sender, self.recipient)):
            raise ValueError("Configura servidor SMTP y direcciones antes de activar el correo")
        return self


@router.get("/notifications")
def mail_settings(auth=Depends(authenticated), db: Session = Depends(get_db)):
    config = configuration(db)
    return {
        **{k: v for k, v in config.items() if k != "password"},
        "has_password": bool(config.get("password")),
        "deliveries": [
            {
                "status": d.status,
                "transition": d.transition,
                "created_at": d.created_at,
                "error": d.error,
            }
            for d in db.scalars(
                select(EmailDelivery).order_by(EmailDelivery.created_at.desc()).limit(20)
            )
        ],
    }


@router.put("/notifications")
def update_mail(payload: MailSettings, auth=Depends(authenticated), db: Session = Depends(get_db)):
    rate_limit("mail-settings", 10, 300)
    old = configuration(db)
    config = payload.model_dump(exclude={"password"})
    password = payload.password.get_secret_value() if payload.password else ""
    if (
        old.get("password")
        and (old.get("host"), old.get("port"), old.get("username"))
        != (config["host"], config["port"], config["username"])
        and not password
    ):
        raise HTTPException(
            422, "Al cambiar servidor o usuario SMTP, vuelve a introducir la contraseña."
        )
    config["password"] = password or old.get("password", "")
    encrypted = get_settings().cipher().encrypt(json.dumps(config).encode()).decode()
    item = db.get(NotificationConfig, 1)
    if item:
        item.encrypted = encrypted
    else:
        db.add(NotificationConfig(id=1, encrypted=encrypted))
    from app.models import AuditEvent

    db.add(AuditEvent(action="notifications.update", target_id="1"))
    db.commit()
    return {"saved": True, "enabled": config["enabled"]}
