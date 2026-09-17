import re
from datetime import datetime, timedelta
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field, SecretStr, model_validator
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.alert_settings import AlertSettings, settings_for
from app.analysis import correlate
from app.db import get_db
from app.evidence import domain_evidence
from app.geo import availability, enrich
from app.incident_summary import summarize
from app.models import (
    AnomalyState,
    AuditEvent,
    ComponentHeartbeat,
    EmailDelivery,
    Incident,
    Server,
    ServerFrame,
    Service,
    now,
)
from app.notifications import configuration, failure_message, lock_channel, send, store
from app.presentation import ResourcePresentation
from app.schemas import StrictModel
from app.security import authenticated, rate_limit
from app.workspace_api import mrtg_only_series, source_summary

router = APIRouter()


@router.get("/servers/{server_id}/alert-settings")
def get_alert_settings(server_id: UUID, auth=Depends(authenticated), db: Session = Depends(get_db)):
    server = db.get(Server, str(server_id))
    if not server:
        raise HTTPException(404, "Servidor no encontrado.")
    return settings_for(server)


@router.put("/servers/{server_id}/alert-settings")
def save_alert_settings(
    server_id: UUID,
    payload: AlertSettings,
    auth=Depends(authenticated),
    db: Session = Depends(get_db),
):
    server = db.scalar(select(Server).where(Server.id == str(server_id)).with_for_update())
    if not server:
        raise HTTPException(404, "Servidor no encontrado.")
    values = payload.model_dump()
    if values != settings_for(server):
        revision = (server.alert_settings or {}).get("revision", 0) + 1
        server.alert_settings = {**values, "revision": revision}
        db.execute(
            update(AnomalyState)
            .where(
                AnomalyState.service_id.in_(
                    select(Service.id).where(Service.server_id == server.id)
                )
            )
            .values(bad=0, good=0)
        )
        db.add(
            AuditEvent(action="server.alert_settings.update", target_id=f"{server.id}:{revision}")
        )
        db.commit()
    return values


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
        "required_recovery_samples": settings_for(db.get(Server, incident.server_id))[
            "recovery_samples"
        ],
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
    hours: int = Query(24, ge=1, le=720),
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
            .limit(10000)
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
                        **{
                            f"domain_{key}": frame.domains.get(domain, {}).get(key)
                            for key in ("req_count", "req_mean", "req_max", "req_p95")
                        },
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
        "slow_domains": sorted(
            [
                dict(domain=d, **v)
                for d, v in (
                    last.domains
                    if last and last.valid and now() - last.observed_at <= timedelta(minutes=10)
                    else {}
                ).items()
                if v.get("req_count", 0) > 0
            ],
            key=lambda v: v.get("req_mean") or 0,
            reverse=True,
        )[:30],
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
        "priority": "critical"
        if any(i.severity == "critical" for i in incidents)
        else "warning"
        if incidents
        else "none",
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
    lock_channel(db)
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
    unchanged = all(
        config.get(k) == old.get(k)
        for k in ("host", "port", "security", "username", "password", "sender", "recipient")
    )
    config["verified_at"] = old.get("verified_at") if unchanged else None
    config["last_test_at"] = old.get("last_test_at")
    config["last_error"] = old.get("last_error") if unchanged else None
    if config["enabled"] and not config["verified_at"]:
        raise HTTPException(409, "Guarda y comprueba el correo antes de activar las alertas.")
    store(db, config)
    from app.models import AuditEvent

    db.add(AuditEvent(action="notifications.update", target_id="1"))
    db.commit()
    return {"saved": True, "enabled": config["enabled"]}


@router.post("/notifications/test")
def test_mail(auth=Depends(authenticated), db: Session = Depends(get_db)):
    from datetime import datetime

    rate_limit("mail-test", 3, 3600)
    lock_channel(db)
    config = configuration(db)
    last = config.get("last_test_at")
    if last and now() - datetime.fromisoformat(last) < timedelta(minutes=5):
        raise HTTPException(
            429, "Espera cinco minutos entre pruebas para evitar bloqueos del proveedor."
        )
    if not all(config.get(k) for k in ("host", "sender", "recipient")):
        raise HTTPException(422, "Guarda primero servidor, remitente y destinatario.")
    config.update(enabled=False, verified_at=None, last_test_at=now().isoformat(), last_error=None)
    # Persist the attempt before network access; a process crash must not bypass cooldown.
    store(db, config)
    db.commit()
    lock_channel(db)
    current = configuration(db)
    if current != config:
        raise HTTPException(409, "La configuración ha cambiado; vuelve a comprobarla.")
    try:
        send(config)
        config["verified_at"] = now().isoformat()
        message = "El servidor SMTP ha aceptado el correo de prueba. Comprueba tu bandeja y después activa las alertas."
        ok = True
    except Exception as error:
        message = failure_message(error)
        config["last_error"] = message
        ok = False
    store(db, config)
    db.add(
        AuditEvent(
            action="notifications.test_ok" if ok else "notifications.test_failed", target_id="1"
        )
    )
    db.commit()
    return {"ok": ok, "message": message}


@router.get("/servers/{server_id}/security-analysis")
def security_analysis(
    server_id: UUID,
    hours: int = Query(24, ge=1, le=720),
    service_id: UUID | None = None,
    auth=Depends(authenticated),
    db: Session = Depends(get_db),
):
    from app.threats import assess, data, history

    server = db.get(Server, str(server_id))
    if not server:
        raise HTTPException(404, "Servidor no encontrado.")
    services = db.scalars(
        select(Service).where(
            Service.server_id == server.id,
            Service.kind == "apache_status",
            Service.enabled.is_(True),
            Service.archived.is_(False),
        )
    ).all()
    if service_id:
        services = [s for s in services if s.id == str(service_id)]
        if not services:
            raise HTTPException(404, "Servicio Apache no encontrado.")
    items, series, endpoints, period_ips, period_domains = [], [], {}, {}, {}
    presentation = ResourcePresentation(db)
    for svc in services:
        last = db.scalar(
            select(ServerFrame)
            .where(ServerFrame.service_id == svc.id)
            .order_by(ServerFrame.observed_at.desc())
            .limit(1)
        )
        if not last:
            continue
        rows = history(db, last)
        fresh = (
            last.valid
            and last.revision == svc.revision
            and now() - last.observed_at <= timedelta(minutes=10)
            and bool(data(last))
        )
        assessment = (
            assess(last, rows, settings_for(server))
            if fresh
            else dict(ips=[], domains=[], degradation=[], contributors=[], samples=0)
        )
        displayed = presentation.resources(last.resources)
        for signal in assessment["degradation"]:
            factor = displayed.get(signal["metric"], {}).get("display_factor")
            if signal["metric"] in {"ram_free", "swap_free"} and factor:
                signal.update(
                    before=signal["before"] * factor, value=signal["value"] * factor, unit="bytes"
                )
        for row in assessment["ips"]:
            row["geo"] = enrich({"ips": [{"ip": row["key"]}]})["ips"][0]
        assessment["resource_coverage"] = (
            sum(
                bool(p.get("source_at"))
                and abs((last.observed_at - datetime.fromisoformat(p["source_at"])).total_seconds())
                <= 900
                for role, p in last.resources.items()
                if role in {"cpu", "load", "ram_free", "swap_free"}
            )
            if fresh
            else 0
        )
        items.append(
            dict(
                service_id=svc.id, service=svc.name, at=last.observed_at, fresh=fresh, **assessment
            )
        )
        for frame in rows + [last]:
            if frame.observed_at < now() - timedelta(hours=hours):
                continue
            valid = frame.valid and bool(data(frame))
            series.append(
                dict(
                    at=frame.observed_at,
                    service=svc.name,
                    connections=sum(r["active"] for r in data(frame).get("ips", {}).values())
                    if valid
                    else None,
                    anomalies=frame.metrics.get("security_anomalies") if valid else None,
                )
            )
            if not valid:
                continue
            for group, totals in (("ips", period_ips), ("domains", period_domains)):
                for key, row in data(frame).get(group, {}).items():
                    entry = totals.setdefault(
                        (svc.id, key),
                        dict(
                            key=key,
                            service=svc.name,
                            observations=0,
                            peak=0,
                            score=0,
                            deviation=None,
                            req_max=None,
                        ),
                    )
                    entry["observations"] += row["active"]
                    entry["peak"] = max(entry["peak"], row["active"])
                    entry["score"] = max(entry["score"], row.get("score", 0))
                    for metric in ("deviation", "req_max"):
                        if row.get(metric) is not None:
                            entry[metric] = max(entry[metric] or 0, row[metric])
            for row in data(frame).get("ips", {}).values():
                for endpoint, count in row["endpoints"].items():
                    endpoints[endpoint] = endpoints.get(endpoint, 0) + count
    degrading = any(i["degradation"] for i in items)
    possible = any(
        r["category"] == "posible ataque" for i in items for g in ("ips", "domains") for r in i[g]
    )
    watch = any(r["signals"] for i in items for g in ("ips", "domains") for r in i[g])
    complete = (
        len(items) == len(services)
        and bool(items)
        and all(
            i["fresh"] and i["samples"] >= 24 and i.get("resource_coverage") == 4 for i in items
        )
    )

    def leaders(totals):
        selected = {}
        for metric in ("observations", "score", "deviation", "req_max"):
            for key, row in sorted(
                totals.items(), key=lambda pair: pair[1].get(metric) or 0, reverse=True
            )[:30]:
                selected[key] = row
        return list(selected.values())

    return dict(
        state="Posible ataque"
        if possible
        else "Degradación"
        if degrading
        else "Vigilancia"
        if watch
        else "Normal"
        if complete
        else "Datos insuficientes",
        items=items,
        series=series,
        endpoints=[
            dict(endpoint=k, observations=v)
            for k, v in sorted(endpoints.items(), key=lambda x: x[1], reverse=True)[:30]
        ],
        active_ips=leaders(period_ips),
        active_domains=leaders(period_domains),
    )
