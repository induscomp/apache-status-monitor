import hashlib
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.connectors.goaccess import parse_report
from app.connectors.policy import service_transport_options
from app.connectors.transport import fetch
from app.db import get_db, session_factory
from app.models import GoAccessReport, GoAccessState, Server, Service, ServiceCheck, now
from app.security import authenticated

router = APIRouter()


def freshness(report, at, max_age_hours=26):
    if not report or not report.generated_at:
        return "partial"
    if report.generated_at > at + timedelta(minutes=5):
        return "partial"
    return "stale" if at - report.generated_at > timedelta(hours=max_age_hours) else "ok"


def collect_service(key):
    with session_factory()() as db:
        service = db.scalar(
            select(Service).where(Service.id == key).with_for_update(skip_locked=True)
        )
        if (
            not service
            or service.kind != "goaccess"
            or not service.enabled
            or service.archived
            or db.get(Server, service.server_id).archived
        ):
            return
        state = db.get(GoAccessState, key)
        stamp = now()
        if state and state.observed_at + timedelta(seconds=300) > stamp:
            return
        if not state:
            state = GoAccessState(service_id=key, status="waiting", warnings=[])
            db.add(state)
        if state.revision != service.revision:
            state.report_id = None
        state.revision, state.observed_at = service.revision, stamp
        try:
            credentials = (
                json.loads(get_settings().cipher().decrypt(service.credentials_encrypted.encode()))
                if service.credentials_encrypted
                else None
            )
            body = fetch(service.url, credentials, **service_transport_options(service))
            generated, summary, panels = parse_report(body)
            fingerprint = hashlib.sha256(
                json.dumps([str(generated), summary, panels], sort_keys=True).encode()
            ).hexdigest()
            report = db.scalar(
                select(GoAccessReport).where(
                    GoAccessReport.service_id == key,
                    GoAccessReport.revision == service.revision,
                    GoAccessReport.fingerprint == fingerprint,
                )
            )
            if not report:
                report = GoAccessReport(
                    service_id=key,
                    revision=service.revision,
                    fingerprint=fingerprint,
                    generated_at=generated,
                    observed_at=stamp,
                    summary=summary,
                    panels=panels,
                )
                db.add(report)
                db.flush()
            state.report_id = report.id
            state.status = freshness(
                report, stamp, service.options.get("goaccess_max_age_hours", 26)
            )
            state.warnings = (
                []
                if state.status == "ok"
                else [
                    "Informe desactualizado o fecha de generación no verificable. No describe el estado actual."
                ]
            )
        except Exception:
            state.status = "error"
            state.warnings = [
                "No se pudo leer el informe GoAccess. Revisa URL, DNS, TLS, permisos y tamaño (máximo 2 MiB)."
            ]
        db.add(
            ServiceCheck(
                service_id=key, revision=service.revision, observed_at=stamp, status=state.status
            )
        )
        db.commit()


def collect_due():
    with session_factory()() as db:
        ids = db.scalars(
            select(Service.id)
            .join(Server)
            .where(
                Service.kind == "goaccess",
                Service.enabled.is_(True),
                Service.archived.is_(False),
                Server.archived.is_(False),
            )
        ).all()
    with ThreadPoolExecutor(max_workers=2) as pool:
        for future in [pool.submit(collect_service, key) for key in ids]:
            try:
                future.result()
            except Exception:
                logging.getLogger("smon.goaccess").error(
                    "goaccess_collection_failed; details withheld"
                )


def status(db, service):
    state = db.get(GoAccessState, service.id)
    if not state:
        return "waiting"
    if state.revision != service.revision or now() - state.observed_at > timedelta(minutes=10):
        return "stale"
    if state.status == "error":
        return "error"
    return freshness(
        db.get(GoAccessReport, state.report_id) if state.report_id else None,
        now(),
        service.options.get("goaccess_max_age_hours", 26),
    )


def report_result(report):
    return {
        "id": report.id,
        "revision": report.revision,
        "observed_at": report.observed_at,
        "generated_at": report.generated_at,
        "summary": report.summary,
        "panels": {
            k: v
            for k, v in report.panels.items()
            if report.observed_at >= now() - timedelta(days=30) or k not in {"hosts", "requests"}
        },
    }


@router.get("/services/{service_id}/goaccess")
def detail(service_id: UUID, auth=Depends(authenticated), db: Session = Depends(get_db)):
    service = db.get(Service, str(service_id))
    if not service or service.kind != "goaccess":
        raise HTTPException(404, "Fuente GoAccess no encontrada.")
    state = db.get(GoAccessState, service.id)
    report = db.get(GoAccessReport, state.report_id) if state and state.report_id else None
    history = db.scalars(
        select(GoAccessReport)
        .where(GoAccessReport.service_id == service.id)
        .order_by(GoAccessReport.observed_at.desc())
        .limit(30)
    ).all()
    return {
        "status": status(db, service),
        "checked_at": state.observed_at if state else None,
        "warnings": state.warnings if state else [],
        "report": report_result(report) if report else None,
        "history": [
            {
                "id": r.id,
                "revision": r.revision,
                "generated_at": r.generated_at,
                "observed_at": r.observed_at,
                "summary": r.summary,
            }
            for r in history
        ],
        "note": "Totales del periodo del informe. No sumar informes sucesivos: sus periodos pueden solaparse. No se usan para alertas en tiempo real ni se ejecuta su JavaScript.",
    }


def retention():
    with session_factory()() as db:
        db.execute(
            delete(ServiceCheck).where(ServiceCheck.observed_at < now() - timedelta(days=90))
        )
        for report in db.scalars(
            select(GoAccessReport).where(GoAccessReport.observed_at < now() - timedelta(days=30))
        ):
            report.panels = {
                k: v for k, v in report.panels.items() if k not in {"hosts", "requests"}
            }
        # Keep the report referenced by polling state, but erase personal detail on time.
        active = select(GoAccessState.report_id).where(GoAccessState.report_id.is_not(None))
        db.execute(
            delete(GoAccessReport).where(
                GoAccessReport.observed_at < now() - timedelta(days=90),
                GoAccessReport.id.not_in(active),
            )
        )
        db.commit()
