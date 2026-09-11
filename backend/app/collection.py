import json
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.orm import defer

from app.config import get_settings
from app.connectors.apache import parse_auto, parse_html
from app.connectors.transport import FetchError, fetch
from app.db import session_factory
from app.models import ApacheObservation, Server, Service, now


def latest(db, service_id, success=False):
    query = (
        select(ApacheObservation)
        .options(defer(ApacheObservation.raw_encrypted), defer(ApacheObservation.workers))
        .where(ApacheObservation.service_id == service_id)
    )
    if success:
        query = query.where(ApacheObservation.status != "error")
    return db.scalar(query.order_by(ApacheObservation.observed_at.desc()).limit(1))


def collect_service(service_id):
    with session_factory()() as db:
        # A row lock excludes other worker processes and concurrent configuration changes.
        service = db.scalar(
            select(Service).where(Service.id == service_id).with_for_update(skip_locked=True)
        )
        if (
            not service
            or not service.enabled
            or service.archived
            or service.kind != "apache_status"
        ):
            return
        if db.get(Server, service.server_id).archived:
            return
        previous = latest(db, service.id)
        stamp = now()
        if previous and previous.observed_at + timedelta(seconds=service.interval_seconds) > stamp:
            return
        result = ApacheObservation(
            service_id=service.id,
            revision=service.revision,
            observed_at=stamp,
            status="error",
            metrics={},
            warnings=[],
            workers=None,
        )
        originals = {}
        try:
            settings = get_settings()
            credentials = (
                json.loads(settings.cipher().decrypt(service.credentials_encrypted.encode()))
                if service.credentials_encrypted
                else None
            )
            originals["html"] = fetch(service.url, credentials)
            parsed = parse_html(originals["html"])
            result.metrics = parsed["metrics"]
            result.workers = parsed["workers"]
            result.warnings = parsed["warnings"]
            if service.options.get("apache_auto", True):
                try:
                    originals["auto"] = fetch(service.url, credentials, auto=True)
                    result.metrics["global"] = parse_auto(originals["auto"])
                except Exception:
                    result.warnings.append("No se pudieron obtener las métricas globales ?auto.")
            prior_success = latest(db, service.id, success=True)
            if prior_success and prior_success.revision == service.revision:
                old = prior_success.metrics.get("global", {})
                new = result.metrics.get("global", {})
                if any(
                    k in old and k in new and new[k] < old[k]
                    for k in ("Uptime", "Total Accesses", "Total kBytes")
                ):
                    result.warnings.append("Reinicio o reinicialización de contadores detectado.")
                if stamp - prior_success.observed_at > timedelta(
                    seconds=service.interval_seconds * 2
                ):
                    result.warnings.append("Hueco de recogida desde la última muestra válida.")
            result.status = "partial" if result.warnings else "ok"
        except FetchError as exc:
            result.warnings = [str(exc)]
        except Exception:
            # Never store remote exception text: it can contain credentials or request data.
            result.warnings = [
                "No se pudo leer o interpretar Apache Status. Revisa URL, DNS, TLS y permisos."
            ]
        if originals:
            result.raw_encrypted = (
                get_settings().cipher().encrypt(json.dumps(originals).encode()).decode()
            )
        db.add(result)
        db.commit()


def collect_due():
    with session_factory()() as db:
        ids = db.scalars(
            select(Service.id)
            .join(Server)
            .where(
                Service.kind == "apache_status",
                Service.enabled.is_(True),
                Service.archived.is_(False),
                Server.archived.is_(False),
            )
        ).all()
    # Bounded across services; each service failure is isolated from the next.
    with ThreadPoolExecutor(max_workers=2) as pool:
        for future in [pool.submit(collect_service, service_id) for service_id in ids]:
            try:
                future.result()
            except Exception:
                logging.getLogger("smon.worker").error("collection_failed; details withheld")


def retain_observations():
    with session_factory()() as db:
        db.execute(
            update(ApacheObservation)
            .where(ApacheObservation.observed_at < now() - timedelta(days=7))
            .values(raw_encrypted=None)
        )
        db.execute(
            update(ApacheObservation)
            .where(ApacheObservation.observed_at < now() - timedelta(days=30))
            .values(workers=None)
        )
        db.execute(
            delete(ApacheObservation).where(
                ApacheObservation.observed_at < now() - timedelta(days=90)
            )
        )
        db.commit()
