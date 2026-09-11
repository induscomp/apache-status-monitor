import json
import logging
import math
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.orm import defer

from app.config import get_settings
from app.connectors.mrtg import allowed_detail, discover, parse_detail
from app.connectors.transport import fetch
from app.db import session_factory
from app.models import MrtgDiscovery, MrtgMetric, MrtgObservation, Server, Service, now


def latest_metric(db, metric_id):
    return db.scalar(
        select(MrtgObservation)
        .options(defer(MrtgObservation.raw_encrypted))
        .where(MrtgObservation.metric_id == metric_id)
        .order_by(MrtgObservation.observed_at.desc())
        .limit(1)
    )


def credentials(service):
    return (
        json.loads(get_settings().cipher().decrypt(service.credentials_encrypted.encode()))
        if service.credentials_encrypted
        else None
    )


def discover_service(service_id):
    with session_factory()() as db:
        service = db.scalar(
            select(Service).where(Service.id == service_id).with_for_update(skip_locked=True)
        )
        if (
            not service
            or service.kind != "mrtg"
            or not service.enabled
            or service.archived
            or db.get(Server, service.server_id).archived
        ):
            return
        state = db.get(MrtgDiscovery, service.id)
        if state is None:
            state = MrtgDiscovery(service_id=service.id, revision=0, requested=True)
            db.add(state)
        if not state.requested and state.revision == service.revision and state.attempted_at:
            delay = timedelta(minutes=5) if state.error else timedelta(days=1)
            if state.attempted_at + delay > now():
                return
        # Throttle even explicit rediscovery so the API cannot flood the source.
        if state.attempted_at and state.attempted_at + timedelta(seconds=60) > now():
            return
        state.attempted_at = now()
        state.requested = False
        try:
            urls = discover(service.url, fetch(service.url, credentials(service)))
            existing = {
                m.url: m
                for m in db.scalars(
                    select(MrtgMetric).where(MrtgMetric.service_id == service.id)
                ).all()
            }
            for metric in existing.values():
                metric.present = metric.url in urls
            for url in urls:
                if url not in existing:
                    db.add(
                        MrtgMetric(
                            service_id=service.id,
                            url=url,
                            name=url.rsplit("/", 1)[-1][:200],
                            selected=True,
                        )
                    )
            state.revision = service.revision
            state.succeeded_at = now()
            state.error = None
        except Exception:
            state.error = "No se pudo descubrir el índice MRTG. Revisa URL, permisos y límites de origen/ruta."
        db.commit()


def collect_metric(metric_id):
    with session_factory()() as db:
        metric = db.scalar(
            select(MrtgMetric).where(MrtgMetric.id == metric_id).with_for_update(skip_locked=True)
        )
        if not metric or not metric.selected or not metric.present:
            return
        service = db.get(Service, metric.service_id)
        state = db.get(MrtgDiscovery, service.id)
        if (
            not service.enabled
            or service.archived
            or db.get(Server, service.server_id).archived
            or not state
            or state.revision != service.revision
        ):
            return
        if not allowed_detail(service.url, metric.url):
            return
        previous = latest_metric(db, metric.id)
        stamp = now()
        if previous and previous.observed_at + timedelta(seconds=service.interval_seconds) > stamp:
            return
        sample = MrtgObservation(
            metric_id=metric.id,
            service_id=service.id,
            revision=service.revision,
            metric_revision=metric.revision,
            configuration=metric.configuration.copy(),
            observed_at=stamp,
            status="error",
            values=[],
            warnings=[],
        )
        try:
            body = fetch(metric.url, credentials(service))
            sample.raw_encrypted = get_settings().cipher().encrypt(body.encode()).decode()
            parsed = parse_detail(body, metric.configuration.get("timezone"), stamp)
            if parsed["title"]:
                metric.name = parsed["title"]
            sample.values = parsed["values"]
            sample.source_at = parsed["source_at"]
            sample.source_time_text = parsed["source_time_text"]
            sample.warnings = parsed["warnings"]
            verified = metric.configuration.get("verified", False)
            for point in sample.values:
                # Comment and visible-table scales may differ (notably bits vs bytes).
                # Only comment values receive this explicitly configured interpretation.
                if verified and point["source"] == "comment":
                    normalized = point["value"] * metric.configuration["factor"]
                    if math.isfinite(normalized):
                        point["normalized_value"] = normalized
                        point["unit"] = metric.configuration["unit"]
                    else:
                        sample.warnings.append(
                            "Conversión fuera de rango; se conserva el valor original."
                        )
            if not verified or any(p["source"] == "table" for p in sample.values):
                sample.warnings.append(
                    "Semántica pendiente de interpretación; valores de origen sin convertir."
                )
            if previous and stamp - previous.observed_at > timedelta(
                seconds=service.interval_seconds * 2
            ):
                sample.warnings.append("Hueco de recogida desde la muestra anterior.")
            sample.status = "partial" if sample.warnings else "ok"
        except Exception:
            sample.warnings = [
                "No se pudo leer o interpretar esta página MRTG. Los demás servicios siguen funcionando."
            ]
        db.add(sample)
        db.commit()


def collect_due():
    with session_factory()() as db:
        ids = db.scalars(
            select(Service.id)
            .join(Server)
            .where(
                Service.kind == "mrtg",
                Service.enabled.is_(True),
                Service.archived.is_(False),
                Server.archived.is_(False),
            )
        ).all()
    for service_id in ids:
        try:
            discover_service(service_id)
        except Exception:
            logging.getLogger("smon.worker").error("mrtg_discovery_failed; details withheld")
    with session_factory()() as db:
        metrics = db.scalars(
            select(MrtgMetric.id).where(
                MrtgMetric.service_id.in_(ids),
                MrtgMetric.selected.is_(True),
                MrtgMetric.present.is_(True),
            )
        ).all()
    # A dedicated pool prevents slow MRTG pages from starving Apache's scheduler job.
    with ThreadPoolExecutor(max_workers=2) as pool:
        for future in [pool.submit(collect_metric, metric_id) for metric_id in metrics]:
            try:
                future.result()
            except Exception:
                logging.getLogger("smon.worker").error("mrtg_collection_failed; details withheld")


def retention():
    with session_factory()() as db:
        db.execute(
            update(MrtgObservation)
            .where(MrtgObservation.observed_at < now() - timedelta(days=7))
            .values(raw_encrypted=None)
        )
        db.execute(
            delete(MrtgObservation).where(MrtgObservation.observed_at < now() - timedelta(days=90))
        )
        db.commit()


def service_status(db, service):
    discovery = db.get(MrtgDiscovery, service.id)
    metrics = db.scalars(
        select(MrtgMetric).where(
            MrtgMetric.service_id == service.id,
            MrtgMetric.selected.is_(True),
            MrtgMetric.present.is_(True),
        )
    ).all()
    samples = [(m, latest_metric(db, m.id)) for m in metrics]
    found = [s for _, s in samples if s]
    last = max(found, key=lambda s: s.observed_at) if found else None
    successes = [s for s in found if s.status != "error"]
    status = "waiting"
    if discovery and discovery.error:
        status = "error"
    elif found:
        if len(found) < len(metrics):
            status = "partial"
        elif any(
            s.revision != service.revision
            or s.metric_revision != m.revision
            or s.observed_at + timedelta(seconds=service.interval_seconds * 2) < now()
            for m, s in samples
        ):
            status = "stale"
        elif all(s.status == "error" for s in found):
            status = "error"
        elif any(s.status != "ok" for s in found):
            status = "partial"
        else:
            status = "ok"
    return status, last, max(successes, key=lambda s: s.observed_at) if successes else None
