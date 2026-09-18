"""Evidence from Apache snapshots and MRTG only; associations are not causation."""

import json
import logging
import re
from collections import Counter
from datetime import datetime, timedelta
from statistics import median
from urllib.parse import unquote

from sqlalchemy import delete, or_, select, text, update
from sqlalchemy.orm import defer

from app.config import get_settings
from app.connectors.apache import parse_auto
from app.connectors.mrtg import parse_detail
from app.db import session_factory
from app.geo import lookup
from app.models import (
    AnomalyState,
    ApacheObservation,
    Incident,
    MrtgMetric,
    MrtgObservation,
    ServerFrame,
    Service,
    now,
)

SENSITIVE = re.compile(
    r"/(?:wp-login\.php|xmlrpc\.php|wp-admin/(?:admin-ajax|admin-post)\.php)(?:/|$)", re.I
)


def rankings(workers):
    domains = {}
    ips, urls, posts = Counter(), Counter(), Counter()
    for worker in workers:
        from app.performance import internal

        if internal(worker) or worker["state"] in {".", "I", "S"}:
            continue
        domain = worker.get("domain")
        active = worker.get("observation") == "current" and bool(worker.get("client"))
        if domain:
            item = domains.setdefault(domain[:254], {"active": 0, "appearances": 0, "posts": 0})
            item["appearances"] += 1
            item["active"] += int(active)
        if active and worker.get("client"):
            ips[worker["client"]] += 1
        path = worker.get("path")
        method = (worker.get("method") or "").upper()
        if path and not method.startswith("["):
            urls[(domain, method, path)] += 1
            if method == "POST" and SENSITIVE.search(unquote(path)):
                posts[(domain, worker.get("client"), path)] += 1
                if domain:
                    domains[domain[:254]]["posts"] += 1
    return domains, {
        "ips": [dict(ip=ip, count=count, **lookup(ip)) for ip, count in ips.most_common(30)],
        "urls": [
            {"domain": d, "method": m, "path": p, "count": count}
            for (d, m, p), count in urls.most_common(30)
        ],
        "posts": [
            {"domain": d, "ip": ip, "path": p, "count": count}
            for (d, ip, p), count in posts.most_common(30)
        ],
    }


def signal(metric, point):
    title = metric.name.casefold()
    label = (point.get("display_label") or point.get("label") or "").casefold()
    if point["window"] != "d" or point["statistic"] != "current":
        return None
    role = None
    if "memoria" in title and "libre" in title and ("fisica" in label or "física" in label):
        role = "ram_free"
    elif "swap" in title and "libre" in title and point["channel"] == "in":
        role = "swap_free"
    elif "cpu" in title and point["channel"] == "in":
        role = "cpu"
    elif ("carga del sistema" in title or "system load" in title) and point["channel"] == "in":
        role = "load"
    elif "http" in title and "proces" in title and point["channel"] == "in":
        role = "http_processes"
    elif "tcp" in title and point["channel"] == "in":
        role = "tcp_connections"
    elif ("procesos ejecutandose" in title or "processes running" in title) and point[
        "channel"
    ] == "in":
        role = "processes"
    return role


def correlate(db, server_id, at):
    metrics = db.scalars(
        select(MrtgMetric)
        .join(Service)
        .where(
            Service.server_id == server_id,
            Service.enabled.is_(True),
            Service.archived.is_(False),
            MrtgMetric.selected.is_(True),
            MrtgMetric.present.is_(True),
        )
    ).all()
    resources, warnings = {}, []
    for metric in metrics:
        samples = db.scalars(
            select(MrtgObservation)
            .options(defer(MrtgObservation.raw_encrypted))
            .where(
                MrtgObservation.metric_id == metric.id,
                MrtgObservation.metric_revision == metric.revision,
                MrtgObservation.revision
                == select(Service.revision)
                .where(Service.id == metric.service_id)
                .scalar_subquery(),
                MrtgObservation.status != "error",
                MrtgObservation.observed_at >= at - timedelta(minutes=5),
                MrtgObservation.observed_at <= at + timedelta(minutes=2),
            )
            .order_by(MrtgObservation.observed_at.desc())
            .limit(3)
        ).all()
        if not samples:
            continue
        sample = min(samples, key=lambda s: abs((s.observed_at - at).total_seconds()))
        if sample.source_at and abs((sample.source_at - at).total_seconds()) > 900:
            continue
        # Detect frozen source pages even when their timezone is unknown.
        if sample.source_time_text:
            earliest = db.scalar(
                select(MrtgObservation.observed_at)
                .where(
                    MrtgObservation.metric_id == metric.id,
                    MrtgObservation.source_time_text == sample.source_time_text,
                )
                .order_by(MrtgObservation.observed_at)
                .limit(1)
            )
            if earliest and sample.observed_at - earliest > timedelta(minutes=15):
                continue
        points = sample.values
        # Earlier collector versions stored comments without visible labels. Read the
        # same encrypted page to recover metadata without inventing another source.
        if not any(p.get("display_label") for p in points) and sample.raw_encrypted:
            try:
                parsed = parse_detail(
                    get_settings().cipher().decrypt(sample.raw_encrypted.encode()).decode()
                )
                metadata = {
                    (p["window"], p["channel"], p["statistic"]): p for p in parsed["values"]
                }
                points = [
                    {
                        **p,
                        **{
                            k: v
                            for k, v in metadata.get(
                                (p["window"], p["channel"], p["statistic"]), {}
                            ).items()
                            if k.startswith("display_")
                        },
                    }
                    for p in points
                ]
            except ValueError, UnicodeError:
                pass
        for point in points:
            role = signal(metric, point)
            if not role:
                continue
            # Visible SI prefixes scale the number, never determine metric meaning.
            table_factor = 1
            if point["source"] == "table":
                suffix = point.get("source_unit", "")
                match = re.match(r"^([kMGT])(?:B|b|bytes|$)", suffix)
                if match:
                    table_factor = {"k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}[match[1]]
            value, unit = (
                point.get("normalized_value", point["value"] * table_factor),
                point.get("unit", "valor de origen"),
            )
            if (
                role == "load"
                and "normalized_value" not in point
                and re.search(r"[*×]\s*100\b", metric.name)
            ):
                value, unit = value / 100, "carga (título ×100)"
            item = {
                "value": value,
                "unit": unit,
                "metric_id": metric.id,
                "sample_id": sample.id,
                "basis": f"{metric.id}:{sample.metric_revision}:{point['channel']}:{point['source']}:{unit}",
                "observed_at": sample.observed_at.isoformat(),
                "source_at": sample.source_at.isoformat() if sample.source_at else None,
                "source_key": f"{metric.id}:{sample.source_at or sample.source_time_text or sample.id}",
                "provenance": f"{metric.name} / {point['channel']} / {point['source']} diario",
            }
            if (
                role == "swap_free"
                and "normalized_value" in point
                and sample.configuration.get("verified")
                and sample.configuration.get("capacity") is not None
            ):
                item["capacity"] = sample.configuration["capacity"]
            if role in resources:
                warnings.append(
                    f"Varias métricas candidatas para {role}; se usa la más próxima temporalmente."
                )
                if abs((sample.observed_at - at).total_seconds()) >= abs(
                    (datetime.fromisoformat(resources[role]["observed_at"]) - at).total_seconds()
                ):
                    continue
            resources[role] = item
    for role in (
        "ram_free",
        "swap_free",
        "cpu",
        "load",
        "processes",
        "tcp_connections",
        "http_processes",
    ):
        if role not in resources:
            warnings.append(f"{role}: sin lectura MRTG correlacionable y reciente.")
    if any(v["source_at"] is None for v in resources.values()):
        warnings.append(
            "Correlación por hora de recogida: alguna fecha MRTG no tiene zona verificada."
        )
    return resources, warnings


def baseline(values, minimum=170):
    if len(values) < minimum:
        return None
    center = median(values)
    mad = median(abs(v - center) for v in values)
    return {"median": center, "mad": mad, "samples": len(values)}


def domain_spike(value, reference, settings=None):
    from app.alert_settings import AlertSettings

    settings = settings or AlertSettings().model_dump()
    if reference is None:
        return False
    center, mad = reference["median"], reference["mad"]
    return value >= max(1, center) * settings["domain_multiplier"] and value - center >= max(
        settings["domain_min_increase"], 6 * max(1, 1.4826 * mad)
    )


def resource_spike(value, reference, role, settings=None):
    from app.alert_settings import AlertSettings

    settings = settings or AlertSettings().model_dump()
    if reference is None:
        return False
    center, mad = reference["median"], reference["mad"]
    if role in {"ram_free", "swap_free"}:
        return (
            center > 0
            and value <= center * (1 - settings["memory_drop_percent"] / 100)
            and center - value >= 3 * mad
        )
    return value >= max(0.1, center) * settings["resource_multiplier"] and value - center >= max(
        0.1, 3 * mad
    )


def apache_globals(observation):
    values = observation.metrics.get("global", {})
    if "FreeSlots" not in values and observation.raw_encrypted:
        try:
            originals = json.loads(
                get_settings().cipher().decrypt(observation.raw_encrypted.encode())
            )
            if originals.get("auto"):
                values = {**values, **parse_auto(originals["auto"])}
        except ValueError, UnicodeError:
            pass
    return values


def build_frame(db, observation):
    service = db.get(Service, observation.service_id)
    domains, details = rankings(observation.workers or [])
    from app.threats import capture

    details["security"] = capture(observation.workers or [])
    g = apache_globals(observation)
    from app.performance import internal, sample_metrics

    metrics = {
        **sample_metrics(observation.workers or [], domains),
        "busy_workers": g.get("BusyWorkers"),
        **{
            f"state_{ {'.': 'dot', '_': 'idle'}.get(s, s) }": g[f"State_{s}"]
            for s in "WRKC_."
            if f"State_{s}" in g
        },
        "active_connections": sum(
            w.get("observation") == "current"
            and bool(w.get("client"))
            and not internal(w)
            and w["state"] not in {".", "I", "S"}
            for w in (observation.workers or [])
        ),
        "active_requests": g.get("ActiveRequests", observation.metrics.get("active_requests")),
        "idle_workers": g.get("IdleWorkers", observation.metrics.get("idle_workers")),
        "free_slots": g.get("FreeSlots", observation.metrics.get("free_slots")),
        "req_per_sec_reported": g.get("ReqPerSec"),
        "bytes_per_sec_reported": g.get("BytesPerSec"),
        "request_ms_reported": g.get("DurationPerReq"),
        "apache_load": g.get("Load1"),
        "req_per_sec": None,
        "bytes_per_sec": None,
        "request_ms": None,
    }
    previous = db.scalar(
        select(ApacheObservation)
        .options(defer(ApacheObservation.raw_encrypted), defer(ApacheObservation.workers))
        .where(
            ApacheObservation.service_id == observation.service_id,
            ApacheObservation.revision == observation.revision,
            ApacheObservation.status != "error",
            ApacheObservation.observed_at < observation.observed_at,
        )
        .order_by(ApacheObservation.observed_at.desc())
        .limit(1)
    )
    if previous:
        old = apache_globals(previous)
        seconds = (observation.observed_at - previous.observed_at).total_seconds()
        reset = any(
            k in old and k in g and g[k] < old[k]
            for k in ("Uptime", "Total Accesses", "Total kBytes", "TotalDuration")
        )
        if not reset and 0 < seconds <= 600:
            for source, target, factor in [
                ("Total Accesses", "req_per_sec", 1),
                ("Total kBytes", "bytes_per_sec", 1024),
            ]:
                if source in old and source in g:
                    metrics[target] = (g[source] - old[source]) * factor / seconds
            if (
                all(k in old and k in g for k in ("Total Accesses", "TotalDuration"))
                and g["Total Accesses"] > old["Total Accesses"]
            ):
                metrics["request_ms"] = (g["TotalDuration"] - old["TotalDuration"]) / (
                    g["Total Accesses"] - old["Total Accesses"]
                )
    resources, warnings = correlate(db, service.server_id, observation.observed_at)
    if observation.metrics.get("http2_observed"):
        warnings.append(
            "HTTP/2 detectado: los rankings muestran actividad visible del scoreboard, no todas las peticiones ni streams simultáneos. Pocos workers ocupados no descartan presión de recursos; consulta también MRTG."
        )
    valid = (
        observation.status != "error"
        and observation.workers is not None
        and not any(
            re.search(r"columna|incomplet|truncad|Filas", w, re.I) for w in observation.warnings
        )
    )
    return ServerFrame(
        observation_id=observation.id,
        server_id=service.server_id,
        service_id=service.id,
        revision=observation.revision,
        observed_at=observation.observed_at,
        valid=valid,
        metrics=metrics,
        domains=domains,
        details=details,
        resources=resources,
        warnings=warnings + observation.warnings,
    )


def run():
    from app.incidents import evaluate

    with session_factory()() as db:
        ids = db.scalars(
            select(ApacheObservation.id)
            .outerjoin(ServerFrame, ServerFrame.observation_id == ApacheObservation.id)
            .where(
                ServerFrame.id.is_(None),
                ApacheObservation.observed_at < now() - timedelta(seconds=90),
                ApacheObservation.observed_at >= now() - timedelta(days=1),
            )
            .order_by(ApacheObservation.observed_at)
            .limit(24)
        ).all()
    # Each service is processed chronologically under one transaction lock.
    for key in ids:
        try:
            with session_factory()() as db:
                service_id = db.scalar(
                    select(ApacheObservation.service_id).where(ApacheObservation.id == key)
                )
                if not service_id or not db.scalar(
                    text("SELECT pg_try_advisory_xact_lock(hashtextextended(:key, 0))"),
                    {"key": "analysis:" + service_id},
                ):
                    continue
                observation = db.scalar(
                    select(ApacheObservation)
                    .outerjoin(ServerFrame, ServerFrame.observation_id == ApacheObservation.id)
                    .where(
                        ServerFrame.id.is_(None),
                        ApacheObservation.service_id == service_id,
                        ApacheObservation.observed_at < now() - timedelta(seconds=90),
                        ApacheObservation.observed_at >= now() - timedelta(days=1),
                    )
                    .order_by(ApacheObservation.observed_at)
                    .limit(1)
                )
                if observation is None:
                    continue
                frame = build_frame(db, observation)
                db.add(frame)
                db.flush()
                evaluate(db, frame)
                db.commit()
        except Exception as exc:
            logging.getLogger("smon.analysis").error(
                json.dumps({"event": "analysis_failed", "type": type(exc).__name__})
            )


def retention():
    with session_factory()() as db:
        db.execute(
            delete(AnomalyState).where(
                or_(
                    AnomalyState.subject.like("security:ips:%"),
                    AnomalyState.subject.like("ipwatch:%"),
                ),
                AnomalyState.last_at < now() - timedelta(days=30),
            )
        )
        db.execute(
            update(ServerFrame)
            .where(ServerFrame.observed_at < now() - timedelta(days=30))
            .values(details=None)
        )
        db.execute(delete(ServerFrame).where(ServerFrame.observed_at < now() - timedelta(days=90)))
        for incident in db.scalars(
            select(Incident).where(Incident.updated_at < now() - timedelta(days=30))
        ):
            if incident.kind in {"security", "ip_activity"}:
                incident.evidence = {
                    k: v for k, v in incident.evidence.items() if k not in {"timeline", "reasons"}
                }
                if incident.subject.startswith(("security:ips:", "ipwatch:")):
                    incident.subject = "security:ips:identidad-caducada-" + incident.id
            if "coincidences" in incident.evidence:
                incident.evidence = {
                    k: v for k, v in incident.evidence.items() if k != "coincidences"
                }
        db.commit()
