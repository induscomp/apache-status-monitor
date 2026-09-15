"""Administrator-facing signals. Source availability is distinct from resource pressure."""

from datetime import datetime, timedelta

from sqlalchemy import select

from app.alert_settings import settings_for
from app.analysis import baseline, correlate, resource_spike
from app.models import Server, ServerFrame, Service
from app.presentation import ResourcePresentation

RESOURCE_NAMES = {
    "ram_free": "Memoria RAM",
    "swap_free": "Swap",
    "cpu": "CPU",
    "load": "Carga del servidor",
}


def recent(point, at):
    try:
        observed = datetime.fromisoformat(point["observed_at"])
        source = datetime.fromisoformat(point["source_at"]) if point.get("source_at") else None
        return abs((at - observed).total_seconds()) <= 600 and (
            source is None or abs((at - source).total_seconds()) <= 900
        )
    except KeyError, ValueError, TypeError:
        return False


def build_monitors(db, server_id, start, end, incidents, truncated=False):
    server = db.get(Server, server_id)
    settings = settings_for(server)
    services = {
        s.id: s
        for s in db.scalars(
            select(Service).where(
                Service.server_id == server_id,
                Service.enabled.is_(True),
                Service.archived.is_(False),
            )
        )
    }
    apache = {key: s for key, s in services.items() if s.kind == "apache_status"}
    frames = db.scalars(
        select(ServerFrame)
        .where(
            ServerFrame.server_id == server_id,
            ServerFrame.service_id.in_(apache),
            ServerFrame.observed_at >= start,
            ServerFrame.observed_at < end,
        )
        .order_by(ServerFrame.observed_at.desc())
        .limit(5001)
    ).all()
    truncated = truncated or len(frames) > 5000
    frames = [f for f in frames[:5000] if f.revision == apache[f.service_id].revision]
    latest = {}
    for frame in frames:
        latest.setdefault(frame.service_id, frame)
    valid_latest = [
        f for f in latest.values() if f.valid and end - f.observed_at <= timedelta(minutes=10)
    ]
    complete_now = (
        bool(apache) and len(valid_latest) == len(apache) and not truncated and not server.archived
    )
    history = [f for f in frames if f.valid and f.observed_at <= end - timedelta(minutes=30)]
    learned = complete_now and all(
        len({int(f.observed_at.timestamp()) // 300 for f in history if f.service_id == key}) >= 170
        for key in apache
    )
    current_resources, _ = correlate(db, server_id, end) if not server.archived else ({}, [])
    # Correlated frame resources supply past evidence; current readings come directly from MRTG.
    presentation = ResourcePresentation(db)
    rows = []
    for key, name in RESOURCE_NAMES.items():
        point = current_resources.get(key)
        samples = []
        references = {}
        for f in frames:
            p = f.resources.get(key)
            if p and recent(p, f.observed_at):
                samples.append((f.observed_at, p))
                if f.observed_at <= end - timedelta(minutes=30):
                    references.setdefault(p.get("basis"), {})[
                        int(f.observed_at.timestamp()) // 300
                    ] = p["value"]
        related = [i for i in incidents if i.subject == "resource:" + key]
        opened = [i for i in related if i.status == "open"]
        state, status, reason = (
            "unknown",
            "Sin lectura reciente",
            "No hay una lectura reciente con la que evaluar este recurso.",
        )
        reference = (
            baseline(list(references.get(point.get("basis"), {}).values()), minimum=12)
            if point
            else None
        )
        if point and recent(point, end):
            if reference:
                state, status, reason = (
                    "observed",
                    "Dentro de lo habitual",
                    "La última lectura está dentro de su referencia histórica.",
                )
                if resource_spike(point["value"], reference, key, settings):
                    state, status, reason = (
                        "warning",
                        "Desviación observada",
                        "La última lectura se ha desviado de su referencia; revisa la evolución y las confirmaciones del incidente.",
                    )
            else:
                state, status, reason = (
                    "learning",
                    "Aprendiendo",
                    "Faltan 12 intervalos históricos comparables para evaluar este recurso.",
                )
            if key == "swap_free":
                total = point.get("capacity")
                free = point["value"]
                if total is None or not 0 <= free <= total:
                    state, status, reason = (
                        "unknown",
                        "Uso sin determinar",
                        "Se conoce la swap libre, pero falta una capacidad total verificada para saber cuánto se está usando.",
                    )
                elif free < total:
                    state, status, reason = (
                        "critical",
                        "Swap en uso",
                        "La lectura confirma uso de swap. Revisa también la RAM y la carga.",
                    )
                else:
                    state, status, reason = (
                        "observed",
                        "Sin uso de swap",
                        "La swap libre coincide con la capacidad total verificada.",
                    )
            if point.get("source_at") is None and state in {"observed", "learning"}:
                state, status, reason = (
                    "unknown",
                    "Fecha por verificar",
                    "La recogida es reciente, pero la zona horaria de MRTG no permite verificar la antigüedad de origen.",
                )
        if opened:
            state = "critical" if any(i.severity == "critical" for i in opened) else "warning"
            status = "Aviso abierto"
            reason = (
                {
                    "ram_free": "La RAM libre cayó respecto a su valor habitual.",
                    "swap_free": "Hay un aviso de swap pendiente de recuperación.",
                    "cpu": "La CPU se desvió de su comportamiento habitual.",
                    "load": "La carga superó su referencia habitual.",
                }[key]
                + " El aviso sigue abierto hasta confirmar la recuperación; la falta de datos no lo resuelve."
            )
        shown = presentation.point(key, point) if point else {}
        context = []
        if reference and point:
            ref_shown = presentation.point(key, {**point, "value": reference["median"]})
            context.append(
                {
                    "label": "Referencia habitual",
                    "value": reference["median"],
                    "unit": point.get("unit"),
                    "display_bytes": ref_shown.get("display_bytes"),
                }
            )
        if point:
            context.append({"label": "Procedencia", "text": point.get("provenance", "MRTG")})
        rows.append(
            dict(
                id=key,
                name=name,
                state=state,
                status_text=status,
                reason=reason,
                value=point["value"] if point else None,
                unit=point.get("unit") if point else None,
                display_bytes=shown.get("display_bytes"),
                value_label="libres" if key in {"ram_free", "swap_free"} else "",
                latest_at=point.get("observed_at") if point else None,
                context=context,
                bins=resource_bins(start, end, samples, related, truncated, key),
                action="resources",
            )
        )
    domains = sorted(
        [
            {"text": d, "value": v.get("active", 0), "service": services[f.service_id].name}
            for f in valid_latest
            for d, v in f.domains.items()
        ],
        key=lambda x: x["value"],
        reverse=True,
    )
    ips = sorted(
        [
            {
                "text": p["ip"],
                "value": p["count"],
                "service": services[f.service_id].name,
                "provider": p.get("organization") or "Proveedor desconocido",
            }
            for f in valid_latest
            for p in (f.details or {}).get("ips", [])
        ],
        key=lambda x: x["value"],
        reverse=True,
    )
    domain_incidents = [i for i in incidents if i.subject.startswith("domain:")]
    for key, name, entries in [
        ("domains", "Actividad por dominio", domains),
        ("ips", "Conexiones por IP", ips),
    ]:
        related = (
            domain_incidents
            if key == "domains"
            else [i for i in domain_incidents if i.evidence.get("coincidences", {}).get("ips")]
        )
        opened = [i for i in related if i.status == "open"]
        state, status = (
            ("observed", "Sin anomalías de dominio")
            if learned
            else ("learning", "Aprendiendo")
            if complete_now
            else ("unknown", "Cobertura insuficiente")
        )
        reason = "Cada dominio se compara con su propio histórico de 24 horas, dentro de su servicio Apache."
        if key == "ips":
            # We have rankings, not an independent IP anomaly detector. Do not promise a green health check.
            state, status = (
                ("informational", "Observación")
                if complete_now
                else ("unknown", "Cobertura insuficiente")
            )
            reason = "Muestra las IP con más conexiones en la última captura y las que coinciden con avisos de dominio. No hay un detector independiente por IP; la concentración no demuestra un ataque."
        if opened:
            state = (
                "critical"
                if key == "domains" and any(i.severity == "critical" for i in opened)
                else "warning"
            )
            status = (
                "Dominios fuera de lo habitual"
                if key == "domains"
                else "IPs coincidentes con avisos"
            )
        context = [
            {
                "label": entry["text"],
                "text": f"{entry['value']} conexiones observadas · {entry['service']}"
                + (f" · {entry['provider']}" if entry.get("provider") else ""),
            }
            for entry in entries[:5]
        ]
        if key == "ips":
            for incident in opened[:3]:
                for ip in incident.evidence.get("coincidences", {}).get("ips", [])[:3]:
                    context.append(
                        {
                            "label": "IP durante un aviso: " + ip["ip"],
                            "text": "Coincidió con "
                            + incident.subject.removeprefix("domain:")
                            + ". Evidencia guardada el "
                            + incident.updated_at.isoformat()
                            + "; no es una atribución de causa.",
                        }
                    )
        rows.append(
            dict(
                id=key,
                name=name,
                state=state,
                status_text=status,
                reason=reason,
                value=entries[0]["value"] if entries else 0 if complete_now else None,
                unit="conexiones",
                display_bytes=None,
                value_label="máximo por dominio" if key == "domains" else "máximo por IP",
                latest_at=max((f.observed_at for f in valid_latest), default=None),
                context=context,
                bins=activity_bins(start, end, frames, apache, related, truncated, key),
                action=key,
            )
        )
    return rows


def segment(start, end, incidents, coverage, samples, state=None):
    active = [
        i
        for i in incidents
        if i.opened_at < end and (i.resolved_at is None or i.resolved_at > start)
    ]
    resolved = [i for i in incidents if i.resolved_at and start <= i.resolved_at < end]
    color = (
        "critical"
        if state == "critical" or any(i.severity == "critical" for i in active)
        else "warning"
        if active
        else state or ("observed" if coverage == "complete" else "unknown")
    )
    return dict(
        start=start.isoformat(),
        end=end.isoformat(),
        state=color,
        coverage=coverage,
        samples=samples,
        incidents=len(active),
        resolved=len(resolved),
        details=[
            dict(
                subject=i.subject,
                service="Evidencia del incidente",
                opened_at=i.opened_at.isoformat(),
                resolved_at=i.resolved_at.isoformat() if i.resolved_at else None,
                severity=i.severity,
            )
            for i in active[:3]
        ],
    )


def resource_bins(start, end, samples, incidents, truncated, key):
    bins = []
    for index in range(48):
        left, right = (
            start + timedelta(minutes=index * 30),
            start + timedelta(minutes=(index + 1) * 30),
        )
        selected = [(at, p) for at, p in samples if left <= at < right]
        count = len({int(at.timestamp()) // 300 for at, p in selected})
        valid = len(
            {
                int(at.timestamp()) // 300
                for at, p in selected
                if p.get("source_at")
                and (
                    key != "swap_free"
                    or (p.get("capacity") is not None and 0 <= p["value"] <= p["capacity"])
                )
            }
        )
        coverage = (
            "complete" if valid >= 5 and not truncated else "partial" if selected else "missing"
        )
        # Without a persisted evaluation, complete readings mean observed, not proof of health.
        color = (
            "critical"
            if key == "swap_free"
            and any(
                p.get("capacity") is not None and 0 <= p["value"] < p["capacity"]
                for at, p in selected
            )
            else None
        )
        bins.append(segment(left, right, incidents, coverage, count, color))
    return bins


def activity_bins(start, end, frames, services, incidents, truncated, key):
    bins = []
    for index in range(48):
        left, right = (
            start + timedelta(minutes=index * 30),
            start + timedelta(minutes=(index + 1) * 30),
        )
        selected = [f for f in frames if left <= f.observed_at < right]
        coverage = (
            "complete"
            if services
            and all(
                len(
                    {
                        int(f.observed_at.timestamp()) // 300
                        for f in selected
                        if f.valid and f.service_id == sid
                    }
                )
                >= 5
                for sid in services
            )
            and not truncated
            else "partial"
            if selected
            else "missing"
        )
        state = "informational" if coverage == "complete" and key == "ips" else None
        item = segment(
            left,
            right,
            incidents,
            coverage,
            len({int(f.observed_at.timestamp()) // 300 for f in selected}),
            state,
        )
        if key == "ips" and item["state"] == "critical":
            item["state"] = "warning"
        bins.append(item)
    return bins
