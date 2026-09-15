"""Compact server-wide incident history. Empty coverage is never a healthy state."""

from datetime import timedelta

from sqlalchemy import or_, select

from app.models import Incident, ServerFrame, Service, now


def summarize(db, server_id):
    end = now()
    start = end - timedelta(hours=24)
    incidents = db.scalars(
        select(Incident)
        .where(
            Incident.server_id == server_id,
            Incident.opened_at < end,
            or_(Incident.resolved_at.is_(None), Incident.resolved_at >= start),
        )
        .order_by(Incident.opened_at.desc())
        .limit(501)
    ).all()
    partial = len(incidents) > 500
    incidents = incidents[:500]
    services = {
        s.id: s.name for s in db.scalars(select(Service).where(Service.server_id == server_id))
    }
    frames = db.execute(
        select(ServerFrame.observed_at, ServerFrame.valid, ServerFrame.resources)
        .where(
            ServerFrame.server_id == server_id,
            ServerFrame.observed_at >= start,
            ServerFrame.observed_at < end,
        )
        .order_by(ServerFrame.observed_at.desc())
        .limit(5001)
    ).all()
    partial = partial or len(frames) > 5000
    frames = frames[:5000]
    bins = []
    for index in range(48):
        left, right = (
            start + timedelta(minutes=30 * index),
            start + timedelta(minutes=30 * (index + 1)),
        )
        active = [
            i
            for i in incidents
            if i.opened_at < right and (i.resolved_at is None or i.resolved_at > left)
        ]
        resolved = [i for i in incidents if i.resolved_at and left <= i.resolved_at < right]
        samples = [f for f in frames if left <= f.observed_at < right]
        complete = {
            int(f.observed_at.timestamp()) // 300
            for f in samples
            if f.valid and {"ram_free", "swap_free", "load"} <= set(f.resources)
        }
        coverage = (
            "complete"
            if len(complete) >= 5 and not partial
            else "partial"
            if samples
            else "missing"
        )
        state = (
            "critical"
            if any(i.severity == "critical" for i in active)
            else "warning"
            if active
            else "resolved"
            if resolved
            else "observed"
            if coverage == "complete"
            else "unknown"
        )
        bins.append(
            {
                "start": left.isoformat(),
                "end": right.isoformat(),
                "state": state,
                "coverage": coverage,
                "samples": len(samples),
                "incidents": len(active),
                "resolved": len(resolved),
                "details": [
                    dict(
                        subject=i.subject,
                        service=services.get(i.service_id, "Servicio archivado"),
                        opened_at=i.opened_at.isoformat(),
                        resolved_at=i.resolved_at.isoformat() if i.resolved_at else None,
                        severity=i.severity,
                    )
                    for i in (active or resolved)[:3]
                ],
            }
        )
    from app.operational_summary import build_monitors

    return {
        "monitors": build_monitors(db, server_id, start, end, incidents, partial),
        "start": start.isoformat(),
        "end": end.isoformat(),
        "partial": partial,
        "open": sum(i.status == "open" for i in incidents),
        "critical": sum(i.status == "open" and i.severity == "critical" for i in incidents),
        "resolved": sum(i.resolved_at is not None and i.resolved_at >= start for i in incidents),
        "bins": bins,
        "rows": service_rows(db, server_id, start, end, incidents, partial),
    }


def service_rows(db, server_id, start, end, incidents, partial):
    """Use each source's own checks, and attribute resource evidence to its MRTG metric."""
    from app.models import ApacheObservation, MrtgMetric, MrtgObservation, Server, ServiceCheck
    from app.workspace_api import source_summary

    services = db.scalars(
        select(Service).where(Service.server_id == server_id).order_by(Service.created_at)
    ).all()
    metrics = db.scalars(
        select(MrtgMetric).join(Service).where(Service.server_id == server_id)
    ).all()
    metric_services = {m.id: m.service_id for m in metrics}
    parent = db.get(Server, server_id)
    result = []
    for service in services:
        assigned = []
        for incident in incidents:
            if incident.subject.startswith("resource:"):
                point = incident.evidence.get("resources", {}).get(incident.subject[9:], {})
                owner = metric_services.get(point.get("metric_id"))
            else:
                owner = incident.service_id
            if owner == service.id:
                assigned.append(incident)
        required = {"source"}
        if service.kind == "mrtg":
            selected = {
                m.id: m for m in metrics if m.service_id == service.id and m.selected and m.present
            }
            required = set(selected)
            data = db.execute(
                select(
                    MrtgObservation.observed_at,
                    MrtgObservation.status,
                    MrtgObservation.metric_id,
                    MrtgObservation.metric_revision,
                    MrtgObservation.source_at,
                    MrtgObservation.source_time_text,
                )
                .where(
                    MrtgObservation.service_id == service.id,
                    MrtgObservation.revision == service.revision,
                    MrtgObservation.metric_id.in_(selected),
                    MrtgObservation.observed_at >= start - timedelta(minutes=20),
                    MrtgObservation.observed_at < end,
                )
                .order_by(MrtgObservation.observed_at.desc())
                .limit(20001)
            ).all()
            truncated = len(data) > 20000
            frozen = {}
            for row in data[:20000]:
                if row.source_time_text:
                    key = (row.metric_id, row.source_time_text)
                    frozen[key] = min(frozen.get(key, row.observed_at), row.observed_at)
            checks = []
            for row in data[:20000]:
                if (
                    row.observed_at < start
                    or row.metric_revision != selected[row.metric_id].revision
                ):
                    continue
                fresh = (
                    row.source_at is not None
                    and abs((row.observed_at - row.source_at).total_seconds()) <= 900
                )
                if row.source_time_text and row.observed_at - frozen[
                    (row.metric_id, row.source_time_text)
                ] > timedelta(minutes=15):
                    fresh = False
                checks.append((row.observed_at, row.status == "ok" and fresh, row.metric_id))
        else:
            model = ApacheObservation if service.kind == "apache_status" else ServiceCheck
            data = db.execute(
                select(model.observed_at, model.status)
                .where(
                    model.service_id == service.id,
                    model.revision == service.revision,
                    model.observed_at >= start,
                    model.observed_at < end,
                )
                .order_by(model.observed_at.desc())
                .limit(1001)
            ).all()
            truncated = len(data) > 1000
            checks = [(r.observed_at, r.status == "ok", "source") for r in data[:1000]]
        bins = []
        for index in range(48):
            left, right = (
                start + timedelta(minutes=30 * index),
                start + timedelta(minutes=30 * (index + 1)),
            )
            active = [
                i
                for i in assigned
                if i.opened_at < right and (i.resolved_at is None or i.resolved_at > left)
            ]
            resolved = [i for i in assigned if i.resolved_at and left <= i.resolved_at < right]
            samples = [c for c in checks if left <= c[0] < right]
            good = {
                key: {
                    int(at.timestamp()) // 300 for at, ok, metric in samples if ok and metric == key
                }
                for key in required
            }
            complete = (
                bool(required)
                and all(len(v) >= 5 for v in good.values())
                and all(c[1] for c in samples)
                and not (truncated or partial)
            )
            coverage = "complete" if complete else "partial" if samples else "missing"
            state = (
                "critical"
                if any(i.severity == "critical" for i in active)
                else "warning"
                if active or any(not c[1] for c in samples)
                else "observed"
                if complete
                else "unknown"
            )
            bins.append(
                dict(
                    start=left.isoformat(),
                    end=right.isoformat(),
                    state=state,
                    coverage=coverage,
                    samples=len({int(c[0].timestamp()) // 300 for c in samples}),
                    incidents=len(active),
                    resolved=len(resolved),
                    details=[
                        dict(
                            subject=i.subject,
                            service=service.name,
                            opened_at=i.opened_at.isoformat(),
                            resolved_at=i.resolved_at.isoformat() if i.resolved_at else None,
                            severity=i.severity,
                        )
                        for i in (active or resolved)[:3]
                    ],
                )
            )
        source = source_summary(db, service, parent.archived)
        if service.kind == "mrtg" and source["status"] == "ok":
            latest_checks = {}
            for at, ok, metric in checks:
                latest_checks.setdefault(metric, (at, ok))
            if not required or any(key not in latest_checks for key in required):
                source["status"] = "partial"
            elif any(
                not latest_checks[key][1] or end - latest_checks[key][0] > timedelta(minutes=10)
                for key in required
            ):
                source["status"] = "stale"
        opened = [i for i in assigned if i.status == "open"]
        current = (
            "critical"
            if any(i.severity == "critical" for i in opened)
            else "warning"
            if opened
            else "observed"
            if source["status"] == "ok"
            else "warning"
            if source["status"] in {"error", "partial", "stale"}
            else "unknown"
        )
        if source["status"] in {"paused", "archived"}:
            current = "unknown"
        result.append(
            {
                **source,
                "state": current,
                "bins": bins,
                "partial": truncated,
                "history_note": "El histórico de comprobaciones comienza con esta versión; no se reconstruye a partir de informes antiguos."
                if service.kind == "goaccess"
                else None,
            }
        )
    return result
