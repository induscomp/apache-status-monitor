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
    return {
        "start": start.isoformat(),
        "end": end.isoformat(),
        "partial": partial,
        "open": sum(i.status == "open" for i in incidents),
        "critical": sum(i.status == "open" and i.severity == "critical" for i in incidents),
        "resolved": sum(i.resolved_at is not None and i.resolved_at >= start for i in incidents),
        "bins": bins,
    }
