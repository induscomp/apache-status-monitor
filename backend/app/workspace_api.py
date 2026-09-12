from datetime import timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session, defer

from app.collection import latest
from app.db import get_db
from app.goaccess import status as goaccess_status
from app.models import Incident, Server, Service, now
from app.mrtg_collection import service_status as mrtg_status
from app.security import authenticated

router = APIRouter()


def source_summary(db, service, parent_archived=False):
    last_at = None
    status = "waiting"
    if service.kind == "apache_status":
        sample = latest(db, service.id)
        if sample:
            last_at = sample.observed_at
            status = (
                sample.status
                if sample.revision == service.revision and now() - last_at <= timedelta(minutes=10)
                else "stale"
            )
    elif service.kind == "mrtg":
        status, sample, _ = mrtg_status(db, service)
        last_at = sample.observed_at if sample else None
    elif service.kind == "goaccess":
        from app.models import GoAccessState

        status = goaccess_status(db, service)
        state = db.get(GoAccessState, service.id)
        last_at = state.observed_at if state else None
    if parent_archived or service.archived:
        status = "archived"
    elif not service.enabled:
        status = "paused"
    return {
        "id": service.id,
        "name": service.name,
        "kind": service.kind,
        "status": status,
        "last_at": last_at,
    }


@router.get("/dashboard")
def dashboard(
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=50),
    auth=Depends(authenticated),
    db: Session = Depends(get_db),
):
    servers = db.scalars(
        select(Server).order_by(Server.created_at, Server.id).offset(offset).limit(limit)
    ).all()
    items = []
    for server in servers:
        sources = [
            source_summary(db, s, server.archived)
            for s in db.scalars(
                select(Service).where(Service.server_id == server.id).order_by(Service.created_at)
            )
        ]
        active = [s for s in sources if s["status"] not in {"paused", "archived"}]
        incidents = db.scalar(
            select(func.count())
            .select_from(Incident)
            .where(Incident.server_id == server.id, Incident.status == "open")
        )
        state = (
            "archived"
            if server.archived
            else "incident"
            if incidents
            else "attention"
            if any(s["status"] in {"error", "partial", "stale"} for s in active)
            else "waiting"
            if not active or any(s["status"] == "waiting" for s in active)
            else "observing"
        )
        items.append(
            {
                "id": server.id,
                "name": server.name,
                "description": server.description,
                "state": state,
                "open_incidents": incidents,
                "sources": sources,
            }
        )
    return {
        "items": items,
        "total": db.scalar(select(func.count()).select_from(Server)),
        "open_incidents": db.scalar(
            select(func.count()).select_from(Incident).where(Incident.status == "open")
        ),
    }


def mrtg_only_series(db, server_id, hours):
    """Independent numeric history when a server publishes no Apache table."""
    import re

    from app.analysis import signal
    from app.models import MrtgMetric, MrtgObservation

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
    by_id = {m.id: m for m in metrics}
    if not by_id:
        return []
    end = now()
    rows = db.scalars(
        select(MrtgObservation)
        .options(defer(MrtgObservation.raw_encrypted))
        .join(MrtgMetric, MrtgObservation.metric_id == MrtgMetric.id)
        .join(Service, MrtgObservation.service_id == Service.id)
        .where(
            MrtgObservation.revision == Service.revision,
            MrtgObservation.metric_revision == MrtgMetric.revision,
            MrtgObservation.metric_id.in_(by_id),
            MrtgObservation.observed_at >= end - timedelta(hours=hours, minutes=20),
            MrtgObservation.status != "error",
        )
        .order_by(MrtgObservation.observed_at.desc())
        .limit(6000)
    ).all()
    frozen = {}
    for row in rows:
        if row.source_time_text:
            key = (row.metric_id, row.source_time_text)
            frozen[key] = min(frozen.get(key, row.observed_at), row.observed_at)
    buckets = {}
    role_metrics = {}
    for row in sorted(rows, key=lambda r: r.observed_at):
        if row.observed_at < end - timedelta(hours=hours) or (
            row.source_at and abs((row.observed_at - row.source_at).total_seconds()) > 900
        ):
            continue
        if row.source_time_text and row.observed_at - frozen[
            (row.metric_id, row.source_time_text)
        ] > timedelta(minutes=15):
            continue
        bucket = int(row.observed_at.timestamp()) // 300
        item = buckets.setdefault(bucket, {"at": row.observed_at.isoformat()})
        comment_roles = {
            signal(by_id[row.metric_id], p) for p in row.values if p["source"] == "comment"
        }
        for point in row.values:
            role = signal(by_id[row.metric_id], point)
            if role and (point["source"] == "comment" or role not in comment_roles):
                # Keep one metric per role throughout a series; don't splice servers'
                # alternative sources or differently scaled metrics into one line.
                role_metrics.setdefault(role, row.metric_id)
                if role_metrics[role] != row.metric_id:
                    continue
                factor = 1
                if point["source"] == "table":
                    prefix = re.match(r"^([kMGT])(?:B|b|bytes|$)", point.get("source_unit") or "")
                    if prefix:
                        factor = {"k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}[prefix[1]]
                value = point.get("normalized_value", point["value"] * factor)
                if (
                    role == "load"
                    and "normalized_value" not in point
                    and re.search(r"[*×]\s*100\b", by_id[row.metric_id].name)
                ):
                    value /= 100
                item[role] = value
    # Materialize gaps; no interpolated history or false zeros.
    if not buckets:
        return []
    from datetime import UTC, datetime

    return [
        buckets.get(b, {"at": datetime.fromtimestamp(b * 300, UTC).isoformat()})
        for b in range(min(buckets), max(buckets) + 1)
    ]
