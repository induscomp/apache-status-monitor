"""Recompute retained client aggregates without replaying alerts or modifying originals."""

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import defer

from app.analysis import rankings
from app.db import session_factory
from app.models import ApacheObservation, AuditEvent, ServerFrame, now
from app.performance import internal, sample_metrics


def main():
    count = 0
    with session_factory()() as db:
        ids = db.scalars(
            select(ServerFrame.id)
            .where(ServerFrame.observed_at >= now() - timedelta(days=30))
            .order_by(ServerFrame.observed_at)
        ).all()
        for key in ids:
            frame = db.get(ServerFrame, key)
            observation = db.get(
                ApacheObservation,
                frame.observation_id,
                options=[defer(ApacheObservation.raw_encrypted)],
            )
            if not observation or observation.workers is None:
                continue
            if frame.metrics.get("performance_version") == 1:
                from app.threats import capture

                if (frame.details or {}).get("security", {}).get("version") != 1:
                    frame.details = {
                        **(frame.details or {}),
                        "security": capture(observation.workers),
                    }
                    count += 1
                    if count % 100 == 0:
                        db.commit()
                        db.expire_all()
                continue
            domains, details = rankings(observation.workers)
            frame.domains = domains
            from app.threats import capture

            frame.details = {**details, "security": capture(observation.workers)}
            frame.metrics = {
                **frame.metrics,
                **sample_metrics(observation.workers, domains),
                "busy_workers": observation.metrics.get("global", {}).get("BusyWorkers"),
                "active_connections": sum(
                    w.get("observation") == "current"
                    and bool(w.get("client"))
                    and w["state"] not in {".", "I", "S"}
                    and not internal(w)
                    for w in observation.workers
                ),
            }
            count += 1
            if count % 100 == 0:
                db.commit()
                db.expire_all()
        db.add(AuditEvent(action="performance.rebuild-retained-aggregates", target_id=str(count)))
        db.commit()
    print("Retained frames rebuilt:", count, "No email or incident replay.")


if __name__ == "__main__":
    main()
