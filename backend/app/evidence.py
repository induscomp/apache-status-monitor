"""Scope incident visitors to the actual domain and retained observation."""

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import defer

from app.models import ApacheObservation, now


def domain_evidence(db, frame, domain):
    from app.analysis import rankings

    if not frame or frame.observed_at < now() - timedelta(days=30):
        return {"scope": "unavailable", "ips": [], "urls": [], "posts": []}
    observation = db.scalar(
        select(ApacheObservation)
        .options(defer(ApacheObservation.raw_encrypted))
        .where(ApacheObservation.id == frame.observation_id)
    )
    if not observation or observation.service_id != frame.service_id or observation.workers is None:
        return {"scope": "unavailable", "ips": [], "urls": [], "posts": []}
    _, result = rankings([w for w in observation.workers if w.get("domain") == domain])
    return {**result, "scope": "domain"}
