from datetime import timedelta

from sqlalchemy import select
from test_analysis import frame, service

from app.alert_settings import AlertSettings
from app.analysis import domain_spike, resource_spike
from app.db import session_factory
from app.incident_summary import summarize
from app.incidents import transition
from app.models import (
    AnomalyState,
    ApacheObservation,
    Incident,
    MrtgMetric,
    MrtgObservation,
    Server,
    ServiceCheck,
    now,
)


def test_settings_are_scoped_validated_audited_and_reset_pending_counts(logged_in):
    with session_factory()() as db:
        first, other = service(db), service(db)
        for svc in (first, other):
            db.add(
                AnomalyState(
                    service_id=svc.id, subject="domain:example.test", last_at=now(), bad=1, good=0
                )
            )
        db.commit()
        server_id, other_id = first.server_id, other.server_id
    url = f"/api/v1/servers/{server_id}/alert-settings"
    defaults = logged_in.get(url).json()
    assert defaults["domain_multiplier"] == 3
    values = {**defaults, "domain_multiplier": 5, "open_samples": 4}
    assert logged_in.put(url, json=values).json() == values
    assert logged_in.get(f"/api/v1/servers/{other_id}/alert-settings").json() == defaults
    assert logged_in.put(url, json={**values, "open_samples": 0}).status_code == 422
    assert logged_in.put(url, json={**values, "unknown": 2}).status_code == 422
    with session_factory()() as db:
        states = db.scalars(select(AnomalyState).order_by(AnomalyState.service_id)).all()
        assert sorted(s.bad for s in states) == [0, 1]
        from app.models import AuditEvent, Server

        assert db.get(Server, server_id).alert_settings["revision"] == 1
        assert db.scalar(
            select(AuditEvent).where(AuditEvent.action == "server.alert_settings.update")
        )
    logged_in.headers.pop("x-csrf-token")
    assert logged_in.put(url, json=values).status_code == 403


def test_relative_sensitivity_and_confirmation_are_effective():
    config = AlertSettings(
        domain_multiplier=5,
        memory_drop_percent=70,
        resource_multiplier=4,
        open_samples=3,
        recovery_samples=2,
    ).model_dump()
    reference = {"median": 10, "mad": 0, "samples": 180}
    assert domain_spike(30, reference)
    assert not domain_spike(30, reference, config)
    assert resource_spike(4, reference, "ram_free")
    assert not resource_spike(4, reference, "ram_free", config)
    assert resource_spike(20, reference, "load")
    assert not resource_spike(20, reference, "load", config)
    with session_factory()() as db:
        svc = service(db)
        stamp = now() - timedelta(minutes=25)
        for index, bad in enumerate([True, True, True, False, False]):
            f = frame(db, svc, at=stamp + timedelta(minutes=index * 5))
            transition(
                db,
                f,
                "domain:example.test",
                "domain",
                50,
                reference,
                bad,
                {"alert_settings": config},
            )
            db.flush()
            incident = db.scalar(select(Incident))
            assert (incident is not None) == (index >= 2)
            if incident:
                assert incident.status == ("resolved" if index == 4 else "open")


def test_service_rows_separate_coverage_and_resource_ownership():
    with session_factory()() as db:
        apache = service(db)
        mrtg = service(
            db,
            name="MRTG",
            server=db.get(Server, apache.server_id),
            kind="mrtg",
        )
        goaccess = service(
            db,
            name="GoAccess",
            server=db.get(Server, apache.server_id),
            kind="goaccess",
        )
        other = service(db)
        metric = MrtgMetric(service_id=mrtg.id, name="RAM", url="https://example.test/ram.html")
        db.add(metric)
        db.flush()
        stamp = now()
        for index in range(6):
            at = stamp - timedelta(minutes=1 + index * 5)
            db.add(
                ApacheObservation(
                    service_id=apache.id, revision=1, observed_at=at, status="ok", workers=[]
                )
            )
            db.add(
                MrtgObservation(
                    service_id=mrtg.id,
                    metric_id=metric.id,
                    revision=1,
                    metric_revision=1,
                    observed_at=at,
                    source_at=at,
                    status="ok",
                )
            )
            db.add(ServiceCheck(service_id=goaccess.id, revision=1, observed_at=at, status="stale"))
        db.add(
            Incident(
                server_id=apache.server_id,
                service_id=apache.id,
                subject="resource:ram_free",
                kind="resources",
                status="open",
                severity="warning",
                opened_at=stamp - timedelta(minutes=20),
                updated_at=stamp,
                evidence={"resources": {"ram_free": {"metric_id": metric.id}}},
            )
        )
        db.flush()
        summary = summarize(db, apache.server_id)
        rows = {r["id"]: r for r in summary["rows"]}
        assert other.id not in rows
        assert rows[apache.id]["bins"][-1]["state"] == "observed"
        assert rows[mrtg.id]["bins"][-1]["state"] == "warning"
        assert rows[mrtg.id]["bins"][-1]["details"][0]["subject"] == "resource:ram_free"
        assert not rows[apache.id]["bins"][-1]["details"]
        assert rows[goaccess.id]["bins"][-1]["state"] == "warning"
        assert all(r["bins"][0]["state"] == "unknown" for r in rows.values())
        apache.enabled = False
        db.flush()
        assert (
            next(r for r in summarize(db, apache.server_id)["rows"] if r["id"] == apache.id)[
                "state"
            ]
            == "unknown"
        )
