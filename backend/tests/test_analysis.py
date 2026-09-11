import json
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

from sqlalchemy import func, select

from app import analysis, notifications
from app.config import get_settings
from app.connectors.apache import parse_auto
from app.connectors.mrtg import parse_detail
from app.db import session_factory
from app.incidents import evaluate, transition
from app.models import (
    ApacheObservation,
    EmailDelivery,
    Incident,
    MrtgMetric,
    MrtgObservation,
    NotificationConfig,
    Server,
    ServerFrame,
    Service,
    now,
)


def service(db, name="Apache", server=None, kind="apache_status"):
    server = server or Server(name=str(uuid4()))
    db.add(server)
    db.flush()
    item = Service(
        server_id=server.id, name=name, kind=kind, url="https://web.example.test/server-status"
    )
    db.add(item)
    db.flush()
    return item


def frame(db, svc, at=None, active=2, valid=True, resources=None):
    item = ServerFrame(
        observation_id=str(uuid4()),
        server_id=svc.server_id,
        service_id=svc.id,
        revision=1,
        observed_at=at or now(),
        valid=valid,
        domains={"example.test": {"active": active, "appearances": active}},
        metrics={"free_slots": 900},
        resources=resources or {},
        details={},
        warnings=[],
    )
    db.add(item)
    db.flush()
    return item


def test_scoreboard_and_duration_are_global_not_inferred():
    result = parse_auto("Scoreboard: ..__RWK\nTotal Duration: 1200\nDurationPerReq: 40\nLoad1: 3.5")
    assert result["FreeSlots"] == 2
    assert result["ActiveRequests"] == 2
    assert result["TotalDuration"] == 1200
    assert result["DurationPerReq"] == 40
    assert result["Load1"] == 3.5
    assert "DurationPerReq" not in parse_auto("ReqPerSec: 10")


def test_rankings_distinguish_active_last_requests_and_sensitive_posts(monkeypatch):
    monkeypatch.setattr(analysis, "lookup", lambda ip: {"country": None, "asn": None})
    workers = [
        dict(
            state="W",
            observation="current",
            domain="a.test",
            client="2001:db8::1",
            method="POST",
            path="/wp-login.php",
        ),
        dict(
            state="_",
            observation="last_request",
            domain="a.test",
            client="192.0.2.2",
            method="POST",
            path="/wp-admin/admin-ajax.php",
        ),
        dict(
            state=".",
            observation="last_request",
            domain="a.test",
            client="192.0.2.2",
            method="GET",
            path="/",
        ),
    ]
    domains, details = analysis.rankings(workers)
    assert domains["a.test"] == {"active": 1, "appearances": 2, "posts": 2}
    assert len(details["ips"]) == 1
    assert len(details["posts"]) == 2


def test_relative_reference_requires_coverage_and_own_scale():
    assert analysis.baseline([1] * 169) is None
    ref = analysis.baseline([2] * 170)
    assert analysis.domain_spike(12, ref)
    assert not analysis.domain_spike(12, analysis.baseline([10] * 170))
    assert not analysis.domain_spike(1000, None)
    assert analysis.resource_spike(30, analysis.baseline([100] * 12, 12), "ram_free")


def test_mrtg_physical_memory_label_and_table_fallback():
    html = '<html><title>Memoria Libre</title><!-- cuin d 100 --><!-- cuout d 60 --><h2>Daily Graph</h2><table><tr><th></th><th>Max</th><th>Average</th><th>Current</th></tr><tr class="out"><th>Memoria Fisica Libre</th><td>70 G</td><td>65 G</td><td>60 G</td></tr></table></html>'
    points = parse_detail(html)["values"]
    metric = SimpleNamespace(name="Memoria Libre")
    physical = next(p for p in points if p["channel"] == "out" and p["statistic"] == "current")
    assert analysis.signal(metric, physical) == "ram_free"
    total = next(p for p in points if p["channel"] == "in")
    assert analysis.signal(metric, total) is None
    fallback = {**physical, "source": "table"}
    assert (
        analysis.signal(metric, fallback) == "ram_free"
    )  # Identity comes from the physical-memory label.
    fallback["normalized_value"] = 60e9
    assert analysis.signal(metric, fallback) == "ram_free"


def test_incident_two_bad_three_good_missing_does_not_resolve():
    with session_factory()() as db:
        svc = service(db)
        start = now() - timedelta(minutes=30)
        reference = {"median": 2, "mad": 0, "samples": 170}

        def apply(index, bad, ref=reference):
            f = frame(db, svc, start + timedelta(minutes=index * 5))
            transition(
                db,
                f,
                "domain:example.test",
                "domain",
                12 if bad else 2,
                ref,
                bad,
                {"reference": reference, "feature": "active"},
            )
            db.flush()
            return f

        apply(0, True)
        assert db.scalar(select(func.count()).select_from(Incident)) == 0
        same = apply(1, True)
        incident = db.scalar(select(Incident))
        assert incident.status == "open"
        transition(db, same, "domain:example.test", "domain", 2, reference, False, {})
        apply(2, False)
        apply(3, False, None)
        apply(4, False)
        apply(5, False)
        assert incident.status == "open"
        apply(6, False)
        assert incident.status == "resolved"
        assert (
            db.scalar(select(func.count()).select_from(EmailDelivery)) == 0
        )  # disabled by default


def test_domains_are_isolated_and_free_slots_never_override_ram_pressure(logged_in):
    with session_factory()() as db:
        one = service(db)
        two = service(db, "Other", db.get(Server, one.server_id))
        start = now()

        def resource(value):
            return {"ram_free": {"value": value, "basis": "ram:1:out:bytes", "unit": "bytes"}}

        for index in range(180):
            at = start - timedelta(minutes=35 + 5 * index)
            frame(db, one, at, 2, resources=resource(100))
            frame(db, two, at, 30, resources=resource(100))
        for index in (1, 0):
            at = start - timedelta(minutes=5 * index)
            evaluate(db, frame(db, one, at, 20, resources=resource(30)))
            evaluate(db, frame(db, two, at, 30, resources=resource(100)))
        db.commit()
        items = db.scalars(select(Incident)).all()
        assert len(items) == 2
        assert {i.service_id for i in items} == {one.id}
        server_id = one.server_id
        service_id = one.id
    response = logged_in.get(
        f"/api/v1/servers/{server_id}/analysis",
        params={"service_id": service_id, "domain": "example.test"},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["state"] == "resource_pressure"
    assert result["metrics"]["free_slots"] == 900
    assert result["period_rankings"][0]["appearances"] == 400
    assert result["series"][-1]["domain_active"] == 20


def test_interval_rates_reset_and_unknown_domain_workers(monkeypatch):
    monkeypatch.setattr(analysis, "correlate", lambda *args: ({}, []))
    with session_factory()() as db:
        svc = service(db)
        old = ApacheObservation(
            service_id=svc.id,
            revision=1,
            status="ok",
            observed_at=now() - timedelta(minutes=5),
            metrics={"global": {"Total Accesses": 100, "TotalDuration": 1000, "Uptime": 500}},
            workers=[],
        )
        db.add(old)
        db.flush()
        current = ApacheObservation(
            service_id=svc.id,
            revision=1,
            status="ok",
            observed_at=old.observed_at + timedelta(minutes=5),
            metrics={"global": {"Total Accesses": 400, "TotalDuration": 7000, "Uptime": 800}},
            workers=[dict(state="W", observation="current", client="192.0.2.1")],
            warnings=[],
        )
        db.add(current)
        db.flush()
        f = analysis.build_frame(db, current)
        assert f.metrics["req_per_sec"] == 1
        assert f.metrics["request_ms"] == 20
        assert f.metrics["active_connections"] == 1
        current.metrics = {"global": {"Total Accesses": 1, "Uptime": 1}}
        assert analysis.build_frame(db, current).metrics["req_per_sec"] is None


def test_correlate_excludes_stale_and_separates_servers():
    with session_factory()() as db:
        svc = service(db, kind="mrtg")
        other = service(db, kind="mrtg")
        metric = MrtgMetric(
            service_id=svc.id,
            name="Swap Libre",
            url="https://web.example.test/mrtg/swap.html",
            selected=True,
            present=True,
        )
        db.add(metric)
        db.flush()
        sample = MrtgObservation(
            service_id=svc.id,
            metric_id=metric.id,
            revision=1,
            metric_revision=1,
            status="ok",
            observed_at=now(),
            source_at=now() - timedelta(hours=1),
            values=[
                {
                    "source": "comment",
                    "window": "d",
                    "statistic": "current",
                    "channel": "in",
                    "value": 100,
                }
            ],
        )
        db.add(sample)
        db.flush()
        assert analysis.correlate(db, svc.server_id, now())[0] == {}
        sample.source_at = now()
        db.flush()
        assert analysis.correlate(db, svc.server_id, now())[0]["swap_free"]["value"] == 100
        assert analysis.correlate(db, other.server_id, now())[0] == {}


def test_notifications_private_encrypted_and_csrf(logged_in):
    payload = dict(
        enabled=True,
        host="smtp.example.test",
        sender="monitor@example.test",
        recipient="admin@example.test",
        password="private-smtp-password",
    )
    response = logged_in.put("/api/v1/notifications", json=payload)
    assert response.status_code == 200
    response = logged_in.get("/api/v1/notifications")
    assert response.json()["has_password"] is True
    assert "private-smtp-password" not in response.text
    with session_factory()() as db:
        assert "private-smtp-password" not in db.get(NotificationConfig, 1).encrypted
    logged_in.headers.pop("x-csrf-token")
    assert logged_in.put("/api/v1/notifications", json=payload).status_code == 403


def test_notifications_require_login(client):
    assert client.get("/api/v1/notifications").status_code == 401


def test_mail_cooldown_and_failure_never_retries(monkeypatch):
    from app.incidents import enqueue

    with session_factory()() as db:
        svc = service(db)
        incident = Incident(
            server_id=svc.server_id,
            service_id=svc.id,
            subject="domain:example.test",
            kind="domain",
            status="open",
            severity="warning",
            opened_at=now(),
            updated_at=now(),
            evidence={},
        )
        db.add(incident)
        db.add(
            NotificationConfig(
                id=1,
                encrypted=get_settings()
                .cipher()
                .encrypt(json.dumps({"enabled": True}).encode())
                .decode(),
            )
        )
        db.flush()
        enqueue(db, incident, "opened", now())
        db.flush()
        enqueue(db, incident, "reminder", now() + timedelta(minutes=5))
        db.flush()
        assert db.scalar(select(func.count()).select_from(EmailDelivery)) == 1
        db.commit()
    calls = []

    def fail(*args):
        calls.append(True)
        raise OSError("secret error must not be exposed")

    monkeypatch.setattr(notifications, "send", fail)
    notifications.deliver()
    notifications.deliver()
    assert len(calls) == 1
    with session_factory()() as db:
        item = db.scalar(select(EmailDelivery))
        assert item.status == "uncertain"
        assert "secret" not in item.error


def test_mrtg_pressure_detected_when_apache_is_incomplete():
    with session_factory()() as db:
        svc = service(db)
        start = now()
        for index in range(12):
            frame(
                db,
                svc,
                start - timedelta(minutes=35 + index * 5),
                resources={"ram_free": {"value": 100, "basis": "ram"}},
            )
        for index in (1, 0):
            evaluate(
                db,
                frame(
                    db,
                    svc,
                    start - timedelta(minutes=index * 5),
                    valid=False,
                    resources={"ram_free": {"value": 20, "basis": "ram"}},
                ),
            )
        db.flush()
        incident = db.scalar(select(Incident))
        assert incident is not None
        assert incident.subject == "resource:ram_free"


def test_missing_sample_breaks_consecutive_recovery():
    with session_factory()() as db:
        svc = service(db)
        start = now()
        for index in range(180):
            frame(db, svc, start - timedelta(minutes=35 + index * 5))
        for index in (0, 1):
            evaluate(db, frame(db, svc, start + timedelta(minutes=index * 5), active=20))
        incident = db.scalar(select(Incident))
        assert incident.status == "open"
        evaluate(db, frame(db, svc, start + timedelta(minutes=10)))
        evaluate(db, frame(db, svc, start + timedelta(minutes=15), valid=False))
        evaluate(db, frame(db, svc, start + timedelta(minutes=20)))
        evaluate(db, frame(db, svc, start + timedelta(minutes=25)))
        assert incident.status == "open"
        evaluate(db, frame(db, svc, start + timedelta(minutes=30)))
        assert incident.status == "resolved"


def test_analysis_restart_is_idempotent(monkeypatch):
    monkeypatch.setattr(analysis, "correlate", lambda *args: ({}, []))
    with session_factory()() as db:
        svc = service(db)
        db.add(
            ApacheObservation(
                service_id=svc.id,
                revision=1,
                status="ok",
                observed_at=now() - timedelta(minutes=5),
                metrics={},
                workers=[],
                warnings=[],
            )
        )
        db.commit()
    analysis.run()
    analysis.run()
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(ServerFrame)) == 1


def test_retention_removes_ip_path_evidence():
    with session_factory()() as db:
        svc = service(db)
        old = frame(db, svc, now() - timedelta(days=31))
        old.details = {"ips": [{"ip": "192.0.2.1"}]}
        expired = frame(db, svc, now() - timedelta(days=91))
        old_id, expired_id = old.id, expired.id
        db.commit()
    analysis.retention()
    with session_factory()() as db:
        assert db.get(ServerFrame, old_id).details is None
        assert db.get(ServerFrame, expired_id) is None


def test_old_encrypted_sources_supply_new_metadata_without_extra_fetches():
    with session_factory()() as db:
        svc = service(db, kind="mrtg")
        metric = MrtgMetric(
            service_id=svc.id, name="Memoria Libre", url="https://web.example.test/mrtg/memory.html"
        )
        db.add(metric)
        db.flush()
        body = '<html><title>Memoria Libre</title><!-- cuout d 60 --><h2>Daily Graph</h2><table><tr><th></th><th>Max</th><th>Average</th><th>Current</th></tr><tr class="out"><th>Memoria Fisica</th><td>70 G</td><td>65 G</td><td>60 G</td></tr></table></html>'
        db.add(
            MrtgObservation(
                service_id=svc.id,
                metric_id=metric.id,
                revision=1,
                metric_revision=1,
                status="partial",
                observed_at=now(),
                values=[
                    dict(window="d", channel="out", statistic="current", source="comment", value=60)
                ],
                raw_encrypted=get_settings().cipher().encrypt(body.encode()).decode(),
            )
        )
        db.flush()
        assert analysis.correlate(db, svc.server_id, now())[0]["ram_free"]["value"] == 60
        old = ApacheObservation(
            metrics={"global": {"ReqPerSec": 20}},
            raw_encrypted=get_settings()
            .cipher()
            .encrypt(json.dumps({"auto": "Scoreboard: .._W\nTotal Duration: 500"}).encode())
            .decode(),
        )
        assert analysis.apache_globals(old)["FreeSlots"] == 2
        assert analysis.apache_globals(old)["TotalDuration"] == 500
        assert (
            analysis.signal(
                SimpleNamespace(name="Procesos SSH ejecutandose"),
                dict(window="d", channel="in", statistic="current", source="comment", value=3),
            )
            is None
        )


def test_compact_timeline_is_scoped_and_never_marks_missing_data_healthy():
    from app.incident_summary import summarize

    with session_factory()() as db:
        svc = service(db)
        other = service(db)
        stamp = now()
        db.add(
            Incident(
                server_id=svc.server_id,
                service_id=svc.id,
                subject="domain:example.test",
                kind="domain",
                status="open",
                severity="critical",
                opened_at=stamp - timedelta(minutes=45),
                updated_at=stamp,
                evidence={},
            )
        )
        db.add(
            Incident(
                server_id=svc.server_id,
                service_id=svc.id,
                subject="resource:ram_free",
                kind="resources",
                status="resolved",
                severity="warning",
                opened_at=stamp - timedelta(hours=3),
                updated_at=stamp - timedelta(hours=2),
                resolved_at=stamp - timedelta(hours=2),
                evidence={},
            )
        )
        db.flush()
        summary = summarize(db, svc.server_id)
        assert summary["open"] == 1
        assert summary["critical"] == 1
        assert summary["resolved"] == 1
        assert len(summary["bins"]) == 48
        assert summary["bins"][-1]["state"] == "critical"
        assert summary["bins"][-1]["coverage"] == "missing"
        assert summary["bins"][0]["state"] == "unknown"
        assert summary["bins"][-1]["details"][0]["subject"] == "domain:example.test"
        assert summarize(db, other.server_id)["open"] == 0
