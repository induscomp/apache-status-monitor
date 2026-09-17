from datetime import timedelta
from types import SimpleNamespace

from sqlalchemy import select
from test_analysis import frame, service

from app.analysis import rankings
from app.db import session_factory
from app.incidents import evaluate
from app.models import Incident, Server, now
from app.performance import context, internal, sample_metrics, stats


def worker(**extra):
    return dict(
        state="W",
        client="192.0.2.1",
        domain="example.test",
        method="GET",
        path="/",
        request_ms=100,
        observation="current",
        **extra,
    )


def test_internal_probe_is_excluded_without_excluding_other_requests_from_same_ip():
    probe = {
        **worker(),
        "client": "93.93.68.189",
        "method": "OPTIONS",
        "path": "*",
        "request_protocol": "HTTP/1.0",
    }
    assert internal(probe)
    real = {**probe, "method": "GET", "path": "/real"}
    other = {**probe, "client": "192.0.2.2"}
    assert not internal(real) and not internal(other)
    domains, details = rankings([probe, real, other])
    assert domains["example.test"]["active"] == 2
    metrics = sample_metrics([probe, real, other], domains)
    assert metrics["internal_workers"] == 1
    assert domains["example.test"]["req_count"] == 2
    assert sum(p["count"] for p in details["urls"]) == 2


def test_req_percentile_requires_twenty_values_and_ignores_idle_and_h2_session():
    workers = [{**worker(), "request_ms": v} for v in range(1, 21)]
    workers += [
        {**worker(), "state": "_", "request_ms": 99999},
        {**worker(), "request_kind": "h2_session", "method": None, "request_ms": 99999},
    ]
    domains, _ = rankings(workers)
    values = sample_metrics(workers, domains)
    assert values["active_req_count"] == 20
    assert domains["example.test"]["req_mean"] == 10.5
    assert domains["example.test"]["req_max"] == 20
    assert domains["example.test"]["req_p95"] == 19
    assert stats(list(range(19)))["req_p95"] is None


def resource(at, value, basis):
    return {
        "value": value,
        "basis": basis,
        "source_at": at.isoformat(),
        "observed_at": at.isoformat(),
    }


def test_latency_opens_with_available_resources_and_gaps_never_resolve():
    with session_factory()() as db:
        svc = service(db)
        at = now()
        for i in range(180):
            stamp = at - timedelta(minutes=35 + 5 * i)
            f = frame(
                db,
                svc,
                at=stamp,
                resources={"cpu": resource(stamp, 20, "cpu"), "load": resource(stamp, 1, "load")},
            )
            f.metrics = {
                "performance_version": 1,
                "request_ms": 100,
                "internal_workers": 0,
                "idle_workers": 250,
                "free_slots": 750,
            }
            f.domains = {
                "example.test": {
                    "active": 2,
                    "appearances": 2,
                    "req_count": 2,
                    "req_mean": 100,
                    "req_max": 100,
                    "req_p95": None,
                }
            }
        for i in range(2):
            stamp = at + timedelta(minutes=5 * i)
            f = frame(
                db,
                svc,
                at=stamp,
                resources={"cpu": resource(stamp, 20, "cpu"), "load": resource(stamp, 1, "load")},
            )
            f.metrics = {
                "performance_version": 1,
                "request_ms": 500,
                "internal_workers": 0,
                "idle_workers": 250,
                "free_slots": 750,
            }
            f.domains = {
                "example.test": {
                    "active": 2,
                    "appearances": 2,
                    "req_count": 2,
                    "req_mean": 600,
                    "req_max": 700,
                    "req_p95": None,
                }
            }
            db.flush()
            evaluate(db, f)
            db.flush()
        incidents = db.scalars(select(Incident).where(Incident.kind == "performance")).all()
        assert len(incidents) == 2
        assert all(i.severity == "warning" for i in incidents)
        assert all(i.evidence["performance_context"]["apparently_available"] for i in incidents)
        # Neither failed collection nor an absent domain is a recovery sample.
        for i in range(3):
            f = frame(db, svc, at=at + timedelta(minutes=10 + 5 * i), valid=False)
            db.flush()
            evaluate(db, f)
            db.flush()
        assert all(i.status == "open" for i in incidents)
        for i in range(3):
            f = frame(db, svc, at=at + timedelta(minutes=25 + 5 * i))
            f.metrics = {"performance_version": 1, "request_ms": 100, "internal_workers": 0}
            f.domains = {
                "example.test": {
                    "active": 2,
                    "appearances": 2,
                    "req_count": 1,
                    "req_mean": 100,
                    "req_max": 100,
                }
            }
            db.flush()
            evaluate(db, f)
            db.flush()
        assert all(i.status == "resolved" for i in incidents)


def test_no_baseline_or_stale_cpu_cannot_prove_available_resources():
    stamp = now()
    f = SimpleNamespace(
        observed_at=stamp,
        metrics={"idle_workers": 1000, "free_slots": 1000},
        resources={
            "cpu": resource(stamp - timedelta(hours=1), 1, "cpu"),
            "load": resource(stamp, 1, "load"),
        },
    )
    assert not context(f, [])["apparently_available"]


def test_latency_is_scoped_to_service_and_requires_history():
    with session_factory()() as db:
        a = service(db)
        b = service(db, name="Other Apache", server=db.get(Server, a.server_id))
        at = now()
        for i in range(30):
            f = frame(db, a, at=at - timedelta(minutes=35 + 5 * i))
            f.metrics = {"performance_version": 1}
            f.domains = {
                "example.test": {"active": 1, "appearances": 1, "req_count": 1, "req_mean": 10}
            }
        for i in range(2):
            f = frame(db, b, at=at + timedelta(minutes=5 * i))
            f.metrics = {"performance_version": 1, "request_ms": 99999}
            f.domains = {
                "example.test": {"active": 1, "appearances": 1, "req_count": 1, "req_mean": 99999}
            }
            db.flush()
            evaluate(db, f)
            db.flush()
        assert not db.scalars(select(Incident).where(Incident.kind == "performance")).all()


def test_internal_identity_is_read_from_exact_request_line():
    from test_apache import HTML

    from app.connectors.apache import parse_html

    source = HTML.replace("2001:db8::1", "93.93.68.189").replace(
        "GET /page?secret=value#part HTTP/1.1", "OPTIONS * HTTP/1.0"
    )
    parsed = parse_html(source)
    assert parsed["workers"][0]["internal"]
    domains, _ = rankings(parsed["workers"])
    assert domains["same.example"]["active"] == 0
    other = parse_html(source.replace("OPTIONS * HTTP/1.0", "OPTIONS * HTTP/1.1"))
    assert not internal(other["workers"][0])


def test_rebuild_retained_frames_is_idempotent_and_does_not_replay_alerts():
    from app.models import ApacheObservation, ServerFrame
    from app.performance_backfill import main

    with session_factory()() as db:
        svc = service(db)
        probe = {**worker(), "client": "93.93.68.189", "method": "OPTIONS", "path": "*"}
        observation = ApacheObservation(
            service_id=svc.id,
            revision=1,
            status="ok",
            workers=[probe, worker()],
            metrics={"global": {"BusyWorkers": 2}},
        )
        db.add(observation)
        db.flush()
        f = frame(db, svc)
        f.observation_id = observation.id
        key = f.id
        db.commit()
    main()
    main()
    with session_factory()() as db:
        f = db.get(ServerFrame, key)
        assert f.metrics["internal_workers"] == 1
        assert f.metrics["active_connections"] == 1
        assert f.domains["example.test"]["req_count"] == 1
        assert f.domains["example.test"]["req_mean"] == 100
        assert not db.scalars(select(Incident)).all()
