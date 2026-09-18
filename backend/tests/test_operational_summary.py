from datetime import timedelta

from test_analysis import frame, service

from app.db import session_factory
from app.models import Incident, now
from app.operational_summary import build_monitors


def point(at, value=100, capacity=None):
    result = {
        "value": value,
        "unit": "bytes",
        "basis": "metric:1:in:comment:bytes",
        "observed_at": at.isoformat(),
        "source_at": at.isoformat(),
        "provenance": "MRTG de prueba",
    }
    if capacity is not None:
        result["capacity"] = capacity
    return result


def test_resource_monitors_do_not_inherit_other_source_or_resource_alerts(monkeypatch):
    with session_factory()() as db:
        svc = service(db)
        stamp = now()
        for index in range(181):
            at = stamp - timedelta(minutes=1 + index * 5)
            sample = frame(
                db,
                svc,
                at=at,
                resources={
                    "ram_free": point(at),
                    "swap_free": point(at, capacity=100),
                    "cpu": point(at),
                    "load": point(at),
                },
            )
            sample.details = {
                "ips": [{"ip": "192.0.2.1", "count": 2, "organization": "Proveedor de prueba"}]
            }
        incident = Incident(
            server_id=svc.server_id,
            service_id=svc.id,
            subject="resource:ram_free",
            kind="resources",
            status="open",
            severity="warning",
            opened_at=stamp - timedelta(minutes=15),
            updated_at=stamp,
            evidence={},
        )
        db.add(incident)
        db.flush()
        monkeypatch.setattr(
            "app.operational_summary.correlate",
            lambda *args: (
                {
                    "ram_free": point(stamp, 20),
                    "swap_free": point(stamp, capacity=100),
                    "cpu": point(stamp),
                    "load": point(stamp),
                },
                [],
            ),
        )
        rows = {
            r["id"]: r
            for r in build_monitors(
                db, svc.server_id, stamp - timedelta(hours=24), stamp, [incident]
            )
        }
        assert set(rows) == {"ram_free", "swap_free", "cpu", "load", "domains", "ips", "latency"}
        assert rows["ram_free"]["state"] == "warning"
        assert rows["ram_free"]["display_bytes"] == 20
        assert rows["swap_free"]["state"] == "observed"
        assert rows["cpu"]["state"] == "observed"
        assert rows["load"]["state"] == "observed"
        assert rows["domains"]["state"] == "observed"
        assert rows["ips"]["state"] == "informational"
        assert "Proveedor de prueba" in rows["ips"]["context"][0]["text"]
        assert rows["ram_free"]["bins"][-1]["state"] == "warning"
        assert rows["cpu"]["bins"][-1]["state"] == "observed"


def test_swap_readings_are_separate_from_unknown_capacity_and_missing_resources(monkeypatch):
    with session_factory()() as db:
        svc = service(db)
        stamp = now()
        for index in range(6):
            at = stamp - timedelta(minutes=1 + index * 5)
            frame(db, svc, at=at, resources={"swap_free": point(at)})
        monkeypatch.setattr(
            "app.operational_summary.correlate", lambda *args: ({"swap_free": point(stamp)}, [])
        )
        rows = {
            r["id"]: r
            for r in build_monitors(db, svc.server_id, stamp - timedelta(hours=24), stamp, [])
        }
        assert rows["swap_free"]["state"] == "learning"
        assert rows["swap_free"]["status_text"] == "Aprendiendo swap libre"
        assert rows["swap_free"]["bins"][-1]["state"] == "observed"
        assert rows["ram_free"]["value"] is None
        assert rows["ram_free"]["state"] == "unknown"
        assert rows["domains"]["state"] == "learning"


def test_confirmed_swap_use_is_red_without_claiming_an_attack(monkeypatch):
    with session_factory()() as db:
        svc = service(db)
        stamp = now()
        monkeypatch.setattr(
            "app.operational_summary.correlate",
            lambda *args: ({"swap_free": point(stamp, 99, 100)}, []),
        )
        rows = {
            r["id"]: r
            for r in build_monitors(db, svc.server_id, stamp - timedelta(hours=24), stamp, [])
        }
        assert rows["swap_free"]["state"] == "critical"
        assert rows["swap_free"]["status_text"] == "Swap en uso"
        assert rows["ips"]["state"] == "unknown"


def test_domain_and_ip_evidence_are_scoped_and_stale_data_is_visible(monkeypatch):
    with session_factory()() as db:
        svc = service(db)
        other = service(db)
        stamp = now()
        f = frame(db, svc, at=stamp - timedelta(minutes=15))
        f.details = {"ips": [{"ip": "192.0.2.1", "count": 2}]}
        frame(db, other, at=stamp - timedelta(minutes=1), active=999)
        incident = Incident(
            server_id=svc.server_id,
            service_id=svc.id,
            subject="domain:example.test",
            kind="domain",
            status="open",
            severity="critical",
            opened_at=stamp - timedelta(minutes=20),
            updated_at=stamp,
            evidence={"coincidences": {"ips": [{"ip": "192.0.2.1", "count": 2}]}},
        )
        db.add(incident)
        db.flush()
        monkeypatch.setattr("app.operational_summary.correlate", lambda *args: ({}, []))
        rows = {
            r["id"]: r
            for r in build_monitors(
                db, svc.server_id, stamp - timedelta(hours=24), stamp, [incident]
            )
        }
        assert rows["domains"]["state"] == "critical"
        assert rows["domains"]["value"] is None
        assert rows["ips"]["state"] == "warning"
        assert rows["ips"]["value"] is None
        assert rows["ips"]["context"][0]["label"] == "IP durante un aviso: 192.0.2.1"
        assert rows["ram_free"]["state"] == "unknown"
        svc.enabled = False
        db.flush()
        rows = build_monitors(db, svc.server_id, stamp - timedelta(hours=24), stamp, [])
        assert all(r["state"] == "unknown" for r in rows)


def test_resource_correlation_ignores_superseded_metric_configuration():
    from app.analysis import correlate
    from app.models import MrtgMetric, MrtgObservation

    with session_factory()() as db:
        svc = service(db, kind="mrtg")
        metric = MrtgMetric(
            service_id=svc.id, name="CPU", url="https://web.example.test/cpu.html", revision=2
        )
        db.add(metric)
        db.flush()
        db.add(
            MrtgObservation(
                service_id=svc.id,
                metric_id=metric.id,
                revision=1,
                metric_revision=1,
                observed_at=now(),
                status="ok",
                values=[
                    {
                        "window": "d",
                        "statistic": "current",
                        "channel": "in",
                        "source": "comment",
                        "value": 10,
                    }
                ],
            )
        )
        db.flush()
        resources, _ = correlate(db, svc.server_id, now())
        assert "cpu" not in resources


def test_domain_ranking_preserves_service_scope_gaps_and_invalid_latest():
    from types import SimpleNamespace

    from app.operational_summary import domain_ranking

    end = now()
    start = end - timedelta(hours=24)
    services = {1: SimpleNamespace(name="Apache A"), 2: SimpleNamespace(name="Apache B")}

    def sample(sid, minutes, domains, valid=True):
        return SimpleNamespace(
            service_id=sid,
            observed_at=end - timedelta(minutes=minutes),
            domains=domains,
            valid=valid,
        )

    frames = [
        sample(1, 10, {"example.test": {"active": 8}}),
        sample(1, 5, {}),
        sample(1, 1, {}, False),
        sample(2, 5, {"example.test": {"active": 2}}),
    ]
    rows = domain_ranking(frames, services, start, end)
    assert len(rows) == 2
    assert rows[0]["service"] == "Apache A"
    assert rows[0]["average"] == 4
    assert rows[0]["peak"] == 8
    assert rows[0]["current"] is None
    assert rows[0]["bins"][0]["value"] is None
    assert rows[0]["bins"][-1]["value"] == 4
    assert rows[1]["average"] == 2
    assert rows[1]["current"] == 2
