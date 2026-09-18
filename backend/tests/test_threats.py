from datetime import timedelta
from types import SimpleNamespace

from sqlalchemy import select
from test_analysis import frame, service

from app.alert_settings import AlertSettings
from app.db import session_factory
from app.models import Incident, now
from app.threats import assess, capture, evaluate, reference_rows


def worker(ip="192.0.2.1", domain="example.test", path="/", **kw):
    return dict(
        client=ip,
        domain=domain,
        state="W",
        observation="current",
        method="POST",
        path=path,
        request_ms=100,
        **kw,
    )


def sample(at, workers, **kw):
    return SimpleNamespace(
        observed_at=at,
        valid=True,
        details={"security": capture(workers)},
        metrics={},
        resources={},
        **kw,
    )


def test_capture_excludes_internal_idle_and_does_not_attribute_keepalive_paths():
    probe = worker("93.93.68.189", path="*", request_protocol="HTTP/1.0")
    probe["method"] = "OPTIONS"
    idle = {**worker(path="/wp-login.php"), "observation": "last_request", "state": "_"}
    keep = {**worker(path="/wp-login.php"), "state": "K"}
    result = capture([probe, idle, keep, worker(path="/.env")])
    assert "93.93.68.189" not in result["ips"]
    assert result["domains"]["example.test"]["active"] == 2
    assert result["ips"]["192.0.2.1"]["sensitive"] == 1
    assert result["ips"]["192.0.2.1"]["req_count"] == 1


def test_personal_baseline_and_concurrent_signals_explain_suspicion():
    at = now()
    rows = [sample(at - timedelta(minutes=5 * (i + 7)), [worker()]) for i in range(40, -1, -1)]
    for i in (3, 2, 1):
        rows.append(
            sample(at - timedelta(minutes=5 * i), [worker(path="/wp-login.php") for _ in range(15)])
        )
    result = assess(sample(at, [worker(path="/wp-login.php") for _ in range(15)]), rows)
    ip = result["ips"][0]
    assert ip["reference"]["median"] == 1
    assert ip["category"] == "posible ataque"
    assert ip["anomaly_persistence"] == 4
    assert ip["deviation"] == 15
    assert any("wp-login.php" in reason for reason in ip["reasons"])
    newcomer = assess(sample(at, [worker(ip="192.0.2.2") for _ in range(50)]), rows)
    assert newcomer["ips"][0]["reference"] is None
    assert newcomer["ips"][0]["category"] == "datos insuficientes"


def test_seasonal_baseline_requires_distinct_days_and_excludes_recent():
    at = now().replace(hour=12, minute=30)
    rows = [
        sample(at - timedelta(days=d, minutes=m), [worker()])
        for d in range(1, 5)
        for m in range(0, 60, 5)
    ]
    refs, label = reference_rows(rows + [sample(at, [])], at)
    # Keep the exact UTC hour; not every half-hour offset is comparable.
    assert all(r.observed_at <= at - timedelta(minutes=30) for r in refs)
    assert len(refs) < 48 or label == "misma hora UTC"


def test_gap_resets_persistence_and_stale_mrtg_is_not_degradation():
    at = now()
    rows = [sample(at - timedelta(minutes=5 * (i + 7)), [worker()]) for i in range(40, -1, -1)]
    current = sample(at, [worker(path="/wp-login.php") for _ in range(15)])
    current.resources = {
        "cpu": {"value": 9999, "basis": "a", "source_at": (at - timedelta(hours=2)).isoformat()}
    }
    result = assess(current, rows)
    assert result["ips"][0]["persistence"] == 1
    assert not result["degradation"]


def test_security_incident_confirmed_once_evolves_and_missing_data_never_resolves():
    with session_factory()() as db:
        svc = service(db)
        at = now()
        for i in range(40, 0, -1):
            old = frame(db, svc, at - timedelta(minutes=30 + 5 * i))
            old.details = {"security": capture([worker()])}
        settings = AlertSettings().model_dump()
        for i in range(3):
            current = frame(db, svc, at + timedelta(minutes=5 * i))
            current.details = {
                "security": capture([worker(path="/wp-login.php") for _ in range(15)])
            }
            evaluate(db, current, settings)
            db.flush()
        incident = db.scalar(
            select(Incident).where(
                Incident.service_id == svc.id, Incident.subject == "security:ips:192.0.2.1"
            )
        )
        assert incident and incident.status == "open"
        db.flush()
        db.expire(current)
        repeated = assess(current, [])
        assert repeated["ips"][0]["active"] == 15
        original_timeline = incident.evidence["timeline"]
        evaluate(db, current, settings)
        assert incident.evidence["timeline"] == original_timeline
        assert len(incident.evidence["timeline"]) == 3
        for i in range(3, 7):
            missing = frame(db, svc, at + timedelta(minutes=5 * i), valid=False)
            evaluate(db, missing, settings)
        assert incident.status == "open"
        for i in range(7, 10):
            normal = frame(db, svc, at + timedelta(minutes=5 * i))
            normal.details = {"security": capture([worker()])}
            evaluate(db, normal, settings)
        assert incident.status == "resolved"
        assert len(incident.evidence["timeline"]) >= 5
        db.rollback()


def test_routine_sensitive_endpoint_use_does_not_open_incidents_without_deviation():
    with session_factory()() as db:
        svc = service(db)
        at = now()
        workers = [worker(path="/wp-admin/admin-ajax.php") for _ in range(15)]
        for i in range(40, 0, -1):
            old = frame(db, svc, at - timedelta(minutes=30 + 5 * i))
            old.details = {"security": capture(workers)}
        for i in range(3):
            current = frame(db, svc, at + timedelta(minutes=i * 5))
            current.details = {"security": capture(workers)}
            evaluate(db, current, AlertSettings().model_dump())
        assert db.scalar(select(Incident).where(Incident.service_id == svc.id)) is None
        db.rollback()
