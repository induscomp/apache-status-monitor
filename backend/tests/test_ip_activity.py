from datetime import timedelta
from types import SimpleNamespace

from sqlalchemy import select
from test_analysis import frame, service

from app.alert_settings import AlertSettings
from app.db import session_factory
from app.ip_activity import WINDOWS, aggregate, analyze, evaluate, network, traces
from app.models import Incident, now
from app.threats import capture


def worker(ip="192.0.2.1", path="/.env", slot="1", state="W", age=0):
    return dict(
        client=ip,
        domain="example.test",
        path=path,
        method="GET",
        slot=slot,
        state=state,
        seconds_since=age,
        observation="last_request" if state == "_" else "current",
        request_ms=1,
    )


def snapshot(at, workers, valid=True):
    return SimpleNamespace(observed_at=at, valid=valid, details={"security": capture(workers)})


def test_retained_requests_are_separate_and_old_undated_internal_are_excluded():
    probe = {**worker("93.93.68.189", "*"), "method": "OPTIONS", "request_protocol": "HTTP/1.0"}
    result = traces(
        [probe, worker(state="_", age=301), worker(state="_", age=None), worker(state="_", age=10)]
    )
    assert len(result) == 1 and result[0]["previous"]
    at = now()
    frames = [
        snapshot(at - timedelta(minutes=5), [worker(state="_", age=10)]),
        snapshot(at, [worker(state="_", age=200)]),
    ]
    row = aggregate(frames)["ips"]["192.0.2.1"]
    assert row["signatures"] == 1 and row["retained"] == 1
    assert sum(row["active_by_sample"].values()) == 0


def test_exact_windows_ipv4_ipv6_and_network_shared_target_evidence():
    at = now()
    frames = [
        snapshot(
            at - timedelta(minutes=5 * i),
            [worker("192.0.2.1", slot=str(i)), worker("192.0.2.2", slot=str(i + 20))],
        )
        for i in range(11, -1, -1)
    ]
    for m in WINDOWS:
        result = analyze(frames, at, m)
        assert result["samples"] == m // 5 and result["coverage"] == 1
        row = result["networks"][0]
        assert row["key"] == "192.0.2.0/24" and len(row["ips"]) == 2
        assert row["shared"][0]["target"] == "example.test · GET /.env"
        assert row["flagged"]
    assert network("2001:db8:1234::1") == "2001:db8:1234::/64"
    assert network("192.0.3.2") != network("192.0.2.1")


def test_neighbors_alone_and_normal_ajax_do_not_indicate_coordination():
    at = now()
    rows = [
        snapshot(
            at, [worker(path="/wp-admin/admin-ajax.php"), worker("192.0.2.2", path="/wp-login.php")]
        )
    ]
    result = analyze(rows, at, 5)
    assert all(not r["flagged"] for g in ("ips", "networks") for r in result[g])
    assert not result["networks"][0]["shared"]
    missing = analyze(rows, at, 60)
    assert missing["coverage"] < 1


def test_equal_window_baselines_and_service_isolation():
    at = now()
    rows = [snapshot(at - timedelta(minutes=5 * i), [worker(path="/")]) for i in range(100, 11, -1)]
    rows.append(snapshot(at, [worker(path="/wp-login.php", slot=str(i)) for i in range(20)]))
    result = analyze(rows, at, 5)
    assert result["ips"][0]["reference"]["median"] == 1
    assert result["ips"][0]["flagged"]
    unknown = analyze([rows[-1]], at, 5)
    assert unknown["ips"][0]["reference"] is None
    assert not unknown["ips"][0]["flagged"]


def test_overlapping_windows_are_not_independent_confirmation_and_failures_do_not_resolve():
    with session_factory()() as db:
        svc = service(db)
        at = now()
        rows = []
        for i in range(12, 0, -1):
            old = frame(db, svc, at - timedelta(minutes=i * 5))
            old.details = {"security": capture([])}
            rows.append(old)
        current = frame(db, svc, at)
        current.details = {
            "security": capture([worker(path="/.env"), worker(path="/.git/config", slot="2")])
        }
        settings = AlertSettings().model_dump()
        evaluate(db, current, rows, settings)
        rows.append(current)
        repeated = frame(db, svc, at + timedelta(minutes=5))
        repeated.details = current.details
        evaluate(db, repeated, rows, settings)
        assert db.scalar(select(Incident).where(Incident.service_id == svc.id)) is None
        rows.append(repeated)
        for j in (2, 3):
            fresh = frame(db, svc, at + timedelta(minutes=j * 5))
            fresh.details = {
                "security": capture(
                    [
                        worker(path="/.env", slot=str(j + 10)),
                        worker(path="/.git/config", slot=str(j + 20)),
                    ]
                )
            }
            evaluate(db, fresh, rows, settings)
            rows.append(fresh)
        incident = db.scalar(select(Incident).where(Incident.service_id == svc.id))
        assert incident and incident.status == "open"
        for j in (4, 5, 6):
            missing = frame(db, svc, at + timedelta(minutes=j * 5), valid=False)
            evaluate(db, missing, rows, settings)
            rows.append(missing)
        assert incident.status == "open"
        db.rollback()


def test_repeated_login_posts_are_visible_without_own_history_but_ajax_is_not_a_probe():
    at = now()
    login = [{**worker(path="/wp-login.php", slot=str(i)), "method": "POST"} for i in range(3)]
    rows = [snapshot(at - timedelta(minutes=5), login[:2]), snapshot(at, login[2:])]
    result = analyze(rows, at, 10)
    assert result["ips"][0]["flagged"] and result["ips"][0]["reference"] is None
    ajax = [{**w, "path": "/wp-admin/admin-ajax.php"} for w in login]
    rows = [snapshot(at - timedelta(minutes=5), ajax[:2]), snapshot(at, ajax[2:])]
    assert not analyze(rows, at, 10)["ips"][0]["flagged"]
    assert network("::ffff:192.0.2.1") == "192.0.2.0/24"


def test_short_window_growth_is_explained_without_claiming_a_mature_baseline():
    at = now()
    rows = [snapshot(at - timedelta(minutes=5), [worker(path="/")])]
    rows.append(snapshot(at, [worker(path="/", slot=str(i)) for i in range(20)]))
    row = analyze(rows, at, 5)["ips"][0]
    assert row["flagged"] and row["reference"]["kind"] == "previous_window"
    assert not row["signatures"]
