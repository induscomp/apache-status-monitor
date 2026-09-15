import json
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select
from test_services import add_server, add_service, update_fields

from app import goaccess, notifications
from app.connectors.goaccess import parse_report
from app.db import session_factory
from app.models import GoAccessReport, GoAccessState, now


def html(stamp=None):
    return (
        "<script>var json_data = "
        + json.dumps(
            {
                "general": {
                    "date_time": (stamp or now()).strftime("%Y-%m-%d %H:%M:%S %z"),
                    "total_requests": 300,
                    "failed_requests": 2,
                    "log_path": "/private/log",
                    "start_date": "01/sep/2026",
                    "end_date": "12/sep/2026",
                },
                "requests": {
                    "data": [
                        {
                            "data": "/wp-login.php?token=private#secret",
                            "method": "POST",
                            "hits": {"count": 7},
                        }
                    ]
                },
                "hosts": {
                    "data": [
                        {"data": "2001:4860:4860::8888", "hits": {"count": 4}},
                        {"data": "invalid"},
                    ]
                },
                "vhosts": {
                    "data": [{"data": "<img src=x onerror=alert(1)>", "hits": {"count": 12}}]
                },
            }
        )
        + '; throw new Error("never execute");</script>'
    )


def test_parser_reads_only_data_and_normalizes_paths():
    generated, summary, panels = parse_report(html())
    assert generated.tzinfo is not None
    assert "log_path" not in summary
    assert summary["failed_requests"] == 2  # Parse failures, not HTTP 500.
    assert panels["requests"][0]["label"] == "/wp-login.php"
    assert len(panels["hosts"]) == 1
    assert panels["vhosts"][0]["label"].startswith("<img")  # Plain text; React escapes it.
    with pytest.raises(ValueError):
        parse_report('<script>var json_data = fetch("/private")</script>')
    with pytest.raises(ValueError):
        parse_report(html()[:50])


def test_freshness_unknown_future_and_expired():
    stamp = now()
    assert goaccess.freshness(SimpleNamespace(generated_at=None), stamp) == "partial"
    assert (
        goaccess.freshness(SimpleNamespace(generated_at=stamp + timedelta(hours=1)), stamp)
        == "partial"
    )
    report = SimpleNamespace(generated_at=stamp - timedelta(hours=30))
    assert goaccess.freshness(report, stamp) == "stale"
    assert goaccess.freshness(report, stamp, 48) == "ok"


def test_collection_dedup_isolation_staleness_and_dashboard(logged_in, monkeypatch):
    a, b = add_server(logged_in, "A"), add_server(logged_in, "B")
    services = [add_service(logged_in, server["id"], kind="goaccess").json() for server in (a, b)]
    body = html(now() - timedelta(days=90))
    monkeypatch.setattr(goaccess, "fetch", lambda *args, **kwargs: body)
    for service in services:
        goaccess.collect_service(service["id"])
    with session_factory()() as db:
        state = db.get(GoAccessState, services[0]["id"])
        state.observed_at -= timedelta(minutes=6)
        db.commit()
    goaccess.collect_service(services[0]["id"])
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(GoAccessReport)) == 2
    detail = logged_in.get(f"/api/v1/services/{services[0]['id']}/goaccess").json()
    assert detail["status"] == "stale"
    assert len(detail["history"]) == 1
    assert detail["report"]["summary"]["total_requests"] == 300
    dashboard = logged_in.get("/api/v1/dashboard").json()
    assert dashboard["total"] == 2 and dashboard["open_incidents"] == 0
    assert all(s["state"] == "attention" and len(s["sources"]) == 1 for s in dashboard["items"])
    overview = logged_in.get(f"/api/v1/servers/{a['id']}/analysis").json()
    assert overview["state"] == "sources_only" and not overview["has_apache"]
    assert overview["series"] == [] and overview["resources"] == {}
    assert logged_in.get("/api/v1/dashboard?limit=51").status_code == 422


def test_revision_failure_never_presents_previous_report_as_new(logged_in, monkeypatch):
    server = add_server(logged_in, "A")
    service = add_service(logged_in, server["id"], kind="goaccess").json()
    monkeypatch.setattr(goaccess, "fetch", lambda *args, **kwargs: html())
    goaccess.collect_service(service["id"])
    changed = logged_in.put(
        f"/api/v1/services/{service['id']}",
        json=update_fields(service, url="https://web.example.test/new"),
    ).json()
    assert changed["revision"] == 2
    with session_factory()() as db:
        db.get(GoAccessState, service["id"]).observed_at -= timedelta(minutes=6)
        db.commit()
    monkeypatch.setattr(goaccess, "fetch", lambda *args, **kwargs: "invalid report")
    goaccess.collect_service(service["id"])
    result = logged_in.get(f"/api/v1/services/{service['id']}/goaccess").json()
    assert result["status"] == "error" and result["report"] is None
    assert len(result["history"]) == 1


def test_retention_and_configured_freshness(logged_in, monkeypatch):
    service = add_service(
        logged_in,
        add_server(logged_in, "A")["id"],
        kind="goaccess",
        options={"goaccess_max_age_hours": 48},
    ).json()
    monkeypatch.setattr(
        goaccess, "fetch", lambda *args, **kwargs: html(now() - timedelta(hours=30))
    )
    goaccess.collect_service(service["id"])
    assert logged_in.get(f"/api/v1/services/{service['id']}/goaccess").json()["status"] == "ok"
    with session_factory()() as db:
        report = db.scalar(select(GoAccessReport))
        report.observed_at -= timedelta(days=31)
        db.commit()
    detail = logged_in.get(f"/api/v1/services/{service['id']}/goaccess").json()
    assert "hosts" not in detail["report"]["panels"]
    goaccess.retention()
    with session_factory()() as db:
        assert "requests" not in db.scalar(select(GoAccessReport)).panels


def test_new_origin_requires_explicit_admin_authorization(logged_in):
    server = add_server(logged_in, "A")
    opts = {"authorize_origin": True, "allow_http": False}
    url = "https://new.example.test/report.html"
    assert add_service(logged_in, server["id"], url=url).status_code == 422
    assert add_service(logged_in, server["id"], url=url, options=opts).status_code == 201
    for url in [
        "http://new.example.test/report.html",
        "https://127.0.0.1/report",
        "https://[::1]/report",
    ]:
        assert (
            add_service(logged_in, server["id"], name="Other", url=url, options=opts).status_code
            == 422
        )
    opts["allow_http"] = True
    assert (
        add_service(
            logged_in,
            server["id"],
            name="HTTP",
            kind="goaccess",
            url="http://new.example.test/report",
            options=opts,
        ).status_code
        == 201
    )
    assert (
        add_service(
            logged_in,
            server["id"],
            name="Credentials",
            url="http://new.example.test/report",
            options=opts,
            credentials={"username": "u", "password": "p"},
        ).status_code
        == 422
    )


def test_dashboard_and_report_require_authentication(client):
    assert client.get("/api/v1/dashboard").status_code == 401
    assert (
        client.get("/api/v1/services/00000000-0000-0000-0000-000000000001/goaccess").status_code
        == 401
    )


@pytest.mark.parametrize("fail_tls", [False, True])
def test_starttls_precedes_credentials_and_has_no_plaintext_fallback(monkeypatch, fail_tls):
    calls = []

    class SMTP:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def ehlo(self):
            calls.append("ehlo")

        def starttls(self, context):
            assert context.check_hostname
            calls.append("tls")
            if fail_tls:
                raise RuntimeError("TLS unavailable")

        def login(self, *args):
            calls.append("login")

        def send_message(self, message):
            calls.append("send")

    monkeypatch.setattr(notifications.smtplib, "SMTP", SMTP)
    incident = SimpleNamespace(
        id="i",
        server_id="s",
        service_id="x",
        subject="domain:example",
        kind="domain",
        status="open",
        severity="warning",
        evidence={},
    )
    config = dict(
        host="smtp.example.test",
        port=587,
        security="starttls",
        sender="from@example.test",
        recipient="to@example.test",
        username="user",
        password="secret",
    )
    if fail_tls:
        with pytest.raises(RuntimeError):
            notifications.send(config, incident, "open")
        assert calls == ["ehlo", "tls"]
    else:
        notifications.send(config, incident, "open")
        assert calls == ["ehlo", "tls", "ehlo", "login", "send"]


def test_mrtg_only_history_excludes_previous_configuration_and_other_servers(logged_in):
    from app.models import MrtgMetric, MrtgObservation
    from app.workspace_api import mrtg_only_series

    a, b = add_server(logged_in, "A"), add_server(logged_in, "B")
    services = [add_service(logged_in, server["id"], kind="mrtg").json() for server in (a, b)]
    with session_factory()() as db:
        for i, service in enumerate(services):
            metric = MrtgMetric(
                service_id=service["id"], url=service["url"], name="Carga del sistema", revision=2
            )
            db.add(metric)
            db.flush()
            for revision, value in [(1, 900), (2, 2 + i)]:
                db.add(
                    MrtgObservation(
                        metric_id=metric.id,
                        service_id=service["id"],
                        revision=1,
                        metric_revision=revision,
                        status="ok",
                        observed_at=now() - timedelta(minutes=5 if revision == 1 else 0),
                        source_at=now(),
                        values=[
                            {
                                "window": "d",
                                "statistic": "current",
                                "channel": "in",
                                "source": "comment",
                                "value": value,
                            }
                        ],
                    )
                )
        db.commit()
        series = mrtg_only_series(db, a["id"], 24)
        assert len(series) == 1 and series[0]["load"] == 2
