from datetime import timedelta

import pytest
from sqlalchemy import select

from app import collection
from app.config import get_settings
from app.connectors.apache import parse_auto, parse_html
from app.db import session_factory
from app.models import ApacheObservation, Server, Service, now

HTML = """<html><table><tr><th>Srv</th><th>M</th><th>Client</th><th>VHost</th><th>Request</th><th>SS</th><th>Req</th><th>Acc</th></tr>
<tr><td>1-0</td><td>W</td><td>2001:db8::1</td><td>same.example:80</td><td>GET /page?secret=value#part HTTP/1.1</td><td>4</td><td>12</td><td>1/100/9000</td></tr>
<tr><td>2-0</td><td>_</td><td>192.0.2.1</td><td>same.example:80</td><td>GET /old HTTP/1.1</td><td>25</td><td>100</td><td>0/200/8000</td></tr></table></html>"""
AUTO = "Uptime: 1000\nTotal Accesses: 9000\nBusyWorkers: 1\nIdleWorkers: 1\n"


def test_parser_preserves_observation_semantics_and_removes_query():
    result = parse_html(HTML)
    assert result["metrics"]["active_workers"] == 1
    assert result["workers"][0]["client"] == "2001:db8::1"
    assert result["workers"][0]["domain"] == "same.example"
    assert result["workers"][0]["path"] == "/page"
    assert result["workers"][1]["observation"] == "last_request"
    assert "9000" not in str(result)
    assert "secret" not in str(result)
    assert parse_auto(AUTO)["Total Accesses"] == 9000


def test_parser_missing_columns_and_truncation():
    result = parse_html(
        HTML.replace("<th>SS</th>", "")
        .replace("<td>4</td>", "")
        .replace("<td>25</td>", "")
        .replace("</html>", "")
    )
    assert result["warnings"]
    assert result["workers"][0]["seconds_since"] is None
    with pytest.raises(ValueError):
        parse_html("<html>Login required</html>")
    with pytest.raises(ValueError):
        parse_auto("ReqPerSec: NaN")


@pytest.fixture
def services():
    with session_factory()() as db:
        server = Server(name="Test server")
        db.add(server)
        db.flush()
        items = [
            Service(
                server_id=server.id,
                name=name,
                kind="apache_status",
                url="https://web.example.test/" + name,
            )
            for name in ("one", "two")
        ]
        db.add_all(items)
        db.commit()
        return [x.id for x in items]


def test_collection_isolated_idempotent_and_encrypted(services, monkeypatch, logged_in):
    monkeypatch.setattr(
        collection, "fetch", lambda url, credentials=None, auto=False: AUTO if auto else HTML
    )
    for key in services:
        collection.collect_service(key)
        collection.collect_service(key)
    with session_factory()() as db:
        rows = db.scalars(select(ApacheObservation)).all()
        assert len(rows) == 2
        assert {x.service_id for x in rows} == set(services)
        assert all(x.status == "ok" and "secret=value" not in x.raw_encrypted for x in rows)
        assert (
            "secret=value"
            in get_settings().cipher().decrypt(rows[0].raw_encrypted.encode()).decode()
        )
    body = logged_in.get(f"/api/v1/services/{services[0]}/observations").json()
    assert len(body["items"]) == 1
    assert "raw_encrypted" not in str(body)
    detail = logged_in.get("/api/v1/observations/" + body["items"][0]["id"]).json()
    assert detail["total_workers"] == 2
    assert "secret=value" not in str(detail)


def test_failures_partial_auto_and_pause_are_independent(services, monkeypatch):
    def fail(url, credentials=None, auto=False):
        if url.endswith("one") or auto:
            raise OSError("private upstream value")
        return HTML

    monkeypatch.setattr(collection, "fetch", fail)
    collection.collect_due()
    with session_factory()() as db:
        rows = db.scalars(select(ApacheObservation)).all()
        assert {r.status for r in rows} == {"error", "partial"}
        assert "private upstream" not in str([r.warnings for r in rows])
        db.get(Service, services[0]).enabled = False
        for row in rows:
            row.observed_at -= timedelta(minutes=10)
        db.commit()
    collection.collect_service(services[0])
    with session_factory()() as db:
        assert len(db.scalars(select(ApacheObservation)).all()) == 2


def test_restart_and_retention(services, monkeypatch):
    monkeypatch.setattr(
        collection, "fetch", lambda url, credentials=None, auto=False: AUTO if auto else HTML
    )
    collection.collect_service(services[0])
    with session_factory()() as db:
        old = db.scalar(select(ApacheObservation))
        old.observed_at -= timedelta(minutes=15)
        db.commit()
    monkeypatch.setattr(
        collection,
        "fetch",
        lambda url, credentials=None, auto=False: (
            AUTO.replace("1000", "100").replace("9000", "90") if auto else HTML
        ),
    )
    collection.collect_service(services[0])
    with session_factory()() as db:
        last = collection.latest(db, services[0])
        assert any("Reinicio" in w for w in last.warnings)
        assert any("Hueco" in w for w in last.warnings)
        last.observed_at = now() - timedelta(days=31)
        db.commit()
    collection.retain_observations()
    with session_factory()() as db:
        rows = db.scalars(
            select(ApacheObservation).where(
                ApacheObservation.observed_at < now() - timedelta(days=30)
            )
        ).all()
        assert rows[0].workers is None and rows[0].raw_encrypted is None


def test_raw_requires_reauthentication_and_obeys_expiry(services, monkeypatch, logged_in, account):
    monkeypatch.setattr(
        collection, "fetch", lambda url, credentials=None, auto=False: AUTO if auto else HTML
    )
    collection.collect_service(services[0])
    with session_factory()() as db:
        key = collection.latest(db, services[0]).id
    url = f"/api/v1/observations/{key}/raw"
    payload = {
        "email": account["email"],
        "password": account["password"],
        "code": account["recovery"],
    }
    assert logged_in.post(url, json={**payload, "password": "wrong"}).status_code == 401
    assert logged_in.post(url, json=payload, headers={"x-csrf-token": "wrong"}).status_code == 403
    result = logged_in.post(url, json=payload)
    assert result.status_code == 200 and "secret=value" in result.json()["text"]
    assert logged_in.post(url, json=payload).status_code == 401


def test_legend_tables_are_not_reported_as_partial_workers():
    body = HTML.replace(
        "</html>", "<table><tr><th>Srv</th><td>Child server number</td></tr></table></html>"
    )
    result = parse_html(body)
    assert not result["warnings"]
    assert result["metrics"]["observed_workers"] == 2


def test_http2_protocol_column_and_session_markers_are_not_urls():
    from html import escape

    from app.analysis import rankings

    headers = [
        "Srv",
        "PID",
        "Acc",
        "M",
        "CPU",
        "SS",
        "Req",
        "Dur",
        "Conn",
        "Child",
        "Slot",
        "Client",
        "Protocol",
        "VHost",
        "Request",
    ]
    rows = [
        [
            "1-17",
            "123",
            "0/0/100",
            "W",
            "0",
            "1",
            "2",
            "50",
            "0",
            "0",
            "0",
            "2001:db8::1",
            "h2",
            "example.test:443",
            "[1/0] write: stream 1, GET /private?token=secret",
        ],
        [
            "2-17",
            "123",
            "0/0/100",
            "_",
            "0",
            "1",
            "2",
            "50",
            "0",
            "0",
            "0",
            "192.0.2.1",
            "h2",
            "example.test:443",
            "[0/0] init",
        ],
        [
            "3-17",
            "123",
            "0/0/100",
            "W",
            "0",
            "1",
            "2",
            "50",
            "0",
            "0",
            "0",
            "192.0.2.2",
            "h2",
            "example.test:443",
            "POST /wp-login.php?token=secret HTTP/2.0",
        ],
        [
            "4-17",
            "-",
            "0/0/100",
            ".",
            "0",
            "1",
            "2",
            "50",
            "0",
            "0",
            "0",
            "192.0.2.3",
            "http/1.1",
            "old.test:80",
            "GET /old HTTP/1.1",
        ],
    ]
    body = "<html><table><tr><th>Slot</th><th>PID</th><th>Connections</th></tr><tr><td>1</td><td>123</td><td>4</td></tr></table><table>"
    for row in [headers, *rows]:
        body += "<tr>" + "".join("<td>" + escape(cell) + "</td>" for cell in row) + "</tr>"
    result = parse_html(body + "</table></html>")
    assert not result["warnings"]
    assert result["metrics"]["http2_observed"] is True
    assert result["metrics"]["protocols"] == {"h2": 3, "http/1.1": 1}
    assert len(result["workers"]) == 4
    assert result["workers"][0]["request_kind"] == "h2_session"
    assert result["workers"][0]["method"] is None
    assert result["workers"][0]["path"] is None
    assert result["workers"][2]["path"] == "/wp-login.php"
    assert result["workers"][3]["observation"] == "last_request"
    domains, details = rankings(result["workers"])
    assert "old.test" not in domains
    assert domains["example.test"]["active"] == 2
    assert [r["path"] for r in details["urls"]] == ["/wp-login.php"]
    assert len(details["posts"]) == 1
    assert "secret" not in str(result)


def test_event_async_connections_are_separate_from_worker_requests():
    data = parse_auto(
        "BusyWorkers: 2\nIdleWorkers: 248\nGracefulWorkers: 0\nConnsTotal: 10\nConnsAsyncWriting: 1\nConnsAsyncKeepAlive: 2\nConnsAsyncClosing: 4\nScoreboard: W_W_.."
    )
    assert data["ConnsTotal"] == 10
    assert data["BusyWorkers"] == 2
    assert data["ActiveRequests"] == 2
    assert data["ConnsAsyncKeepAlive"] == 2
