from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app import mrtg_collection as collector
from app.config import get_settings
from app.connectors.mrtg import allowed_detail, discover, parse_detail
from app.db import session_factory
from app.models import MrtgDiscovery, MrtgMetric, MrtgObservation, Server, Service, now

INDEX = '<html><a href="traffic.html"><img src="traffic.png"></a><a href="load.html"><img src="load.png"></a><a href="https://external.example/logo.html"><img src="logo.png"></a></html>'
PAGE = """<html><head><title>Load * 100</title><!-- cuin d 500 --><!-- cuout d 400 --><!-- avin w 300 --><!-- maxout y 900 --></head><body><p>The statistics were last updated <strong>Friday, 11 September 2026 at 18:35</strong></p><h2>Daily Graph</h2><table><tr><th></th><th>Max</th><th>Average</th><th>Current</th></tr><tr class="in"><th>Load</th><td>1.2 kB/s</td><td>600 B/s</td><td>999 B/s</td></tr></table></body></html>"""


def test_discover_follows_images_and_deduplicates():
    urls = discover(
        "http://metrics.example.test/mrtg/",
        INDEX
        + '<a href="traffic.html#daily"><img src="another.png"></a><a href="not-image.html">Text</a>',
    )
    assert urls == [
        "http://metrics.example.test/mrtg/traffic.html",
        "http://metrics.example.test/mrtg/load.html",
    ]
    assert discover("http://metrics.example.test/mrtg/index.html", INDEX) == urls
    assert discover("http://metrics.example.test/mrtg", INDEX) == urls


@pytest.mark.parametrize(
    "href",
    [
        "../outside.html",
        "/outside.html",
        "http://elsewhere.test/mrtg/a.html",
        "//elsewhere.test/mrtg/a.html",
        "http://user@metrics.example.test/mrtg/a.html",
        "a.html?url=secret",
        "%2e%2e/a.html",
        "%252e%252e/a.html",
        "a.png",
        "a.log",
        "http://[invalid",
        "javascript:alert(1)",
        "a\\b.html",
    ],
)
def test_discovery_rejects_unauthorized_paths(href):
    assert allowed_detail("http://metrics.example.test/mrtg/", href) is None


def test_comments_preferred_and_windows_channels_stay_separate():
    result = parse_detail(PAGE)
    values = {(p["window"], p["channel"], p["statistic"]): p for p in result["values"]}
    assert values["d", "in", "current"]["value"] == 500
    assert values["d", "in", "current"]["source"] == "comment"
    assert values["d", "in", "maximum"]["value"] == 1.2
    assert values["d", "in", "maximum"]["source_unit"] == "kB/s"
    assert values["w", "in", "average"]["value"] == 300
    assert values["y", "out", "maximum"]["value"] == 900
    assert result["source_at"] is None
    assert "18:35" in result["source_time_text"]
    assert result["warnings"]


def test_timezone_staleness_and_table_fallback():
    result = parse_detail(PAGE, "Europe/Madrid", datetime(2026, 9, 11, 16, 40, tzinfo=UTC))
    assert result["source_at"] == datetime(2026, 9, 11, 16, 35, tzinfo=UTC)
    assert not result["warnings"]
    assert parse_detail(PAGE, "UTC", datetime(2026, 9, 11, 20, 0, tzinfo=UTC))["warnings"]
    assert parse_detail(PAGE.replace("</html>", ""))["warnings"]
    with pytest.raises(ValueError):
        parse_detail("<html>No data</html>")


@pytest.fixture
def service():
    with session_factory()() as db:
        server = Server(name="MRTG test server")
        db.add(server)
        db.flush()
        item = Service(
            server_id=server.id, name="MRTG", kind="mrtg", url="http://metrics.example.test/mrtg/"
        )
        db.add(item)
        db.commit()
        return item.id


def mock_fetch(monkeypatch):
    monkeypatch.setattr(
        collector, "fetch", lambda url, credentials=None: INDEX if url.endswith("/") else PAGE
    )


def test_discovery_collection_selection_and_retention(service, monkeypatch, logged_in):
    mock_fetch(monkeypatch)
    collector.discover_service(service)
    collector.discover_service(service)
    collector.collect_due()
    collector.collect_due()
    result = logged_in.get(f"/api/v1/services/{service}/mrtg").json()
    assert len(result["items"]) == 2
    metric = result["items"][0]
    assert metric["latest"]["status"] == "partial"
    assert metric["latest"]["configuration"] == {}
    assert "raw_encrypted" not in str(result)
    with session_factory()() as db:
        rows = db.scalars(select(MrtgObservation)).all()
        assert len(rows) == 2
        assert all(
            get_settings().cipher().decrypt(r.raw_encrypted.encode()).decode() == PAGE for r in rows
        )
        for row in rows:
            row.observed_at -= timedelta(days=8)
        db.commit()
    config = {
        "selected": False,
        "verified": True,
        "unit": "load",
        "factor": 0.01,
        "timezone": "Europe/Madrid",
    }
    assert logged_in.put(f"/api/v1/mrtg/metrics/{metric['id']}", json=config).status_code == 200
    collector.collect_metric(metric["id"])
    collector.retention()
    with session_factory()() as db:
        rows = db.scalars(select(MrtgObservation)).all()
        assert len(rows) == 2 and all(r.raw_encrypted is None for r in rows)
    assert logged_in.post(f"/api/v1/services/{service}/mrtg/discover", json={}).status_code == 202
    with session_factory()() as db:
        assert db.get(MrtgDiscovery, service).requested


def test_metric_interpretation_is_snapshot_and_source_specific(service, monkeypatch, logged_in):
    mock_fetch(monkeypatch)
    collector.discover_service(service)
    with session_factory()() as db:
        key = db.scalar(select(MrtgMetric.id))
    payload = {
        "selected": True,
        "verified": True,
        "unit": "load",
        "factor": 0.01,
        "timezone": "Europe/Madrid",
    }
    assert logged_in.put(f"/api/v1/mrtg/metrics/{key}", json=payload).status_code == 200
    collector.collect_metric(key)
    history = logged_in.get(f"/api/v1/mrtg/metrics/{key}/observations").json()["items"]
    assert len(history) == 1 and history[0]["metric_revision"] == 2
    comments = [p for p in history[0]["values"] if p["source"] == "comment"]
    tables = [p for p in history[0]["values"] if p["source"] == "table"]
    assert any(p["normalized_value"] == 5 for p in comments)
    assert all("normalized_value" not in p for p in tables)
    assert (
        logged_in.put(f"/api/v1/mrtg/metrics/{key}", json={**payload, "factor": 2}).status_code
        == 200
    )
    assert (
        logged_in.get(f"/api/v1/mrtg/metrics/{key}/observations").json()["items"][0][
            "configuration"
        ]["factor"]
        == 0.01
    )
    assert (
        logged_in.put(
            f"/api/v1/mrtg/metrics/{key}", json={**payload, "timezone": "invalid/zone"}
        ).status_code
        == 422
    )


def test_page_errors_and_disappearing_links_are_independent(service, monkeypatch):
    mock_fetch(monkeypatch)
    collector.discover_service(service)

    def fetch(url, credentials=None):
        if url.endswith("traffic.html"):
            raise OSError("secret upstream error")
        return PAGE

    monkeypatch.setattr(collector, "fetch", fetch)
    collector.collect_due()
    with session_factory()() as db:
        assert {r.status for r in db.scalars(select(MrtgObservation))} == {"error", "partial"}
        state = db.get(MrtgDiscovery, service)
        state.attempted_at = now() - timedelta(days=2)
        db.commit()
    monkeypatch.setattr(
        collector, "fetch", lambda *args: '<a href="load.html"><img src="load.png"></a>'
    )
    collector.discover_service(service)
    with session_factory()() as db:
        metrics = db.scalars(select(MrtgMetric)).all()
        assert len(metrics) == 2 and sum(m.present for m in metrics) == 1


def test_mrtg_requires_session_and_csrf(service, client, logged_in):
    # Fixtures share the authenticated client; remove its cookie for the unauthenticated check.
    assert (
        logged_in.post(
            f"/api/v1/services/{service}/mrtg/discover", json={}, headers={"x-csrf-token": "wrong"}
        ).status_code
        == 403
    )
    logged_in.cookies.clear()
    assert logged_in.get(f"/api/v1/services/{service}/mrtg").status_code == 401


def test_discovery_origin_normalization_and_size_limits():
    assert (
        allowed_detail(
            "http://metrics.example.test/mrtg/", "http://METRICS.example.test:80/mrtg/a.html"
        )
        == "http://metrics.example.test/mrtg/a.html"
    )
    assert allowed_detail("http://metrics.example.test/mrtg/", "a" * 2050 + ".html") is None
    with pytest.raises(ValueError):
        discover(
            "http://metrics.example.test/mrtg/",
            "".join(f'<a href="{n}.html"><img src="x.png"></a>' for n in range(101)),
        )
