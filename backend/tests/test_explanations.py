from datetime import timedelta
from types import SimpleNamespace

import pytest
from test_analysis import frame, service

from app import geo
from app.db import session_factory
from app.evidence import domain_evidence
from app.models import ApacheObservation, Incident, MrtgMetric, MrtgObservation, now
from app.presentation import ResourcePresentation


def test_domain_evidence_does_not_blame_other_domains(logged_in):
    with session_factory()() as db:
        svc = service(db)
        observation = ApacheObservation(
            service_id=svc.id,
            revision=1,
            status="ok",
            workers=[
                dict(domain=d, client=ip, state="W", observation="current", method="GET", path="/")
                for d, ip in [("example.test", "192.0.2.1"), ("other.test", "192.0.2.2")]
            ],
        )
        db.add(observation)
        db.flush()
        f = frame(db, svc)
        f.observation_id = observation.id
        scoped = domain_evidence(db, f, "example.test")
        assert scoped["scope"] == "domain"
        assert [r["ip"] for r in scoped["ips"]] == ["192.0.2.1"]
        incident = Incident(
            server_id=svc.server_id,
            service_id=svc.id,
            subject="domain:example.test",
            kind="domain",
            severity="warning",
            status="resolved",
            opened_at=now() - timedelta(minutes=20),
            updated_at=now() - timedelta(minutes=5),
            resolved_at=now() - timedelta(minutes=5),
            evidence={"frame_id": f.id, "coincidences": {"ips": [{"ip": "192.0.2.2", "count": 9}]}},
        )
        db.add(incident)
        db.commit()
        result = logged_in.get(f"/api/v1/servers/{svc.server_id}/incidents").json()["items"][0]
        assert [r["ip"] for r in result["evidence"]["coincidences"]["ips"]] == ["192.0.2.1"]
        assert result["progress"]["last_evaluated_at"] == result["resolved_at"]
        f.observed_at = now() - timedelta(days=31)
        db.commit()
        assert domain_evidence(db, f, "example.test")["scope"] == "unavailable"


@pytest.mark.parametrize(
    "suffix,visible,value,expected",
    [
        ("G", 2.22, 2220000, 2.22e9),
        ("Mbytes", 66, 66000000, 66e6),
        ("B/s", 22, 22, None),
        ("G", 2.22, 0, None),
    ],
)
def test_memory_display_preserves_detector_value(suffix, visible, value, expected):
    with session_factory()() as db:
        svc = service(db, kind="mrtg")
        metric = MrtgMetric(service_id=svc.id, name="Memoria libre", url=svc.url)
        db.add(metric)
        db.flush()
        sample = MrtgObservation(
            metric_id=metric.id,
            service_id=svc.id,
            revision=1,
            metric_revision=1,
            status="ok",
            values=[
                dict(
                    channel="out",
                    window="d",
                    statistic="current",
                    source="comment",
                    value=value,
                    display_value=visible,
                    display_unit=suffix,
                )
            ],
        )
        db.add(sample)
        db.flush()
        raw = {
            "value": value,
            "unit": "valor de origen",
            "sample_id": sample.id,
            "basis": f"{metric.id}:1:out:comment:valor de origen",
        }
        shown = ResourcePresentation(db).point("ram_free", raw)
        assert shown["value"] == value and "display_bytes" not in raw
        assert shown.get("display_bytes") == expected


def test_unknown_memory_not_guessed_and_verified_kib_converted():
    presenter = ResourcePresentation(None)
    assert "display_bytes" not in presenter.point("ram_free", {"value": 2220000, "unit": "unknown"})
    assert presenter.point("ram_free", {"value": 1024, "unit": "KiB"})["display_bytes"] == 1048576


def test_geo_local_asn_prefix_and_country_with_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(geo, "GEO_DIR", tmp_path)
    for name in ("dbip-asn-lite.mmdb", "dbip-country-lite.mmdb"):
        (tmp_path / name).touch()

    class Reader:
        def __init__(self, path):
            self.asn = "asn" in path.name

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def metadata(self):
            return SimpleNamespace(build_epoch=1788220800)

        def get_with_prefix_len(self, address):
            return (
                {
                    "autonomous_system_number": 64500,
                    "autonomous_system_organization": "Example operator",
                }
                if self.asn
                else {"country": {"iso_code": "ES"}},
                24,
            )

    monkeypatch.setattr(geo.maxminddb, "open_database", Reader)
    geo._lookup.cache_clear()
    result = geo.lookup("192.0.2.10")
    assert (
        result["network"] == "192.0.2.0/24" and result["asn"] == 64500 and result["country"] == "ES"
    )
    assert result["source"] == "db-ip-lite" and result["database_at"]
    assert geo.availability() == {"country": True, "asn": True}
    assert geo.lookup("not an IP")["source"] == "unknown"
