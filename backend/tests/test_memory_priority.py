from datetime import timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from test_analysis import frame, service

from app.db import session_factory
from app.incidents import memory_severity, transition
from app.models import Incident, now
from app.mrtg_api import MetricConfig


@pytest.mark.parametrize(
    "swap,expected",
    [
        ({}, ("warning", "unknown")),
        ({"value": 90}, ("warning", "unknown")),
        ({"value": 100, "capacity": 100}, ("warning", "unused")),
        ({"value": 99, "capacity": 100}, ("critical", "used")),
        ({"value": 101, "capacity": 100}, ("warning", "unknown")),
    ],
)
def test_memory_priority_requires_real_swap_capacity(swap, expected):
    assert memory_severity({"swap_free": swap}) == expected


def test_memory_can_escalate_and_return_to_orange_without_resolving(logged_in):
    with session_factory()() as db:
        svc = service(db)
        stamp = now() - timedelta(minutes=40)
        for index, resources in enumerate(
            [
                {},
                {},
                {"swap_free": {"value": 99, "capacity": 100}},
                {},
                {"swap_free": {"value": 100, "capacity": 100}},
            ]
        ):
            for point in resources.values():
                point.update(basis="swap:1", unit="bytes")
            f = frame(db, svc, at=stamp + timedelta(minutes=5 * index), resources=resources)
            transition(
                db,
                f,
                "resource:ram_free",
                "resources",
                20,
                {"median": 100, "mad": 0, "samples": 12},
                True,
                {"resources": resources},
            )
            db.flush()
            incident = db.scalar(select(Incident))
            if index > 0:
                assert incident.status == "open"
                assert incident.severity == ("critical" if index in (2, 3) else "warning")
                db.commit()
                overview = logged_in.get(f"/api/v1/servers/{svc.server_id}/analysis").json()
                assert overview["priority"] == incident.severity
                assert (
                    logged_in.get("/api/v1/dashboard").json()["items"][0]["priority"]
                    == incident.severity
                )


def test_capacity_requires_confirmed_unit():
    with pytest.raises(ValidationError):
        MetricConfig(selected=True, capacity=100)
    assert MetricConfig(selected=True, verified=True, unit="bytes", capacity=100).capacity == 100


def test_any_confirmed_swap_use_opens_red_even_without_large_free_drop():
    from app.incidents import evaluate

    with session_factory()() as db:
        svc = service(db)
        stamp = now()
        for index in range(12):
            frame(
                db,
                svc,
                at=stamp - timedelta(minutes=40 + index * 5),
                resources={"swap_free": {"value": 100, "capacity": 100, "basis": "swap:1"}},
            )
        for index in (1, 0):
            current = frame(
                db,
                svc,
                at=stamp - timedelta(minutes=index * 5),
                resources={"swap_free": {"value": 99, "capacity": 100, "basis": "swap:1"}},
            )
            evaluate(db, current)
        db.flush()
        incident = db.scalar(select(Incident).where(Incident.subject == "resource:swap_free"))
        assert incident and incident.severity == "critical" and incident.status == "open"
        invalid = frame(
            db,
            svc,
            at=stamp + timedelta(minutes=5),
            resources={"swap_free": {"value": 101, "capacity": 100, "basis": "swap:1"}},
        )
        evaluate(db, invalid)
        assert incident.status == "open" and incident.severity == "critical"
