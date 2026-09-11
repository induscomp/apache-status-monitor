import secrets

import pytest
from sqlalchemy import select

from app.config import get_settings
from app.connectors.policy import validate_service_url
from app.db import session_factory
from app.models import Service, ServiceRevision


def add_server(client, name):
    response = client.post("/api/v1/servers", json={"name": name})
    assert response.status_code == 201
    return response.json()


def add_service(
    client,
    server_id,
    name="Apache",
    kind="apache_status",
    url="https://web.example.test/server-status",
    **extra,
):
    return client.post(
        f"/api/v1/servers/{server_id}/services",
        json={"name": name, "kind": kind, "url": url, **extra},
    )


def update_fields(service, **extra):
    return {
        k: service[k] for k in ("name", "url", "interval_seconds", "enabled", "options", "archived")
    } | extra


def test_multiple_servers_and_same_connector_type(logged_in):
    a, b = add_server(logged_in, "A"), add_server(logged_in, "B")
    for name in ("Apache one", "Apache two"):
        assert add_service(logged_in, a["id"], name).status_code == 201
    assert add_service(logged_in, b["id"], "Apache one").status_code == 201
    assert (
        add_service(
            logged_in, a["id"], "Graphs", "mrtg", "http://metrics.example.test/mrtg/"
        ).status_code
        == 201
    )
    a_services = logged_in.get(f"/api/v1/servers/{a['id']}/services").json()
    b_services = logged_in.get(f"/api/v1/servers/{b['id']}/services").json()
    assert a_services["total"] == 3 and b_services["total"] == 1
    assert all(x["server_id"] == a["id"] and x["status"] == "waiting" for x in a_services["items"])
    assert all(
        x["last_attempt_at"] is None and x["next_run_at"] is None for x in a_services["items"]
    )
    assert add_service(logged_in, a["id"], "Apache one").status_code == 409


def test_pause_archive_and_revision_history(logged_in):
    server = add_server(logged_in, "A")
    first = add_service(logged_in, server["id"]).json()
    other = add_service(logged_in, server["id"], "Other").json()
    paused = logged_in.put(
        f"/api/v1/services/{first['id']}", json=update_fields(first, enabled=False)
    ).json()
    assert paused["status"] == "paused" and paused["revision"] == 2
    assert logged_in.get(f"/api/v1/services/{other['id']}/status").json()["status"] == "waiting"
    changed = logged_in.put(
        f"/api/v1/services/{first['id']}",
        json=update_fields(paused, url="https://web.example.test/other", archived=True),
    ).json()
    assert changed["status"] == "archived" and changed["revision"] == 3
    with session_factory()() as db:
        versions = db.scalars(
            select(ServiceRevision)
            .where(ServiceRevision.service_id == first["id"])
            .order_by(ServiceRevision.revision)
        ).all()
        assert [v.revision for v in versions] == [1, 2, 3]
        assert versions[0].configuration["url"].endswith("server-status")
    assert (
        logged_in.put(
            f"/api/v1/servers/{server['id']}", json={"name": "A", "archived": True}
        ).status_code
        == 200
    )
    assert logged_in.get(f"/api/v1/services/{other['id']}/status").json()["status"] == "archived"
    assert add_service(logged_in, server["id"], "New").status_code == 409
    assert logged_in.get(f"/api/v1/servers/{server['id']}/services").json()["total"] == 2


def test_credentials_encrypted_and_not_returned(logged_in):
    server = add_server(logged_in, "A")
    password = secrets.token_urlsafe(25)
    response = add_service(
        logged_in, server["id"], credentials={"username": "example-user", "password": password}
    )
    assert response.status_code == 201
    assert password not in response.text and "example-user" not in response.text
    service = response.json()
    assert service["has_credentials"] is True
    with session_factory()() as db:
        encrypted = db.get(Service, service["id"]).credentials_encrypted
        assert password not in encrypted
        assert password in get_settings().cipher().decrypt(encrypted.encode()).decode()
        assert password not in str(db.scalar(select(ServiceRevision)).configuration)
    path = f"/api/v1/services/{service['id']}"
    assert (
        logged_in.put(
            path, json=update_fields(service, url="http://metrics.example.test/mrtg/")
        ).status_code
        == 422
    )
    cleared = logged_in.put(path, json=update_fields(service, clear_credentials=True)).json()
    assert cleared["has_credentials"] is False


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "https://unapproved.example/status",
        "https://user:password@web.example.test/status",
        "https://web.example.test/status?token=secret",
        "https://web.example.test:invalid-private-value/status",
        "https://web.example.test/status#fragment",
        "http://web.example.test/status",
        "http://127.0.0.1/status",
        "http://[::1]/status",
        "https://web.example.test\\@evil.test/status",
        "https://web.example.test/\nstatus",
    ],
)
def test_invalid_destinations_rejected(logged_in, url):
    server = add_server(logged_in, "A")
    assert add_service(logged_in, server["id"], url=url).status_code == 422


def test_nonpublic_literals_rejected_even_if_allowlisted():
    for origin in ("http://127.0.0.1", "http://[::1]", "http://169.254.169.254", "http://10.0.0.1"):
        with pytest.raises(ValueError):
            validate_service_url(origin + "/", [origin], [origin])


def test_pagination_input_validation_and_pending_health(logged_in):
    for name in ("A", "B", "C"):
        add_server(logged_in, name)
    page = logged_in.get("/api/v1/servers?offset=1&limit=1").json()
    assert page["total"] == 3 and len(page["items"]) == 1 and page["items"][0]["name"] == "B"
    assert logged_in.get("/api/v1/servers?limit=999").status_code == 422
    assert logged_in.get("/api/v1/services/invalid/status").status_code == 422
    health = logged_in.get("/api/v1/health").json()
    assert health["database"] == "ok" and health["apache_collector"] == "available"
    assert health["scheduler"] == "unavailable"
    connectors = logged_in.get("/api/v1/connectors").json()
    assert {x["kind"] for x in connectors} == {"apache_status", "mrtg"}
    assert {x["kind"] for x in connectors if x["implemented"]} == {"apache_status", "mrtg"}


def test_worker_only_updates_heartbeat_and_cleans_auth(logged_in):
    from app.worker import cleanup_auth, heartbeat

    heartbeat()
    cleanup_auth()
    health = logged_in.get("/api/v1/health").json()
    assert health["scheduler"] == "ok"
    assert health["apache_collector"] == "available" and health["mrtg_collector"] == "available"
