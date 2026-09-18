import smtplib
from datetime import timedelta
from types import SimpleNamespace

from sqlalchemy import select
from test_analysis import service

from app import analysis_api, notifications, support
from app.config import get_settings
from app.db import session_factory
from app.models import SupportReport, now


def setup(monkeypatch):
    with session_factory()() as db:
        svc = service(db)
        sid = svc.server_id
        notifications.store(
            db,
            dict(
                enabled=True,
                verified_at=now().isoformat(),
                host="smtp.example.test",
                port=465,
                security="tls",
                username="",
                sender="monitor@example.test",
                recipient="owner@example.test",
            ),
        )
        db.commit()
    at = now()
    monkeypatch.setattr(
        analysis_api,
        "ip_activity",
        lambda *a, **k: {
            "items": [
                {
                    "fresh": True,
                    "service": "Apache",
                    "start": at - timedelta(hours=1),
                    "end": at,
                    "samples": 12,
                    "expected": 12,
                    "networks": [
                        {
                            "high_priority": True,
                            "key": "192.0.2.0/24",
                            "support_ips": ["192.0.2.1"],
                            "support_evidence": [
                                {
                                    "ip": "192.0.2.1",
                                    "domain": "example.test",
                                    "endpoint": "POST /wp-login.php",
                                    "captures": [at],
                                    "geo": {},
                                }
                            ],
                        }
                    ],
                }
            ]
        },
    )
    return sid


def test_preview_encrypted_and_manual_send_exact_once(logged_in, monkeypatch):
    sid = setup(monkeypatch)
    calls = []
    monkeypatch.setattr(
        support, "send", lambda config, **kw: calls.append((config["recipient"], kw))
    )
    draft = logged_in.post(f"/api/v1/servers/{sid}/support/drafts").json()
    assert not calls and draft["status"] == "draft"
    assert draft["recipient"] == "owner@example.test"
    with session_factory()() as db:
        stored = db.get(SupportReport, draft["id"])
        assert "192.0.2.1" not in stored.encrypted
        assert "192.0.2.1" in get_settings().cipher().decrypt(stored.encrypted.encode()).decode()
    url = f"/api/v1/servers/{sid}/support/{draft['id']}/send"
    assert logged_in.post(url).json()["status"] == "sent"
    assert logged_in.post(url).json()["status"] == "sent"
    assert calls == [("owner@example.test", {"subject": draft["subject"], "body": draft["body"]})]
    second = logged_in.post(f"/api/v1/servers/{sid}/support/drafts").json()
    assert logged_in.post(f"/api/v1/servers/{sid}/support/{second['id']}/send").status_code == 429


def test_failed_send_suspends_smtp_and_never_retries(logged_in, monkeypatch):
    sid = setup(monkeypatch)
    calls = []

    def fail(*args, **kwargs):
        calls.append(1)
        raise smtplib.SMTPAuthenticationError(535, b"private credentials")

    monkeypatch.setattr(support, "send", fail)
    draft = logged_in.post(f"/api/v1/servers/{sid}/support/drafts").json()
    url = f"/api/v1/servers/{sid}/support/{draft['id']}/send"
    result = logged_in.post(url)
    assert result.json()["status"] == "uncertain"
    assert "private credentials" not in result.text
    logged_in.post(url)
    assert len(calls) == 1
    with session_factory()() as db:
        config = notifications.configuration(db)
        assert not config["enabled"] and not config["verified_at"]


def test_support_rejects_expiry_recipient_change_cross_server_and_csrf(logged_in, monkeypatch):
    sid = setup(monkeypatch)
    draft = logged_in.post(f"/api/v1/servers/{sid}/support/drafts").json()
    url = f"/api/v1/servers/{sid}/support/{draft['id']}/send"
    with session_factory()() as db:
        cfg = notifications.configuration(db)
        notifications.store(db, {**cfg, "recipient": "changed@example.test"})
        other = service(db)
        other_id = other.server_id
        db.commit()
    assert logged_in.post(url).status_code == 409
    assert (
        logged_in.post(f"/api/v1/servers/{other_id}/support/{draft['id']}/send").status_code == 404
    )
    with session_factory()() as db:
        db.get(SupportReport, draft["id"]).created_at = now() - timedelta(minutes=16)
        db.commit()
    assert "caducado" in logged_in.post(url).text
    logged_in.headers.pop("x-csrf-token")
    assert logged_in.post(url).status_code == 403
    assert logged_in.post(f"/api/v1/servers/{sid}/support/drafts").status_code == 403


def test_stale_campaigns_do_not_prepare_reports_and_smtp_must_be_verified(logged_in, monkeypatch):
    sid = setup(monkeypatch)
    draft = logged_in.post(f"/api/v1/servers/{sid}/support/drafts").json()
    with session_factory()() as db:
        notifications.store(db, {"enabled": False, "recipient": "owner@example.test"})
        db.commit()
    assert logged_in.post(f"/api/v1/servers/{sid}/support/{draft['id']}/send").status_code == 409
    monkeypatch.setattr(
        analysis_api, "ip_activity", lambda *a, **k: {"items": [{"fresh": False, "networks": []}]}
    )
    assert logged_in.post(f"/api/v1/servers/{sid}/support/drafts").status_code == 409


def test_automatic_campaign_email_includes_concrete_ips_and_evidence(monkeypatch):
    messages = []

    class SMTP:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def send_message(self, message):
            messages.append(message)

    monkeypatch.setattr(notifications.smtplib, "SMTP_SSL", SMTP)
    incident = SimpleNamespace(
        id="incident",
        server_id="server",
        service_id="apache",
        subject="ipwatch:networks:192.0.2.0/24",
        kind="ip_activity",
        status="open",
        severity="critical",
        evidence={
            "support_ips": ["192.0.2.1"],
            "window_minutes": 30,
            "support_evidence": [
                {
                    "ip": "192.0.2.1",
                    "domain": "example.test",
                    "endpoint": "POST /wp-login.php",
                    "captures": ["2026-09-18T10:00:00+00:00"],
                }
            ],
        },
    )
    notifications.send(
        dict(
            sender="from@example.test",
            recipient="owner@example.test",
            host="smtp.example.test",
            port=465,
        ),
        incident,
        "opened",
    )
    assert "192.0.2.1" in messages[0].get_content()
    assert "example.test | POST /wp-login.php" in messages[0].get_content()
    assert messages[0]["To"] == "owner@example.test"


def test_support_retention_deletes_expired_private_reports(monkeypatch):
    from app.analysis import retention

    setup(monkeypatch)
    with session_factory()() as db:
        from app.models import Server

        server = db.scalar(select(Server))
        old = SupportReport(
            server_id=server.id, encrypted="expired", created_at=now() - timedelta(days=31)
        )
        recent = SupportReport(server_id=server.id, encrypted="recent")
        db.add_all([old, recent])
        db.commit()
        old_id, recent_id = old.id, recent.id
    retention()
    with session_factory()() as db:
        assert db.get(SupportReport, old_id) is None
        assert db.get(SupportReport, recent_id) is not None


def test_backup_and_restore_clean_expired_support_evidence():
    from app.backup import clean_row

    stamp = now()
    old = (stamp - timedelta(days=31)).isoformat()
    assert clean_row("support_reports", {"created_at": old, "encrypted": "private"}, stamp) is None
    assert clean_row("support_reports", {"created_at": stamp, "encrypted": "private"}, stamp)
    row = clean_row(
        "incidents",
        {
            "updated_at": old,
            "evidence": {
                "support_ips": ["192.0.2.1"],
                "support_evidence": [{"domain": "example.test"}],
                "high_priority": True,
            },
        },
        stamp,
    )
    assert row["evidence"] == {"high_priority": True}
