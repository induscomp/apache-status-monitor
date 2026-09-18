import smtplib

from app import analysis_api, notifications


def settings():
    return dict(
        enabled=False,
        host="smtp.example.test",
        port=465,
        security="tls",
        username="user",
        password="secret-password",
        sender="from@example.test",
        recipient="to@example.test",
    )


def test_mail_requires_successful_test_before_activation(logged_in, monkeypatch):
    payload = settings()
    assert (
        logged_in.put("/api/v1/notifications", json={**payload, "enabled": True}).status_code == 409
    )
    assert logged_in.put("/api/v1/notifications", json=payload).status_code == 200
    calls = []
    monkeypatch.setattr(analysis_api, "send", lambda config: calls.append(config["host"]))
    response = logged_in.post("/api/v1/notifications/test")
    assert response.json()["ok"] is True
    assert len(calls) == 1
    assert logged_in.get("/api/v1/notifications").json()["enabled"] is False
    assert (
        logged_in.put("/api/v1/notifications", json={**payload, "enabled": True}).status_code == 200
    )
    assert logged_in.post("/api/v1/notifications/test").status_code == 429
    assert len(calls) == 1
    payload["recipient"] = "other@example.test"
    assert (
        logged_in.put("/api/v1/notifications", json={**payload, "enabled": True}).status_code == 409
    )
    assert logged_in.put("/api/v1/notifications", json=payload).status_code == 200
    assert logged_in.get("/api/v1/notifications").json()["verified_at"] is None
    assert logged_in.post("/api/v1/notifications/test").status_code == 429


def test_rejected_test_stays_disabled_and_does_not_leak_error(logged_in, monkeypatch):
    assert logged_in.put("/api/v1/notifications", json=settings()).status_code == 200

    def fail(config):
        raise smtplib.SMTPAuthenticationError(535, b"private-provider-secret")

    monkeypatch.setattr(analysis_api, "send", fail)
    response = logged_in.post("/api/v1/notifications/test")
    assert response.json()["ok"] is False
    assert "Acceso SMTP rechazado" in response.json()["message"]
    assert "private-provider-secret" not in response.text
    config = logged_in.get("/api/v1/notifications").json()
    assert not config["enabled"] and not config["verified_at"]
    assert "password" not in config
    assert (
        logged_in.put("/api/v1/notifications", json={**settings(), "enabled": True}).status_code
        == 409
    )
    logged_in.headers.pop("x-csrf-token")
    assert logged_in.post("/api/v1/notifications/test").status_code == 403


def test_smtp_uses_only_one_auth_mechanism(monkeypatch):
    calls = []

    class SMTP:
        esmtp_features = {"auth": "PLAIN LOGIN CRAM-MD5"}
        auth_plain = None

        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def ehlo_or_helo_if_needed(self):
            pass

        def auth(self, method, callback):
            calls.append(method)
            raise smtplib.SMTPAuthenticationError(535, b"rejected")

    monkeypatch.setattr(notifications.smtplib, "SMTP_SSL", SMTP)
    import pytest

    with pytest.raises(smtplib.SMTPAuthenticationError):
        notifications.send(settings())
    assert calls == ["PLAIN"]
