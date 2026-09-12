import json
import smtplib
import ssl
from datetime import timedelta
from email.message import EmailMessage

from sqlalchemy import select, update

from app.config import get_settings
from app.db import session_factory
from app.models import EmailDelivery, Incident, NotificationConfig, now


def configuration(db):
    config = db.get(NotificationConfig, 1)
    return (
        json.loads(get_settings().cipher().decrypt(config.encrypted.encode()))
        if config
        else {"enabled": False}
    )


def send(config, incident, transition):
    message = EmailMessage()
    message["From"] = config["sender"]
    message["To"] = config["recipient"]
    message["Subject"] = "[Apache Monitor] " + transition + " · " + incident.kind
    evidence = incident.evidence
    message.set_content(
        f"Incidente: {incident.id}\nServidor: {incident.server_id}\nServicio: {incident.service_id}\nSujeto: {incident.subject}\nEstado: {incident.status}\nSeveridad: {incident.severity}\nValor observado: {evidence.get('value')}\nReferencia: {evidence.get('reference')}\n\nSe comparan observaciones de Apache Status y MRTG. No son visitas totales, no confirman errores 500 y no demuestran causalidad. Consulta Incidentes en el panel."
    )
    # Certificate verification is mandatory. No cleartext SMTP mode is offered.
    context = ssl.create_default_context()
    if config.get("security", "tls") == "starttls":
        smtp = smtplib.SMTP(config["host"], config["port"], timeout=10)
    else:
        smtp = smtplib.SMTP_SSL(config["host"], config["port"], timeout=10, context=context)
    with smtp:
        if config.get("security") == "starttls":
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
        if config.get("username"):
            smtp.login(config["username"], config.get("password", ""))
        smtp.send_message(message)


def deliver():
    with session_factory()() as db:
        db.execute(
            update(EmailDelivery)
            .where(
                EmailDelivery.status == "sending",
                EmailDelivery.created_at < now() - timedelta(minutes=15),
            )
            .values(
                status="uncertain",
                error="Entrega interrumpida; requiere revisión, sin reenvío automático.",
            )
        )
        config = configuration(db)
        pending = db.scalars(
            select(EmailDelivery)
            .where(EmailDelivery.status == "pending")
            .order_by(EmailDelivery.created_at)
            .limit(10)
            .with_for_update(skip_locked=True)
        ).all()
        ids = []
        for item in pending:
            if not config.get("enabled") or item.created_at < now() - timedelta(hours=1):
                item.status = "suppressed"
            else:
                item.status = "sending"
                ids.append(item.id)
        db.commit()
    for key in ids:
        with session_factory()() as db:
            item = db.get(EmailDelivery, key)
            incident = db.get(Incident, item.incident_id)
            try:
                # Re-read so disabling the channel stops queued deliveries.
                config = configuration(db)
                if not config.get("enabled"):
                    item.status = "suppressed"
                else:
                    send(config, incident, item.transition)
                    item.status = "sent"
            except Exception:
                # Acceptance may have occurred before disconnect: never blindly send a duplicate.
                item.status = "uncertain"
                item.error = (
                    "No se pudo confirmar la entrega SMTP. No se reintenta automáticamente."
                )
            db.commit()
