import json
import smtplib
import ssl
from datetime import timedelta
from email.message import EmailMessage

from sqlalchemy import select, text, update

from app.config import get_settings
from app.db import session_factory
from app.models import AuditEvent, EmailDelivery, Incident, NotificationConfig, now


def lock_channel(db):
    # Serialize configuration, manual checks and worker sends across all processes.
    db.execute(text("SELECT pg_advisory_xact_lock(73419021)"))
    db.expire_all()


def store(db, config):
    item = db.get(NotificationConfig, 1)
    encrypted = get_settings().cipher().encrypt(json.dumps(config).encode()).decode()
    if item:
        item.encrypted = encrypted
    else:
        db.add(NotificationConfig(id=1, encrypted=encrypted))
    if not config.get("enabled"):
        db.execute(
            update(EmailDelivery)
            .where(EmailDelivery.status.in_(["pending", "sending"]))
            .values(status="suppressed")
        )


def failure_message(error):
    if isinstance(error, smtplib.SMTPAuthenticationError):
        return "Acceso SMTP rechazado. Revisa usuario y contraseña; correo suspendido para evitar bloqueos."
    if isinstance(error, ssl.SSLError):
        return "No se pudo verificar la conexión TLS. Revisa servidor, puerto y seguridad. Correo suspendido."
    return "No se pudo confirmar el envío. Revisa servidor, puerto, remitente y destinatario. Correo suspendido; no se reintentará automáticamente."


def configuration(db):
    config = db.get(NotificationConfig, 1)
    values = (
        json.loads(get_settings().cipher().decrypt(config.encrypted.encode()))
        if config
        else {"enabled": False}
    )
    if not values.get("verified_at"):
        values["enabled"] = False
    return values


def send(config, incident=None, transition="test"):
    message = EmailMessage()
    message["From"] = config["sender"]
    message["To"] = config["recipient"]
    if incident is None:
        message["Subject"] = "[Apache Monitor] Prueba de correo"
        message.set_content(
            "Prueba solicitada desde la configuración del monitor. Si recibes este mensaje, puedes activar las alertas en el panel."
        )
    else:
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
            # SMTP.login tries multiple mechanisms after rejection. Use exactly one.
            smtp.ehlo_or_helo_if_needed()
            mechanisms = smtp.esmtp_features.get("auth", "").upper().split()
            method = next((m for m in ("PLAIN", "LOGIN", "CRAM-MD5") if m in mechanisms), None)
            if method is None:
                raise smtplib.SMTPNotSupportedError("No supported authentication mechanism")
            smtp.user, smtp.password = config["username"], config.get("password", "")
            smtp.auth(method, getattr(smtp, "auth_" + method.lower().replace("-", "_")))
        smtp.send_message(message)


def deliver():
    with session_factory()() as db:
        lock_channel(db)
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
            if not (
                config.get("enabled") and config.get("verified_at")
            ) or item.created_at < now() - timedelta(hours=1):
                item.status = "suppressed"
            else:
                item.status = "sending"
                ids.append(item.id)
        db.commit()
    for key in ids:
        with session_factory()() as db:
            lock_channel(db)
            item = db.get(EmailDelivery, key)
            if item.status != "sending":
                continue
            incident = db.get(Incident, item.incident_id)
            try:
                # Re-read so disabling the channel stops queued deliveries.
                config = configuration(db)
                if not (config.get("enabled") and config.get("verified_at")):
                    item.status = "suppressed"
                else:
                    send(config, incident, item.transition)
                    item.status = "sent"
            except Exception as error:
                item.status = "uncertain"
                item.error = failure_message(error)
                config.update(enabled=False, verified_at=None, last_error=item.error)
                store(db, config)
                db.add(AuditEvent(action="notifications.suspended", target_id="1"))
            db.commit()
