"""Reviewed support requests. No scheduled sends or automatic retries."""

import json
import re
from datetime import timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import AuditEvent, Server, SupportReport, now
from app.notifications import configuration, failure_message, lock_channel, send, store
from app.security import authenticated, rate_limit

router = APIRouter()


def server_for(db, server_id):
    server = db.get(Server, str(server_id))
    if not server or server.archived:
        raise HTTPException(404, "Servidor no disponible.")
    return server


def decode(report):
    return json.loads(get_settings().cipher().decrypt(report.encrypted.encode()))


def report_state(report):
    status = report.status
    if status == "sending" and report.attempted_at < now() - timedelta(minutes=2):
        status = "uncertain"
    return dict(
        id=report.id,
        status=status,
        created_at=report.created_at,
        attempted_at=report.attempted_at,
        error=report.error,
    )


@router.get("/servers/{server_id}/support")
def settings(server_id: UUID, auth=Depends(authenticated), db: Session = Depends(get_db)):
    server = server_for(db, server_id)
    config = configuration(db)
    reports = db.scalars(
        select(SupportReport)
        .where(
            SupportReport.server_id == server.id,
            SupportReport.created_at >= now() - timedelta(days=30),
        )
        .order_by(SupportReport.created_at.desc())
        .limit(10)
    ).all()
    return dict(
        email=config.get("recipient", ""),
        ready=bool(config.get("enabled") and config.get("verified_at")),
        reports=[report_state(r) for r in reports],
    )


@router.post("/servers/{server_id}/support/drafts")
def prepare(server_id: UUID, auth=Depends(authenticated), db: Session = Depends(get_db)):
    from app.analysis_api import ip_activity

    rate_limit("support-draft", 10, 300)
    server = server_for(db, server_id)
    recipient = configuration(db).get("recipient")
    if not recipient:
        raise HTTPException(409, "Configura primero el destinatario en Correo.")
    result = ip_activity(server_id, minutes=60, auth=auth, db=db)
    groups = [
        (item, row)
        for item in result["items"]
        if item["fresh"]
        for row in item["networks"]
        if row["high_priority"]
    ]
    ips = sorted({ip for _, row in groups for ip in row["support_ips"]})
    if not ips:
        raise HTTPException(409, "No hay campañas con lecturas recientes para preparar el correo.")
    lines = [
        "Hola,",
        f"Solicitamos revisar y bloquear las siguientes IP en el servidor {server.name}.",
        "Hemos observado actividad repetida contra rutas sensibles de varios dominios.",
        "Se solicita actuar sobre estas direcciones concretas, no sobre prefijos completos.",
        "",
        "IP candidatas a bloqueo:",
        *ips,
        "",
        "Evidencias (horas UTC):",
    ]
    for item, row in groups:
        lines.append(
            f"Fuente: {item['service']} · ventana {item['start']} — {item['end']} · "
            f"cobertura {item['samples']}/{item['expected']} capturas · grupo {row['key']}"
        )
        for e in row["support_evidence"]:
            geo = e.get("geo") or {}
            lines.append(
                f"{e['ip']} | {e['domain']} | {e['endpoint']} | "
                f"{', '.join(str(t) for t in e['captures'])} | "
                f"país {geo.get('country') or 'desconocido'} · "
                f"ASN {geo.get('asn') or 'desconocido'} · "
                f"{geo.get('organization') or 'proveedor desconocido'}"
            )
    lines += [
        "",
        "Capturas de Apache Status cada cinco minutos, incluidas peticiones recientes retenidas. "
        "No son logs completos ni confirman explotación exitosa. País y ASN son contexto de la base local.",
        "Por favor, confirmad las IP bloqueadas y cualquier excepción necesaria. Gracias.",
    ]
    subject = f"Solicitud de bloqueo de {len(ips)} IP · {server.name}"
    subject = re.sub(r"[\r\n]", " ", subject)[:200]
    payload = dict(recipient=recipient, subject=subject, body="\n".join(lines), ips=ips)
    report = SupportReport(
        server_id=server.id,
        encrypted=get_settings().cipher().encrypt(json.dumps(payload).encode()).decode(),
    )
    db.add(report)
    db.flush()
    db.add(AuditEvent(action="support.draft", target_id=report.id))
    db.commit()
    return {**report_state(report), **payload}


@router.post("/servers/{server_id}/support/{report_id}/send")
def deliver(
    server_id: UUID, report_id: UUID, auth=Depends(authenticated), db: Session = Depends(get_db)
):
    # One global lock protects support sends, alert sends and SMTP setting changes.
    lock_channel(db)
    server = server_for(db, server_id)
    report = db.get(SupportReport, str(report_id))
    if not report or report.server_id != server.id:
        raise HTTPException(404, "Borrador no encontrado.")
    if report.status != "draft":
        return report_state(report)  # Duplicate clicks and uncertain sends never resend.
    if report.created_at < now() - timedelta(minutes=15):
        raise HTTPException(409, "El borrador ha caducado. Prepara uno con evidencia reciente.")
    payload = decode(report)
    if payload["recipient"] != configuration(db).get("recipient"):
        raise HTTPException(409, "El destinatario ha cambiado. Prepara y revisa otro borrador.")
    config = configuration(db)
    if not (config.get("enabled") and config.get("verified_at")):
        raise HTTPException(409, "Comprueba y activa el SMTP en Correo antes de enviar a soporte.")
    attempts = db.scalars(
        select(SupportReport).where(SupportReport.attempted_at > now() - timedelta(hours=1))
    ).all()
    if len(attempts) >= 3 or any(r.attempted_at > now() - timedelta(minutes=5) for r in attempts):
        raise HTTPException(429, "Espera cinco minutos entre envíos; máximo tres por hora.")
    # Durable intent before network access: a crash cannot cause a duplicate retry.
    report.status, report.attempted_at = "sending", now()
    db.add(AuditEvent(action="support.send_attempt", target_id=report.id))
    db.commit()
    lock_channel(db)
    current = configuration(db)
    if current != config:
        report.status, report.error = (
            "uncertain",
            "El SMTP cambió; prepara otro borrador después de comprobarlo.",
        )
    else:
        try:
            send(
                {**config, "recipient": payload["recipient"]},
                subject=payload["subject"],
                body=payload["body"],
            )
            report.status = "sent"
        except Exception as error:
            report.status, report.error = "uncertain", failure_message(error)
            config.update(enabled=False, verified_at=None, last_error=report.error)
            store(db, config)
    db.add(AuditEvent(action="support." + report.status, target_id=report.id))
    db.commit()
    return report_state(report)
