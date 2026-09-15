from datetime import timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session, defer

from app.config import get_settings
from app.db import get_db
from app.models import ApacheObservation, AuditEvent, MrtgObservation, now
from app.schemas import Login
from app.security import (
    authenticated,
    consume_second_factor,
    locked_admin,
    password_valid,
    rate_limit,
)

router = APIRouter()


def summary(item):
    return {
        "id": item.id,
        "service_id": item.service_id,
        "revision": item.revision,
        "observed_at": item.observed_at,
        "status": item.status,
        "metrics": item.metrics,
        "warnings": item.warnings,
    }


@router.get("/services/{service_id}/observations")
def history(
    service_id: UUID,
    auth=Depends(authenticated),
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    items = db.scalars(
        select(ApacheObservation)
        .options(defer(ApacheObservation.raw_encrypted), defer(ApacheObservation.workers))
        .where(
            ApacheObservation.service_id == str(service_id),
            ApacheObservation.observed_at >= now() - timedelta(days=90),
        )
        .order_by(ApacheObservation.observed_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return {"items": [summary(x) for x in items]}


@router.get("/observations/{observation_id}")
def detail(
    observation_id: UUID,
    auth=Depends(authenticated),
    db: Session = Depends(get_db),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
):
    item = db.get(ApacheObservation, str(observation_id))
    if not item or item.observed_at < now() - timedelta(days=90):
        raise HTTPException(404, "Muestra no disponible.")
    rows = item.workers or [] if item.observed_at >= now() - timedelta(days=30) else []
    return {
        **summary(item),
        "workers": rows[offset : offset + limit],
        "total_workers": len(rows),
        "details_expired": item.observed_at < now() - timedelta(days=30),
    }


@router.post("/observations/{observation_id}/raw")
def original(
    observation_id: UUID, payload: Login, auth=Depends(authenticated), db: Session = Depends(get_db)
):
    rate_limit("original-reauth", 5, 300)
    admin = locked_admin(db, auth[0].email)
    settings = get_settings()
    if (
        payload.email != admin.email
        or not password_valid(admin.password_hash, payload.password.get_secret_value())
        or not consume_second_factor(admin, payload.code.get_secret_value(), settings)
    ):
        raise HTTPException(
            401, "Confirma tu contraseña y un código actual para consultar el original."
        )
    item = db.get(ApacheObservation, str(observation_id)) or db.get(
        MrtgObservation, str(observation_id)
    )
    if not item or not item.raw_encrypted or item.observed_at < now() - timedelta(days=7):
        raise HTTPException(404, "Original no disponible o vencido.")
    content = settings.cipher().decrypt(item.raw_encrypted.encode()).decode()
    db.add(AuditEvent(action="observation.read-original", target_id=item.id))
    db.commit()
    # JSON text only. Clients must use textContent / React escaped text, never HTML injection.
    return {"text": content}
