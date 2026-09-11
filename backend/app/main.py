import json
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import timedelta
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.config import get_settings
from app.connectors import CONNECTORS
from app.connectors.policy import validate_service_url
from app.db import get_db
from app.models import (
    AuditEvent,
    ComponentHeartbeat,
    Server,
    Service,
    ServiceRevision,
    now,
)
from app.schemas import Login, ServerInput, ServerUpdate, ServiceInput, ServiceUpdate
from app.security import (
    DUMMY_HASH,
    PASSWORDS,
    AccessVerifier,
    access_identity,
    authenticated,
    consume_second_factor,
    encrypt_credentials,
    locked_admin,
    new_session,
    password_valid,
    rate_limit,
)
from app.setup import router as setup_router

logger = logging.getLogger("smon")
logging.basicConfig(level=logging.INFO, format="%(message)s")


class RequestBoundary:
    """Bound JSON bodies, including chunked requests, before parsing any input."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > 16384:
                response = JSONResponse({"detail": "Solicitud demasiado grande."}, status_code=413)
                return await response(scope, receive, send)
            if not message.get("more_body", False):
                break
        supplied = False

        async def bounded_receive():
            nonlocal supplied
            if not supplied:
                supplied = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        response_started = False

        async def secured_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                message["headers"] = list(message.get("headers", [])) + [
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
                ]
            await send(message)

        started = time.monotonic()
        try:
            await self.app(scope, bounded_receive, secured_send)
        except Exception as exc:
            # Handle before Starlette's outer error middleware can re-raise and make
            # Uvicorn log exception text (e.g. database parameters or credentials).
            logger.error(json.dumps({"event": "internal_error", "type": type(exc).__name__}))
            if response_started:
                raise RuntimeError("Response interrupted; details withheld") from None
            response = JSONResponse(
                {"detail": "Error interno. Consulta el estado del sistema."}, status_code=500
            )
            await response(scope, bounded_receive, secured_send)
        finally:
            # Do not log URL, query, headers, input, tokens or upstream content.
            if scope.get("path", "").startswith("/api/"):
                logger.info(
                    json.dumps(
                        {
                            "event": "api_request",
                            "method": scope["method"],
                            "duration_ms": round((time.monotonic() - started) * 1000),
                        }
                    )
                )


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    settings.cipher()  # Fail closed before accepting traffic if key is unavailable/invalid.
    app.state.access_verifier = (
        AccessVerifier(settings) if settings.environment == "production" else None
    )
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Apache Status Monitor",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(RequestBoundary)
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=[
            urlsplit(settings.public_origin).hostname,
            "localhost",
            "127.0.0.1",
            "backend",
        ],
    )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Pydantic's default error includes the rejected input, potentially a password.
        return JSONResponse(
            status_code=422, content={"detail": "Datos no válidos. Revisa los campos."}
        )

    @app.exception_handler(IntegrityError)
    async def conflict(request, exc):
        return JSONResponse(
            status_code=409, content={"detail": "Ya existe un elemento con ese nombre."}
        )

    @app.exception_handler(Exception)
    async def unexpected(request, exc):
        logger.error(json.dumps({"event": "internal_error", "type": type(exc).__name__}))
        return JSONResponse(
            status_code=500, content={"detail": "Error interno. Consulta el estado del sistema."}
        )

    @app.get("/health/live")
    def live():
        return {"status": "ok"}

    @app.get("/health/ready")
    def ready(db: Session = Depends(get_db)):
        # Check schema as well as the database connection. No details are disclosed.
        db.execute(select(Server.id).limit(1))
        return {"status": "ok"}

    api = APIRouter(prefix="/api/v1", dependencies=[Depends(access_identity)])
    api.include_router(setup_router)

    @api.post("/auth/login")
    def login(
        payload: Login,
        request: Request,
        response: Response,
        db: Session = Depends(get_db),
        identity=Depends(access_identity),
    ):
        rate_limit("login-global", 30, 60)
        rate_limit(f"login:{payload.email}", 5, 300)
        admin = locked_admin(db, payload.email)
        valid = password_valid(
            admin.password_hash if admin else DUMMY_HASH, payload.password.get_secret_value()
        )
        if (
            not valid
            or not admin
            or (identity is not None and identity != admin.email)
            or not consume_second_factor(admin, payload.code.get_secret_value(), settings)
        ):
            raise HTTPException(401, "Credenciales o código no válidos.")
        if PASSWORDS.check_needs_rehash(admin.password_hash):
            admin.password_hash = PASSWORDS.hash(payload.password.get_secret_value())
        token, session = new_session(admin, settings)
        db.add(session)
        db.add(AuditEvent(action="auth.login", target_id=str(admin.id)))
        db.commit()
        response.set_cookie(
            settings.cookie_name,
            token,
            httponly=True,
            secure=settings.secure_cookie,
            samesite="strict",
            path="/",
            max_age=settings.session_hours * 3600,
        )
        return {"email": admin.email, "csrf_token": session.csrf_token}

    @api.get("/auth/session")
    def session(auth=Depends(authenticated)):
        return {"email": auth[0].email, "csrf_token": auth[1].csrf_token}

    @api.post("/auth/logout", status_code=204)
    def logout(response: Response, auth=Depends(authenticated), db: Session = Depends(get_db)):
        db.delete(auth[1])
        db.add(AuditEvent(action="auth.logout", target_id=str(auth[0].id)))
        db.commit()
        response.delete_cookie(
            settings.cookie_name,
            path="/",
            secure=settings.secure_cookie,
            httponly=True,
            samesite="strict",
        )

    @api.post("/auth/revoke-sessions", status_code=204)
    def revoke(response: Response, auth=Depends(authenticated), db: Session = Depends(get_db)):
        from sqlalchemy import delete

        from app.models import AuthSession

        db.execute(delete(AuthSession).where(AuthSession.admin_id == auth[0].id))
        db.add(AuditEvent(action="auth.revoke_sessions", target_id=str(auth[0].id)))
        db.commit()
        response.delete_cookie(
            settings.cookie_name,
            path="/",
            secure=settings.secure_cookie,
            httponly=True,
            samesite="strict",
        )

    @api.get("/connectors")
    def connectors(auth=Depends(authenticated)):
        return [asdict(item) for item in CONNECTORS.values()]

    @api.get("/health")
    def health(auth=Depends(authenticated), db: Session = Depends(get_db)):
        db.execute(text("SELECT 1"))
        heartbeat = db.get(ComponentHeartbeat, "scheduler")
        return {
            "database": "ok",
            "scheduler": "ok"
            if heartbeat and heartbeat.seen_at > now() - timedelta(seconds=90)
            else "unavailable",
            "scheduler_last_seen": heartbeat.seen_at if heartbeat else None,
            "apache_collector": "pending",
            "mrtg_collector": "pending",
            "email": "not_configured",
        }

    def server_result(server: Server):
        return {
            "id": server.id,
            "name": server.name,
            "description": server.description,
            "tags": server.tags,
            "archived": server.archived,
            "created_at": server.created_at,
        }

    def service_result(service: Service, parent_archived: bool = False):
        return {
            "id": service.id,
            "server_id": service.server_id,
            "name": service.name,
            "kind": service.kind,
            "url": service.url,
            "interval_seconds": service.interval_seconds,
            "enabled": service.enabled,
            "archived": service.archived,
            "revision": service.revision,
            "options": service.options,
            "has_credentials": bool(service.credentials_encrypted),
            "status": "archived"
            if service.archived or parent_archived
            else "paused"
            if not service.enabled
            else "pending",
            "last_attempt_at": None,
            "last_success_at": None,
            "next_run_at": None,
            "capabilities": [],
            "created_at": service.created_at,
        }

    def get_server(db, server_id):
        item = db.get(Server, str(server_id))
        if not item:
            raise HTTPException(404, "Servidor no encontrado.")
        return item

    def get_service(db, service_id):
        item = db.get(Service, str(service_id))
        if not item:
            raise HTTPException(404, "Servicio no encontrado.")
        return item

    def save_revision(db, service):
        config = service_result(service)
        # Avoid datetime JSON encoding, runtime state and any credential material.
        config = {
            k: config[k]
            for k in (
                "name",
                "kind",
                "url",
                "interval_seconds",
                "enabled",
                "archived",
                "options",
                "has_credentials",
            )
        }
        db.add(
            ServiceRevision(service_id=service.id, revision=service.revision, configuration=config)
        )

    def checked_url(payload):
        try:
            url = validate_service_url(
                payload.url, settings.allowed_monitor_origins, settings.allowed_http_origins
            )
            if payload.credentials and not url.startswith("https://"):
                raise ValueError("Credentials require HTTPS")
            return url
        except ValueError:
            raise HTTPException(
                422,
                "URL no válida o destino no autorizado. Revisa el origen permitido y usa HTTPS para credenciales.",
            ) from None

    @api.get("/servers")
    def servers(
        auth=Depends(authenticated),
        db: Session = Depends(get_db),
        offset: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=100),
    ):
        items = db.scalars(
            select(Server).order_by(Server.created_at, Server.id).offset(offset).limit(limit)
        ).all()
        return {
            "items": [server_result(x) for x in items],
            "total": db.scalar(select(func.count()).select_from(Server)),
        }

    @api.post("/servers", status_code=201)
    def add_server(
        payload: ServerInput, auth=Depends(authenticated), db: Session = Depends(get_db)
    ):
        item = Server(**payload.model_dump())
        db.add(item)
        db.flush()
        db.add(AuditEvent(action="server.create", target_id=item.id))
        db.commit()
        return server_result(item)

    @api.put("/servers/{server_id}")
    def update_server(
        server_id: UUID,
        payload: ServerUpdate,
        auth=Depends(authenticated),
        db: Session = Depends(get_db),
    ):
        item = get_server(db, server_id)
        for key, value in payload.model_dump().items():
            setattr(item, key, value)
        db.add(AuditEvent(action="server.update", target_id=item.id))
        db.commit()
        return server_result(item)

    @api.get("/servers/{server_id}/services")
    def services(
        server_id: UUID,
        auth=Depends(authenticated),
        db: Session = Depends(get_db),
        offset: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=100),
    ):
        parent = get_server(db, server_id)
        query = select(Service).where(Service.server_id == parent.id)
        items = db.scalars(
            query.order_by(Service.created_at, Service.id).offset(offset).limit(limit)
        ).all()
        total = db.scalar(
            select(func.count()).select_from(Service).where(Service.server_id == parent.id)
        )
        return {"items": [service_result(x, parent.archived) for x in items], "total": total}

    @api.post("/servers/{server_id}/services", status_code=201)
    def add_service(
        server_id: UUID,
        payload: ServiceInput,
        auth=Depends(authenticated),
        db: Session = Depends(get_db),
    ):
        parent = get_server(db, server_id)
        if parent.archived:
            raise HTTPException(409, "Restaura el servidor antes de añadir servicios.")
        item = Service(
            server_id=parent.id,
            **payload.model_dump(exclude={"credentials", "url"}),
            url=checked_url(payload),
        )
        if payload.credentials:
            item.credentials_encrypted = encrypt_credentials(payload.credentials, settings)
        db.add(item)
        db.flush()
        save_revision(db, item)
        db.add(AuditEvent(action="service.create", target_id=item.id))
        db.commit()
        return service_result(item)

    @api.put("/services/{service_id}")
    def update_service(
        service_id: UUID,
        payload: ServiceUpdate,
        auth=Depends(authenticated),
        db: Session = Depends(get_db),
    ):
        item = db.scalar(select(Service).where(Service.id == str(service_id)).with_for_update())
        if not item:
            raise HTTPException(404, "Servicio no encontrado.")
        url = checked_url(payload)
        if payload.credentials and payload.clear_credentials:
            raise HTTPException(422, "No se pueden guardar y borrar credenciales a la vez.")
        if (
            item.credentials_encrypted
            and not payload.credentials
            and not payload.clear_credentials
            and urlsplit(item.url).netloc != urlsplit(url).netloc
        ):
            raise HTTPException(422, "Al cambiar de origen, sustituye o borra las credenciales.")
        if (
            not url.startswith("https://")
            and item.credentials_encrypted
            and not payload.clear_credentials
        ):
            raise HTTPException(422, "Borra las credenciales antes de configurar HTTP.")
        for key, value in payload.model_dump(
            exclude={"credentials", "clear_credentials", "url"}
        ).items():
            setattr(item, key, value)
        item.url = url
        if payload.clear_credentials:
            item.credentials_encrypted = None
        elif payload.credentials:
            item.credentials_encrypted = encrypt_credentials(payload.credentials, settings)
        item.revision += 1
        save_revision(db, item)
        db.add(AuditEvent(action="service.update", target_id=item.id))
        db.commit()
        return service_result(item, get_server(db, item.server_id).archived)

    @api.get("/services/{service_id}/status")
    def service_status(
        service_id: UUID, auth=Depends(authenticated), db: Session = Depends(get_db)
    ):
        item = get_service(db, service_id)
        return service_result(item, get_server(db, item.server_id).archived)

    app.include_router(api)
    return app
