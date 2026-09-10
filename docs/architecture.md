# Arquitectura de SMON-001

## Modelo y procesos

Un servidor agrupa varios servicios. Cada servicio tiene tipo (`apache_status` o `mrtg`), nombre, URL, intervalo (300 segundos por defecto, mínimo 60), opciones, credenciales opcionales, estado y revisión. Se admiten varios servicios del mismo tipo. Los nombres de servidor son únicos; los de servicio son únicos dentro de su servidor.

PostgreSQL almacena `servers`, `services`, `service_revisions`, `admins`, `auth_sessions`, `rate_buckets`, `audit_events` y `component_heartbeats`. Cada edición de servicio crea una revisión sin credenciales ni ciphertext. Archivar un servidor suspende efectivamente todos sus servicios conservando sus estados individuales. No hay borrado físico en la API.

Los futuros snapshots, dominios, IP y alertas se asociarán al servicio y su revisión. Un mismo dominio en dos servicios no compartirá contadores ni referencias estadísticas.

| Proceso | Responsabilidad |
|---|---|
| backend | FastAPI, SQLAlchemy/psycopg con pool limitado, autenticación y configuración |
| worker | APScheduler 3.x; heartbeat cada 30 segundos y limpieza de sesiones/rate limits cada hora |
| postgres | PostgreSQL 18, volumen persistente y sin puerto publicado |
| nginx | Frontend compilado y proxy; sin Node en producción |
| cloudflared | Perfil tunnel dedicado; no modifica otros túneles |
| migrate | Tarea única previa al backend/worker; roles y migraciones Alembic |

Solo `migrate` y PostgreSQL reciben la credencial propietaria. El rol de aplicación `smon` no puede crear roles, bases o tablas ni es superusuario. El propietario aplica migraciones y concede permisos de datos.

Los descriptores de conectores declaran `implemented=false`. No hay recogida remota, rutas públicas para ejecutar tareas ni carga de plugins arbitrarios.

## API implementada

Prefijo `/api/v1`. Access obligatorio en producción; recursos privados requieren también sesión local.

| Recurso | Operación |
|---|---|
| POST /auth/login | Email, contraseña y TOTP/recuperación; cookie HttpOnly y token CSRF |
| GET /auth/session | Cuenta y token CSRF |
| POST /auth/logout | Revocar sesión actual |
| POST /auth/revoke-sessions | Revocar todas las sesiones |
| GET /connectors | Tipos y estado de implementación |
| GET, POST /servers | Listar/crear servidores |
| PUT /servers/{id} | Editar, archivar o restaurar |
| GET, POST /servers/{id}/services | Listar/crear servicios |
| PUT /services/{id} | Editar, pausar o archivar/restaurar; incrementar revisión |
| GET /services/{id}/status | Estado efectivo sin lecturas ficticias |
| GET /health | Base de datos, heartbeat y funcionalidades pendientes |

Listados `{items,total}` con `offset=0`, `limit=50`, máximo 100. PUT recibe configuración editable completa; tipo y servidor del servicio son inmutables. Cuerpos limitados a 16 KiB, incluidos mensajes chunked. Los errores no reflejan entradas.

`/health/live` y `/health/ready` son probes internos mínimos bloqueados por Nginx. `/healthz` comprueba solo Nginx. Series, dominios, eventos y alertas tendrán API en sus hitos.

## Autenticación

Producción exige HTTPS, dominio de equipo `*.cloudflareaccess.com` y audience. Se valida JWT RS256: firma, emisor, audiencia, expiración, emisión, sujeto y email. JWKS procede del dominio configurado, nunca del token; timeout de cinco segundos y caché de cinco minutos. Claves desconocidas no fuerzan descargas por petición. Una rotación puede requerir hasta cinco minutos, denegando acceso mientras tanto.

El email de Access debe coincidir con el administrador local. Sesiones de ocho horas con token almacenado como hash. En HTTPS, cookie `__Host-smon`, Secure, HttpOnly y SameSite=Strict. Mutaciones requieren Origin exacto y, salvo login, token CSRF.

TOTP y recuperación se consumen bajo bloqueo de fila; no admiten reutilización concurrente. Tolerancia TOTP de un paso. Alta y cambios de contraseña/MFA son locales e interactivos. Cambiar contraseña o MFA revoca sesiones. No hay registro público ni contraseña por defecto.

Rate limiting atómico en PostgreSQL: cinco intentos por cuenta/cinco minutos y 30 globales/minuto. No depende de cabeceras IP. Access debe restringir previamente la identidad.

Credenciales de endpoints y secreto TOTP cifrados con Fernet y clave externa. Nunca aparecen en respuestas, revisiones o logs. Conserva la clave fuera del equipo para recuperación; no hay rotación automática en este hito.

## Destinos y límites actuales

Orígenes exactos mediante `SMON_ALLOWED_MONITOR_ORIGINS`; HTTP requiere además `SMON_ALLOWED_HTTP_ORIGINS`. Se rechazan credenciales/query en URL, esquemas ajenos a HTTP(S), literales no públicos y caracteres ambiguos. Basic solo se permite con HTTPS.

**Esta es validación de configuración, no un transporte SSRF completo.** SMON-002 deberá validar todas las resoluciones IPv4/IPv6 y conectar a una IP aprobada conservando TLS/hostname, bloquear redes internas/metadatos, desactivar redirecciones/proxies ambientales y limitar tamaño/tiempo/concurrencia. No habrá recogida hasta probar esos controles.

Estado de servicio: pendiente, pausado o archivado. Fechas de intento, éxito y próxima ejecución son nulas. El heartbeat prueba el worker local, no disponibilidad remota.

Logs de aplicación JSON con evento, método y duración; sin URL, query, cuerpos o tokens. Logs de acceso Uvicorn/Nginx desactivados. Auditoría administrativa persistente en PostgreSQL.

## Referencias

- [Apache mod_status](https://httpd.apache.org/docs/2.4/mod/mod_status.html)
- [OWASP SSRF](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Validación de JWT Access](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)
- [PyOTP](https://pyauth.github.io/pyotp/)
