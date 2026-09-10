# Instalación y operación de SMON-001

## Local

```bash
cp .env.example .env  # solo si no existe
python3 scripts/init-secrets.py
docker compose -f compose.yaml -f compose.local.yaml up --build -d --wait
docker compose -f compose.yaml -f compose.local.yaml exec backend python -m app.cli create-admin
```

Secretos creados una vez, sin sobrescribir, modo 0600 y carpeta 0700. Ajusta SMON_UID/SMON_GID para que backend/worker puedan leerlos. Nunca pongas secretos en chat, argumentos del shell, Git o issues.

El alta solicita email, contraseña (mínimo 14 caracteres), muestra clave/URI para registrar TOTP y exige un código válido antes de guardar. Muestra ocho códigos de recuperación de un uso; guárdalos en tu gestor de contraseñas. El email debe coincidir con Access en producción.

Abre **http://localhost:8187**. Este perfil solo publica en loopback y omite Access; **no lo expongas mediante un túnel**.

## Configuración de servicios

Ejemplo ficticio en `.env`:

```dotenv
SMON_ALLOWED_MONITOR_ORIGINS=["https://web.example.com","http://metrics.example.com"]
SMON_ALLOWED_HTTP_ORIGINS=["http://metrics.example.com"]
```

Son orígenes exactos sin rutas. Ejecuta Compose `up -d` con los mismos archivos tras cambiarlos. Crea el servidor y servicios en la web con URL completas. MRTG recibe el índice; su futuro conector seguirá los enlaces de las imágenes.

URL sin credenciales/query/fragmento. Apache `?auto` se configura aparte. Credenciales opcionales cifradas y solo con HTTPS; campos vacíos al editar conservan las anteriores, y la casilla de borrado las elimina.

## Producción con túnel dedicado

1. Crea una aplicación Access para un hostname dedicado, autoriza únicamente tu identidad y no añadas reglas bypass. Habilita HTTPS/HSTS para ese hostname.
2. Crea un túnel dedicado con destino `http://nginx:8080` dentro de Compose. No reutilices túneles de otros proyectos.
3. Guarda su token en `secrets/cloudflare_token`, modo 0600 y propietario SMON_UID. No uses `.env` o argumentos para el token.
4. Completa `.env`: `SMON_ENVIRONMENT=production`, `SMON_PUBLIC_ORIGIN=https://tu-hostname`, `SMON_CF_TEAM_DOMAIN=https://tu-equipo.cloudflareaccess.com`, `SMON_CF_AUDIENCE` con el AUD. Origen sin `/` final.
5. Detén el perfil local sin borrar datos: `docker compose -f compose.yaml -f compose.local.yaml down`.
6. Arranca sin el archivo local: `docker compose --profile tunnel up --build -d --wait`.
7. Si falta la cuenta: `docker compose exec backend python -m app.cli create-admin`.

Producción no publica puertos. Sin configuración Access válida no arranca el backend; sin JWT válido se deniega la API. Access no sustituye contraseña/TOTP local. El túnel no se activa durante el desarrollo.

Verifica desde fuera: identidad no autorizada rechazada por Access, identidad permitida llega al login, contraseña/TOTP incorrectos rechazados y logout revoca acceso. Las pruebas de JWT no sustituyen validar la política real de Cloudflare.

## Estado, contraseña y MFA

```bash
docker compose -f compose.yaml -f compose.local.yaml ps
docker compose -f compose.yaml -f compose.local.yaml logs --tail=100 backend worker migrate
docker compose -f compose.yaml -f compose.local.yaml exec backend python -m app.cli change-password
docker compose -f compose.yaml -f compose.local.yaml exec backend python -m app.cli reset-mfa
```

En producción omite el archivo local. Migración debe finalizar con código 0; el worker publica heartbeat. Recolectores todavía pendientes.

Cambiar contraseña/MFA exige contraseña actual y revoca sesiones. Un código de recuperación permite login una vez; no restablece automáticamente el autenticador. No hay recuperación pública ni usuario oculto.

Conserva una copia externa segura de la clave de cifrado: perderla impide descifrar TOTP y credenciales. Regenerar archivos no rota contraseñas PostgreSQL de un volumen existente; deben sincronizarse con sus roles.

## Actualizaciones y datos

Haz copia manual antes de cambiar esquema. Actualiza mediante PR y ejecuta `up --build -d --wait`; la tarea migrate aplica cambios antes de arrancar backend/worker. **No uses `down --volumes` para actualizar: elimina datos.**

El volumen persiste configuración. Backup diario cifrado, retención de métricas y restauración automatizada llegarán en SMON-002; no hay backups programados todavía. Conserva copias manuales privadas y claves separadas antes de guardar información importante.

Esta entrega no es una versión auditada para producción. Las pruebas cubren controles implementados, no recolectores futuros ni tu configuración externa de Access.
