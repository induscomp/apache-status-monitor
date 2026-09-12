# Apache Status Monitor

Monitor open source para organizar varios servidores y sus fuentes Apache Status, MRTG y GoAccess.

Monitorización cada cinco minutos con **fuentes públicas configurables por servidor: Apache Status, MRTG y GoAccess**. Incluye estado del servidor, gráficos temporales, rankings por dominio/IP/ruta, correlación con memoria/carga e incidentes basados en el histórico de cada dominio. Correo SMTP configurable y GeoIP local opcional. Consulta [uso, interpretación y límites](docs/analysis.md).

GoAccess conserva los totales del periodo del informe y muestra su antigüedad; no mezcla esos totales con muestras instantáneas ni alertas actuales. La home reúne los servidores, con acceso a cada resumen y sus detalles.

## Incluye

- Varios servidores y servicios del mismo tipo; edición, pausa y archivo reversible.
- Contraseña Argon2id, TOTP, recuperación, sesiones revocables y CSRF.
- Cloudflare Access con validación de JWT en producción.
- PostgreSQL con migraciones y cuenta de aplicación sin permisos administrativos.
- Credenciales de endpoints cifradas y orígenes autorizados por el operador.
- Interfaz responsive en español, pruebas con PostgreSQL/navegador y CI.
- Diagnóstico Apache con muestras por servicio, cobertura parcial y originales cifrados.

## Inicio local

Requisitos: Docker Engine, Docker Compose y Python 3 para generar secretos. Los contenedores usan Python 3.14; no se modifica el Python del equipo.

```bash
cp .env.example .env  # solo si no existe
python3 scripts/init-secrets.py
docker compose -f compose.yaml -f compose.local.yaml up --build -d --wait
```

Abre **http://localhost:8187** y completa el asistente web: copia la clave del archivo `secrets/setup_token`, elige email y contraseña, escanea el QR y guarda los códigos de recuperación. No hace falta crear el usuario desde la terminal. Si ya existe un administrador, aparece el login y el asistente queda cerrado. No hay cuenta ni contraseña predeterminada. Ajusta `SMON_UID`/`SMON_GID` en `.env` si no son 1000.

**El perfil local omite Access y solo publica en loopback. No lo uses detrás de un túnel público.** Consulta [despliegue](docs/deployment.md) para acceso remoto y configuración de los orígenes monitorizables.

## Arquitectura y documentación

React + TypeScript + Vite → Nginx → FastAPI → PostgreSQL. Un worker independiente con APScheduler recoge Apache, MRTG e informes GoAccess, correlaciona muestras, evalúa incidentes y procesa el correo configurado. Cloudflared tiene un perfil opcional dedicado.

- [Fuentes por servidor, GoAccess y correo de la cuenta](docs/goaccess.md)
- [Estado del servidor, incidentes, correo y GeoIP](docs/analysis.md)
- [Backup cifrado y recuperación](docs/backups.md)
- [Arquitectura y seguridad](docs/architecture.md)
- [Instalación y recuperación](docs/deployment.md)
- [Desarrollo y pruebas](docs/development.md)
- [Plan de hitos](docs/roadmap.md)
- [Recogida y diagnóstico de MRTG](docs/mrtg.md)
- [Contribuir](CONTRIBUTING.md) · [Vulnerabilidades](SECURITY.md)

[Licencia MIT](LICENSE). Proyecto independiente, sin afiliación con Apache Software Foundation.
