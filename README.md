# Apache Status Monitor

Monitor open source para organizar varios servidores y sus servicios Apache Status y MRTG.

**SMON-002 en desarrollo: recogida de Apache operativa.** Incluye autenticación con TOTP, administración multiservidor, lectura periódica de Apache Status y MRTG, histórico y detalle de workers. **MRTG también está operativo**, con descubrimiento de páginas, selección de métricas y estadísticas numéricas. Consulta el [alcance y la interpretación del diagnóstico](docs/apache.md).

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

React + TypeScript + Vite → Nginx → FastAPI → PostgreSQL. Un worker independiente con APScheduler mantiene el estado del planificador; los recolectores están pendientes. Cloudflared tiene un perfil opcional dedicado.

- [Arquitectura y seguridad](docs/architecture.md)
- [Instalación y recuperación](docs/deployment.md)
- [Desarrollo y pruebas](docs/development.md)
- [Plan de hitos](docs/roadmap.md)
- [Recogida y diagnóstico de MRTG](docs/mrtg.md)
- [Contribuir](CONTRIBUTING.md) · [Vulnerabilidades](SECURITY.md)

[Licencia MIT](LICENSE). Proyecto independiente, sin afiliación con Apache Software Foundation.
