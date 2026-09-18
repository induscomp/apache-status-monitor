# Desarrollo y validación

Python 3.14, uv 0.12.12, Node 24 y Docker/Compose. Instala `uv sync --frozen` en backend y `npm ci --ignore-scripts` en frontend.

```bash
cd backend
.venv/bin/ruff check app migrations tests
.venv/bin/ruff format --check app migrations tests
.venv/bin/pip-audit --progress-spinner off
cd ../frontend
npm run build
npm audit --audit-level=high
```

## Pruebas con PostgreSQL y navegador

Desde la raíz:

```bash
bash scripts/test-backend.sh
cd frontend
npx playwright install chromium
cd ..
SMON_RUN_E2E=1 bash scripts/test-backend.sh
```

Se crea un PostgreSQL temporal con puerto aleatorio en loopback, contraseña aleatoria y base `smon_test`. Solo se eliminan ese contenedor y sus secretos temporales al terminar; no se usan los datos del Compose principal.

La suite prueba migraciones, diferencias de esquema, autenticación/API y downgrade/upgrade sobre datos descartables. Nunca replicar downgrade en producción.

E2E arranca backend en 8189 y Vite en 4173; falla si están ocupados. Solo usa datos sintéticos y cuenta temporal. Recorre login, varios servidores/servicios, pausa independiente, persistencia, escritorio/móvil y logout. Capturas/trazas en `frontend/test-results/`, excluido de Git.

## Cobertura

- Origin/CSRF, autenticación, expiración, revocación, TOTP/recuperación y rate limit persistente.
- JWT Access: clave/firma, emisor, audience, emisión, caducidad e identidad local.
- Producción falla cerrada sin Access.
- Credenciales cifradas y ausentes en respuestas/revisiones; credenciales HTTP rechazadas.
- Orígenes no autorizados, credenciales/query en URL y literales internos rechazados.
- Servicios independientes, revisión, archivo, pausa y paginación.
- Cuerpos limitados incluso con transferencia chunked, errores sin reflejar secretos.
- Heartbeat y estados pendientes sin lecturas simuladas.

La suite también prueba parsers Apache/MRTG, transporte contra DNS rebinding, series, retención, referencias por dominio/servicio, presión de RAM incluso con slots libres o Apache incompleto, idempotencia, confirmación/recuperación, correo cifrado y deduplicación. El navegador recorre estado, gráficos, rankings, incidentes y correo desactivado, en escritorio/móvil. Backup/restauración prueban cifrado, orden, truncamiento, claves incorrectas, destino no vacío, rotación y limpieza de datos vencidos.

Las pruebas de GoAccess cubren JSON sin ejecución de scripts, fechas antiguas/futuras, deduplicación, revisiones, separación de servidores y eliminación de IPs/rutas vencidas. Se verifican las autorizaciones por origen sin eludir SSRF, la negociación STARTTLS antes de credenciales y el recorrido Inicio → servidor → informe, con texto remoto escapado.

CI ejecuta lint, auditorías, build, pruebas y arranque Docker. Acciones fijadas por SHA, permisos de lectura, checkout sin credenciales persistidas y artefactos solo sintéticos. Secretos excluidos de Git y contextos Docker.

Actualizar lockfiles y repetir auditorías en cada cambio de dependencias. No publicar fixtures reales con IP, dominios, rutas, endpoints internos o credenciales. Crear ejemplos sintéticos.

Commit `SMON-001: descripción` en rama y pull request; main sigue protegida. La fusión requiere revisión independiente del funcionamiento local.
