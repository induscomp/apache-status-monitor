# Plan de implementación

Investigar qué dominios, IP, rutas y patrones observamos antes de una degradación, sin modificar el servidor remoto. Múltiples servidores y servicios independientes; un administrador con Access y contraseña/TOTP local.

| Hito | Entrega | Estado |
|---|---|---|
| SMON-001 | Docker, autenticación, Access, migraciones, administración multiservidor/servicios, conectores, healthchecks y CI | Implementado; ver development.md |
| SMON-002 | Transporte seguro, parser/recogida Apache, snapshots, originales cifrados, retención y backup | Pendiente |
| SMON-003 | Panel de métricas, históricos, dominio/IP y eventos manuales | Pendiente |
| SMON-004 | MRTG por enlaces de imágenes a páginas de detalle, selección, correlación y GeoLite local | Pendiente |
| SMON-005 | Anomalías explicables y email con deduplicación, escalado y resolución | Pendiente |
| SMON-006 | Antes/después, diagnóstico, restauración completa y documentación operativa | Pendiente |

Cada hito requiere explicar alcance, implementar en rama, probar, documentar y crear commit/pull request `SMON-XXX: descripción`. No avanzar automáticamente al siguiente ni modificar otros proyectos.

## Contrato de datos

- Cinco minutos por servicio inicialmente; bloqueos, idempotencia, reintentos limitados y fallos independientes.
- Snapshots no son logs de acceso. No convertir observaciones en peticiones o visitantes totales.
- Diferenciar SS, Req, Dur, estados y última petición; no asignar contadores históricos del worker al último VHost.
- Tasas globales por diferencias, detectando reinicios. Mostrar datos ausentes y cobertura.
- Servicio, revisión y timestamp UTC en observaciones; no mezclar fuentes.
- Original cifrado siete días; workers/IP/rutas normalizadas 30 días; agregados de cinco minutos 90 días; horarios un año. Rutas normalizadas sin parámetros/fragmentos. No sumar IP únicas como personas distintas.
- Backup diario cifrado, siete diarios/cuatro semanales; originales de depuración excluidos. Restauración con limpieza de datos vencidos. Destino externo configurable para proteger frente a pérdida del equipo.

## Análisis y UX

Qué destaca, desde cuándo, respecto a qué referencia y con qué evidencia. Estados con texto e iconos, responsive, sin animaciones innecesarias. Eventos manuales superpuestos y comparación antes/después sin afirmar causalidad.

GeoLite Country/ASN locales opcionales; API externas desactivadas. Clasificación de red, crawler y sospecha son atributos separados con procedencia/confianza. Datacenter no implica malicia; desconocido es válido.

Anomalías con mediana/MAD de 24 horas excluyendo los últimos 30 minutos; «aprendiendo» sin cobertura. Score versionado de prioridad, calibrado antes de correo real. Dos muestras significativas abren alerta, tres recuperadas resuelven, cooldown de una hora por igual severidad. Ausencia de datos no resuelve alertas.

Criterio final: tras 24–48 horas de captura válida, investigar actividad previa a degradación y su relación con MRTG/eventos, explicando resolución y límites.

Fuera de esta versión: ML, bloqueo de tráfico, administración remota, mapa mundial y clientes con cuentas aisladas.
