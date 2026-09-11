# Recogida y diagnóstico de Apache Status

La primera entrega de SMON-002 consulta los servicios Apache habilitados desde el worker, respetando el intervalo configurado (300 segundos por defecto). MRTG también dispone de [recogida numérica](mrtg.md), en un trabajo independiente. Abre **Ver diagnóstico** en la fila de un servicio para consultar las últimas 50 muestras y sus workers paginados. **Actualizar histórico** vuelve a leer la base de datos; no fuerza una petición remota.

Se conservan servicio, fecha UTC y revisión en cada intento, también cuando falla. Estados: esperando primera recogida, correcto, parcial, error o desactualizado. Un intervalo sin muestras no se convierte en cero tráfico. Se advierte de huecos respecto a la última muestra válida y de descensos de uptime o contadores que indican reinicio o reinicialización. Los contadores no se comparan entre revisiones diferentes.

## Interpretación

El parser identifica las columnas por su cabecera. Las filas de workers inactivos son últimas peticiones; las filas de los restantes estados muestran actividad instantánea. Las apariciones de un dominio o IP no representan el volumen total de visitas. No se atribuyen los contadores acumulados de un worker a su último dominio. Las rutas almacenadas excluyen parámetros y fragmentos.

`SS` indica segundos desde el inicio de la petición más reciente; `Req` es la duración reportada en milisegundos. La interpretación depende del estado del worker. Los datos globales de `?auto` se recogen en una segunda petición y pueden corresponder a un instante ligeramente posterior al HTML. Se muestran como métricas globales, no como sumas por dominio. Si falla `?auto`, se conserva el detalle HTML con una advertencia de cobertura parcial.

Referencia de semántica: [documentación oficial de mod_status](https://httpd.apache.org/docs/2.4/mod/mod_status.html).

## Límites y privacidad

- DNS con tiempo límite, validación de todas las direcciones devueltas y conexión fijada a una IP pública. Host y SNI conservan el nombre autorizado.
- TLS con verificación, sin proxies de entorno ni seguimiento de redirecciones. HTTP solo para orígenes explícitamente autorizados.
- Máximo 2 MiB por respuesta, DNS hasta tres segundos por familia y conexión/lectura hasta quince segundos por petición. Dos servicios como máximo por proceso worker; desplegar una sola réplica del worker.
- Bloqueo de fila del servicio para impedir recogidas concurrentes, cambios de configuración durante la consulta y duplicados al reiniciar el worker.
- Originales cifrados siete días; workers, IP y rutas treinta días; muestras noventa días. La limpieza se ejecuta al arrancar y cada hora. La API aplica también los plazos de acceso aunque la limpieza esté retrasada.

La API `/api/v1/services/{id}/observations` lista muestras y `/api/v1/observations/{id}` pagina los workers. El original se entrega exclusivamente como texto dentro de JSON mediante `POST /api/v1/observations/{id}/raw`, con sesión, CSRF, email, contraseña y segundo factor actual. La consulta queda auditada; no hay una vista que ejecute HTML remoto.

## Trabajo pendiente del hito

Esta entrega permite empezar a observar Apache. SMON-002 aún no está cerrado: faltan agregados horarios con retención anual, backup diario cifrado y restauración automatizada. No hay gráficos temporales, alertas ni diagnóstico automático de ataques. Mantén las copias privadas manuales; los originales de depuración no deben incluirse en backups de larga retención.
