# Recogida y diagnóstico de MRTG

El conector está operativo. En la fila del servicio MRTG, pulsa **Ver diagnóstico**. El worker descubre el índice y recoge las páginas enlazadas desde imágenes. No descarga PNG, no usa OCR, no sigue enlaces externos y no intenta acceder a archivos `.log`.

## Descubrimiento y selección

Se admiten hasta 100 páginas HTML únicas bajo el mismo origen y directorio del índice. Se rechazan rutas fuera de ese directorio, credenciales en enlaces, consultas, rutas codificadas, redirecciones y recursos que no sean HTML. Se ignora cualquier `<base>` remoto. Se conserva el transporte compartido: IP pública validada y fijada, TLS verificado, límite de 2 MiB y plazos de DNS/conexión/lectura.

Las páginas nuevas se activan inicialmente para disponer de datos. Para excluir una, selecciónala, desmarca **Monitorizar esta página** y guarda. Su histórico se conserva. Si una página desaparece del índice, deja de consultarse; si reaparece, recupera su selección anterior.

El descubrimiento se actualiza diariamente. **Redescubrir páginas** encola una petición administrativa protegida por sesión, CSRF y límites de intentos. No hace peticiones remotas desde la API. Un servicio pausado o archivado no ejecutará la tarea hasta volver a habilitarlo. Se limita el redescubrimiento a una vez por minuto y los reintentos fallidos a cinco minutos.

## Qué datos se guardan

Se prefieren los comentarios `cuin`, `cuout`, `avin`, `avout`, `maxin`, `maxout`, `avmxin` y `avmxout`. Como alternativa por estadística, se leen las tablas visibles con columnas Max, Average y Current. Cada cifra conserva ventana (`d`, `w`, `m`, `y`), canal (`in`, `out`), estadística y procedencia. Las ventanas diaria, semanal, mensual y anual nunca se suman ni se mezclan.

Se guardan fecha UTC de recogida, revisión del servicio, revisión y copia de configuración de la métrica, fecha de origen cuando puede interpretarse, texto original de esa fecha y avisos. Las observaciones se conservan 90 días y sus originales cifrados siete días, con limpieza al arrancar y cada hora. El histórico de la web muestra las últimas 50 muestras por página; la API permite paginar.

## Unidades, escalas y frescura

MRTG puede mostrar bytes en comentarios y bits en tablas. También puede reutilizar etiquetas de tráfico en gráficas de carga. Por eso los valores aparecen inicialmente **sin interpretar**. Una cifra de una tabla conserva su etiqueta y prefijo tal como aparecen; por ejemplo, `1.2 kB/s` no se convierte silenciosamente en `1200 B/s`.

En **Unidades, escala y zona horaria**, una interpretación verificada requiere unidad y factor explícitos. Esa conversión se aplica **solo a los comentarios**; las tablas alternativas siguen mostrando su valor y etiqueta originales. Las configuraciones nuevas se aplican a las siguientes muestras: no alteran cifras históricas ni mezclan las revisiones. No se deduce automáticamente que CPU tenga un máximo del 100 % ni que una gráfica de carga use realmente B/s.

La zona horaria del servidor no se deduce de su nombre o localización. Se puede introducir una zona IANA conocida. Sin ella se conserva el texto de actualización y se indica **frescura sin verificar**. Se advierte cuando una fecha interpretada lleva más de 15 minutos sin actualizarse, está más de cinco minutos en el futuro o resulta ambigua por un cambio horario. El formato de fecha soportado inicialmente es el inglés generado por la plantilla MRTG inspeccionada.

## Operación y API

Apache y MRTG tienen trabajos y grupos de ejecución independientes, con dos consultas concurrentes por conector en un único worker. Un fallo de página genera una muestra de error sin detener las demás. El bloqueo por métrica evita duplicados entre ticks o réplicas; se comprueban también intervalo, pausa, archivo, revisión del servicio y ruta autorizada antes de consultar.

- `GET /api/v1/services/{id}/mrtg`: catálogo, descubrimiento y última muestra de cada métrica.
- `POST /api/v1/services/{id}/mrtg/discover`: encolar descubrimiento.
- `PUT /api/v1/mrtg/metrics/{id}`: selección, unidad, factor, verificación y zona horaria.
- `GET /api/v1/mrtg/metrics/{id}/observations`: histórico paginado.
- `POST /api/v1/observations/{id}/raw`: original como texto JSON, con contraseña, segundo factor, CSRF y auditoría; nunca HTML ejecutable.

La configuración exige autenticación; los originales no se incluyen en el catálogo ni en el histórico normal. El proyecto sigue sin enviar correo ni activar alertas basadas en métricas cuya semántica no esté verificada.

Pendientes del plan general: gráficos de correlación temporal, GeoLite local opcional, agregados horarios, backup/restauración automáticos y alertas explicables. La recogida numérica de Apache y MRTG ya permite trabajar con datos reales mientras se incorporan esas capacidades.
