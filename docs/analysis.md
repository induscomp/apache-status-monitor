# Estado del servidor e incidentes

La navegación comienza en **Inicio → Mis servidores → Ver servidor**. El resumen conserva las franjas temporales; **Gráficos y rankings** amplía los datos. Las fuentes se configuran por servidor y el correo por cuenta. Consulta [fuentes opcionales y GoAccess](goaccess.md).

## Fuentes y uso

El análisis de incidentes utiliza **Apache Status público y MRTG público**. El conector opcional **GoAccess** presenta informes históricos separados, con su periodo y frescura, sin alimentar las alertas actuales. No necesita shell del servidor observado, logs, PHP-FPM, systemd ni APIs del hosting. El worker local de Docker consulta cada fuente configurada cada cinco minutos. MRTG descubre páginas siguiendo los enlaces que contienen imágenes: extrae números de comentarios o tablas, sin OCR. Las métricas seleccionadas conservan sus ventanas y canales en PostgreSQL.

En el panel:

1. Selecciona el servidor en la barra lateral.
2. **Estado del servidor** resume las fuentes disponibles, recursos e incidencias. Selecciona un servicio Apache si hay varios.
3. Abre **Gráficos y rankings** para ampliar las últimas 24 horas; pulsa un dominio para ver su histórico. El ranking de conexiones corresponde a workers activos con IP; el de apariciones suma presencia en muestras durante el periodo.
4. **Incidentes** muestra anomalías abiertas/resueltas, su referencia estadística y las lecturas de MRTG, dominios, IPs y patrones coincidentes.
5. **Configuración** permite añadir y editar fuentes. Desde el resumen y desde su fila puedes abrir el diagnóstico Apache, MRTG o GoAccess, incluidos originales Apache/MRTG, descubrimiento y selección de métricas.

La correlación se calcula tras un margen de 90 segundos para que ambos recolectores terminen. El panel se actualiza cada 30 segundos; esto no aumenta la frecuencia de consulta remota. Reiniciar el worker no duplica los análisis. El bloqueo de análisis es por servicio y se comparte entre réplicas mediante PostgreSQL.

Consulta también la [guía de avisos, proveedores y unidades de memoria](networks-and-alerts.md).

## Interpretación y límites

- **Muchos slots libres no prueban salud.** Nunca producen una etiqueta «servidor sano». Las anomalías de memoria/carga se evalúan aunque Apache devuelva una muestra incompleta o falle.
- Apache Status y MRTG no confirman errores HTTP 500, consumo de RAM por dominio ni la causa de una caída. Los incidentes muestran coincidencias, no culpables.
- Una muestra cada cinco minutos no cuenta todas las visitas ni conexiones transitorias. Un worker idle puede mostrar su última petición. No se atribuyen sus contadores acumulados al último VHost.
- Los POST a rutas sensibles son candidatos a revisión, no ataques confirmados. También pueden ser legítimos. Las URLs almacenadas excluyen query y fragmento.
- Req/s, bytes/s y tiempo medio entre muestras se calculan por diferencias de contadores globales comparables, sin reinicio ni huecos superiores a diez minutos. La media usa duración acumulada / peticiones acumuladas, nunca el inverso de req/s. Si Apache no ofrece un contador necesario, se muestra «Sin dato».
- Los huecos y cambios de revisión/escala interrumpen las líneas del gráfico.

## MRTG y unidades

El reconocimiento usa títulos y etiquetas de las páginas observadas. En «Memoria Libre» se toma el canal etiquetado **Memoria Física Libre**, no el de memoria total. La carga con título explícito «* 100» se divide por 100; una etiqueta heredada B/s no convierte carga en tráfico. CPU no se limita al 100%, ya que la página puede expresar actividad agregada.

Las unidades no verificadas se muestran como **valor de origen**. No se inventan GB, porcentajes de capacidad ni totales disponibles. En tablas se respetan los prefijos SI reconocidos al escalar cifras; se conserva una referencia separada de los comentarios. En el diagnóstico MRTG se pueden verificar unidad, factor y zona horaria para las métricas cuya semántica se conozca.

Se correlacionan muestras del mismo servidor entre cinco minutos antes y dos después de Apache. Una fecha de origen con más de quince minutos de diferencia se excluye. Si no se conoce la zona horaria, se indica correlación por hora de recogida y se detectan páginas cuya fecha permanece congelada más de quince minutos. Esto no puede verificar la antigüedad inicial de una página sin zona conocida. Reutilizar una misma actualización MRTG no confirma dos anomalías independientes.

## Referencias y alertas

Cada dominio se compara únicamente con su propio histórico del mismo servicio y revisión. Ventana de 24 horas, excluyendo los últimos 30 minutos; mediana y desviación absoluta mediana (MAD). Se requieren al menos **170 intervalos válidos de cinco minutos**. Hasta entonces el panel muestra aprendizaje/cobertura, no una falsa certeza. Las ausencias de un dominio en muestras completas cuentan como cero; una recogida fallida no cuenta como cero.

Actividad anómala inicial: al menos tres veces la mediana, con incremento mayor o igual a `max(5, 6 × max(1, 1.4826 × MAD))`. Se comparan workers activos y apariciones. Son criterios relativos con un mínimo de evidencia; no estiman tráfico total ni probabilidad de ataque.

Para RAM/swap se busca una caída a la mitad de la mediana y al menos tres MAD; CPU/carga, una duplicación y al menos tres MAD. Requieren doce intervalos históricos comparables, también excluyendo los últimos treinta minutos. Las comparaciones separan métricas, canales, revisiones, unidades y origen tabla/comentario.

Dos muestras anómalas consecutivas abren un incidente. Tres muestras válidas recuperadas lo resuelven. Un hueco o muestra inválida rompe la confirmación; la falta de datos nunca resuelve. La referencia de apertura permanece fija durante el incidente para que un problema prolongado no se vuelva «normal». La prioridad es media, o alta ante presión de recursos o actividad diez veces superior a la mediana. Requiere calibración con datos reales; no es una probabilidad de ataque.

## Email privado

En **Correo de la cuenta**, configura servidor SMTP, TLS directo (habitualmente 465) o STARTTLS obligatorio (habitualmente 587), usuario/contraseña si se requieren, remitente y destinatario. La contraseña se cifra con la clave privada de la instalación y nunca vuelve al navegador. El canal está **desactivado por defecto**. Guarda la configuración, pulsa **Comprobar y enviar prueba**, comprueba la bandeja del destinatario y activa los avisos guardando de nuevo. La aceptación SMTP no garantiza llegada a la bandeja de entrada. Cualquier cambio de conexión, credenciales o direcciones invalida la comprobación. No se necesita correo para recoger datos o consultar incidentes.

La cola registra apertura, escalado, resolución y recordatorios con cooldown de una hora. No envía aperturas históricas de más de quince minutos ni entregas pendientes de más de una hora. Un fallo ambiguo de SMTP queda como `uncertain`: no se reintenta automáticamente porque el servidor pudo aceptar el mensaje antes de cortarse la conexión. Un proceso interrumpido durante el envío se marca igualmente para revisión. Consulta «Últimas entregas» en Correo. No se garantiza recepción hasta configurar y validar el proveedor real.

## GeoIP y retención

Country/ASN son enriquecimiento opcional **local** de las IPs ya observadas. Coloca las bases GeoLite2 Country/ASN en `geoip/`, siguiendo su licencia, o instala DB-IP Lite con el comando de la [guía de redes](networks-and-alerts.md). Docker las monta en solo lectura. Sin ellas, o sin coincidencia, aparece «Desconocido». No hay consultas a servicios externos; las consultas locales tienen caché acotada e invalidación al cambiar los archivos. Los datos GeoIP no identifican personas ni demuestran malicia.

Originales cifrados: siete días. Workers/IP/rutas: treinta días, incluidos los detalles coincidentes de incidentes. Series y agregados por dominio: noventa días. La limpieza corre cada hora. El backup diario cifrado y la restauración en una base vacía están descritos en [backups](backups.md). El archivo horario anual sigue pendiente.

API privada: `GET /api/v1/servers/{id}/analysis` (servicio, dominio y periodo opcionales), `GET /api/v1/servers/{id}/incidents` (paginado), `GET/PUT /api/v1/notifications`. Mantienen sesión local, Access en producción y CSRF en mutaciones.

## Resumen orientado a decisiones del administrador

El resumen principal agrupa **Memoria RAM, Swap, CPU, Carga del servidor, Actividad por dominio y Conexiones por IP**. Apache/MRTG/GoAccess permanecen como fuentes en Configuración y en sus diagnósticos; sus fallos de recogida no se convierten automáticamente en presión de memoria o anomalías de dominio.

Cada indicador muestra lectura actual (memoria en unidades legibles), estado con texto, tramos de 30 minutos y detalle desplegable con fecha, referencia o ranking y acceso a gráficos/configuración/incidentes. Los recursos se evalúan individualmente con la sensibilidad configurada; un incidente de RAM no tiñe CPU ni dominios. La swap libre sin capacidad total verificada se marca **Uso sin determinar**, nunca verde por inferir una capacidad. El uso confirmado de swap aparece rojo. Un aviso abierto se conserva cuando faltan datos.

La fila de dominios utiliza los incidentes existentes y el histórico de cada servicio; el valor visible es el máximo de conexiones activas de un dominio en la última captura. Los servicios del mismo servidor no mezclan referencias ni suman el mismo dominio. La fila de IP presenta el máximo por IP y su proveedor si se conoce, y señala coincidencias con avisos de dominio. **Es una observación, no un detector independiente por IP**: su estado neutral azul evita confundir un ranking con una garantía de normalidad o un ataque demostrado. Tampoco cuenta peticiones totales entre capturas.

El histórico de recursos se apoya en las muestras correlacionadas de análisis disponibles y la lectura actual procede de MRTG; si no hay histórico correlacionado, no se rellena artificialmente. Gris indica evaluación insuficiente, y “Aprendiendo” la falta de referencia histórica. Verde en la franja significa lecturas suficientes sin incidentes registrados, no una reconstrucción de cada evaluación ni garantía de salud. Las fuentes antiguas como GoAccess no colorean estas filas.

## Ajustes de alertas por servidor

En **Configuración → Alertas de este servidor**, el administrador puede cambiar:

| Ajuste | Predeterminado | Rango |
|---|---:|---:|
| Multiplicador de actividad del dominio | 3 | 1,1–100 |
| Incremento mínimo de conexiones/apariciones | 5 | 1–10.000 |
| Caída de memoria libre respecto a la mediana | 50 % | 1–99 % |
| Multiplicador de CPU/carga | 2 | 1,1–100 |
| Muestras consecutivas para abrir | 2 | 2–12 |
| Muestras consecutivas para resolver | 3 | 2–12 |

Son parámetros del detector real, no cambios de color. Se conservan la cobertura mínima, el filtro MAD y el histórico propio de cada dominio/recurso. La memoria permanece naranja salvo uso de swap confirmado mediante capacidad total verificada; ese criterio prevalece sobre el porcentaje de caída. El envío SMTP sigue sujeto a su configuración y cooldown.

La API autenticada y protegida por CSRF es `GET/PUT /api/v1/servers/{id}/alert-settings`. Guardar una modificación incrementa su revisión y deja auditoría. Los incidentes guardan los parámetros utilizados como evidencia. Se reinician las confirmaciones pendientes de ese servidor; se conservan incidentes, históricos y referencias de apertura. Las nuevas reglas se aplican en las siguientes evaluaciones.

La API conserva las filas por fuente para compatibilidad y diagnóstico. En esas filas, **verde** significa lecturas completas sin avisos registrados, no ausencia garantizada de problemas. Para un tramo se exigen al menos cinco intervalos correctos, y en MRTG todas las métricas seleccionadas de la revisión actual, con fechas de origen recientes. Las lecturas fallidas, parciales o antiguas se muestran en naranja; los huecos, en gris. El estado actual se muestra junto al nombre, incluidas pausa y archivo. Cambiar una revisión deja sin cobertura comparable sus lecturas anteriores.

GoAccess guarda ahora un resultado de comprobación cada cinco minutos, separado del informe deduplicado, con retención de 90 días y limpieza también en backup/restauración. Su histórico de comprobaciones comienza con esta versión; no inventa comprobaciones pasadas a partir de informes antiguos. Un informe desactualizado permanece en naranja aunque su URL responda.

## Ranking compacto de dominios

El resumen incluye hasta doce dominios ordenados por la media de conexiones activas de las capturas válidas de las últimas 24 horas. Cada fila conserva su servicio Apache, muestra lectura actual y pico, y una mini gráfica con medias de 30 minutos en escala común. Una captura válida sin ese dominio cuenta como cero; un intervalo sin capturas queda vacío, no se convierte en cero. La última lectura fallida o antigua no se presenta como actual. Estos valores describen concurrencia observada, no visitas ni tráfico acumulado.

## Protección frente a bloqueos SMTP

La prueba manual usa una petición autenticada con CSRF, sin recargar la página. Como máximo se permite una prueba cada cinco minutos y tres por hora; guardar cambios no reinicia el tiempo de espera. No se activa un canal que no haya superado la prueba. Las configuraciones anteriores deben comprobarse de nuevo.

Cada conexión realiza un único método de autenticación, sin probar otros tras un rechazo. El primer fallo de envío suspende todo el canal e invalida la comprobación, incluso si aparecen incidencias nuevas. Los mensajes pendientes se suprimen mientras está desactivado y no se recuperan al activarlo. Los accesos de prueba, configuración y envío se serializan entre procesos. Una entrega incierta no se reintenta automáticamente; el administrador debe revisar los datos y realizar una nueva prueba. Se auditan las comprobaciones y suspensiones sin guardar contraseñas ni respuestas privadas del proveedor en los mensajes de error.

## Apache event y HTTP/2

La tabla de procesos/asíncronos de event se distingue de la tabla de workers por sus cabeceras. La columna opcional `Protocol` se conserva en cada observación. Los textos de sesión HTTP/2 (`[0/0] init`, `write: stream…`, etc.) no se interpretan como métodos ni URLs, ni se convierten sus contadores en peticiones. Las líneas de petición HTTP/2 reales se normalizan igual que las HTTP/1.1. Los campos `ConnsTotal` y `ConnsAsync*` disponibles en `?auto` se guardan separadamente de workers y requests.

El panel indica la cobertura limitada cuando detecta HTTP/2: los rankings describen la actividad visible del scoreboard, no todos los streams ni workers internos de HTTP/2. Los valores anteriores y posteriores a un cambio de protocolo deben compararse con cautela; la línea base móvil se adaptará a las nuevas observaciones. No se reescribe el histórico ni se inventan streams ocultos. Véase la [documentación de Apache sobre HTTP/2](https://httpd.apache.org/docs/2.4/mod/mod_http2.html#dimensioning).

## Recogida y evaluación son estados distintos

El resumen indica cuántos indicadores tienen lecturas de los últimos diez minutos. Esto acredita lecturas recientes para esos indicadores, no que todas las fuentes estén completas ni que el servidor esté sano. «Aprendiendo» explica la cobertura histórica pendiente tras huecos; no significa que el recolector esté parado. MRTG requiere una zona horaria configurada por métrica para validar las fechas de sus páginas. Una descarga reciente con fecha de origen sin interpretar permanece diferenciada de un dato fresco verificado. Cambiar la zona horaria crea una nueva revisión: las muestras antiguas no se reescriben ni se pintan retroactivamente como correctas.

## Contrastar unidades MRTG

El diagnóstico muestra juntos el valor extraído o convertido y el valor/etiqueta de la tabla pública, además del nombre del canal. Así pueden contrastarse los comentarios exactos con los valores redondeados visibles. Una etiqueta de origen no se considera automáticamente una unidad verificada: por ejemplo, una página de carga puede conservar «B/s». La falta de interpretación se presenta como una aclaración, no como un error de descarga. Las conversiones configuradas mantienen el valor original y su factor visibles; las estadísticas sin equivalente en la tabla se identifican como tales.

## Degradación de rendimiento

La recogida conserva BusyWorkers, IdleWorkers, estados W/R/K/C/_/., ms/request global publicado y su media entre capturas (diferencias de TotalDuration/TotalAccesses, solo sin reinicio y con intervalo válido), además de requests/s. Los agregados incluyen Req de filas R/W con una petición identificable: cantidad, media, máximo y p95 por captura/dominio. El p95 usa rango más próximo y requiere al menos 20 valores; nunca se promedian percentiles. Los originales de workers conservan los tiempos individuales con su retención de 30 días.

`Req` describe la petición más reciente del worker y puede valer cero mientras trabaja; no garantiza la duración final de la petición activa ni la latencia del navegador. Las sesiones HTTP/2 y sus streams no se reconstruyen. Referencia: [código de mod_status](https://github.com/apache/httpd/blob/2.4.x/modules/generators/mod_status.c).

Se excluye de clientes la coincidencia de IP `93.93.68.189` con `OPTIONS * HTTP/1.0`; otras peticiones de esa IP permanecen. Las sondas se cuentan como actividad interna aparte. Los contadores globales de Apache incluyen actividad interna que esta fuente no permite desglosar: se presentan como globales, nunca como tráfico de clientes. La detección global evita capturas donde se observan sondas internas; la detección por dominio usa solo clientes filtrados.

El detector compara cada servicio Apache (y cada dominio dentro de él) con las últimas 24 h, excluyendo 30 minutos recientes y muestras inválidas. Necesita 170 intervalos globales o 24 observaciones válidas del estadístico del dominio, y mediana positiva. Señala aumentos superiores a 3 veces la mediana y 6 desviaciones robustas (MAD × 1,4826), sin umbral absoluto en milisegundos. Media, máximo y p95 del dominio se evalúan separadamente, preservando el estadístico y referencia de apertura. Utiliza las confirmaciones configuradas (por defecto dos para abrir, tres para resolver), siempre prioridad media. La falta de muestras no resuelve avisos.

La evidencia destaca «latencia elevada con disponibilidad aparente» si CPU y carga MRTG están frescas, comparables y dentro de su referencia, y quedan workers idle y slots libres en niveles comparables a los habituales. Eso no descarta memoria insuficiente, esperas de aplicación ni demuestra causalidad. Se conserva la evidencia de RAM/swap para revisarla.

En Estado del servidor aparece el indicador de latencia; Gráficos y rankings incluye las series globales, estados y Req, y dominios ordenados por tiempo medio de la última captura. Seleccionar un dominio muestra su evolución. `python -m app.performance_backfill` reconstruye agregados de los workers todavía retenidos, sin reescribir originales ni reproducir correos/incidentes pasados. No rellena huecos ni reconstruye datos caducados. La banda de evaluación histórica empieza con el detector nuevo: reconstruir métricas no equivale a haber evaluado alertas en el pasado.

## Seguridad y anomalías (capturas, no atribución de ataques)

La sección se añade al resumen existente. Solo utiliza Apache Status y MRTG; GoAccess no participa en esta evaluación. Ofrece estado actual, IP y dominios con evidencias desplegables, coincidencias con degradación y rankings/series seleccionables de 1 h, 6 h, 24 h, 7 días y 30 días. Las tablas iniciales se pliegan para mantener compacto el resumen. Copiar una IP no ejecuta un bloqueo.

Se agregan únicamente filas actuales R/W/K/C, excluyendo las sondas internas identificadas. Los endpoints y Req proceden de R/W con peticiones identificables; no se atribuye una última URL de keepalive a un nuevo acceso. Se conservan concurrencia, distribución de estados, IP/dominios asociados, concentración y Req. Apariciones entre capturas no equivalen a solicitudes nuevas, y no permiten demostrar que una conexión permanezca abierta. No hay información suficiente para detectar rutas inexistentes/404. Los accesos a admin o AJAX también pueden ser legítimos.

Las referencias se aíslan por servicio y revisión. Se excluyen los últimos 30 minutos y se deduplican intervalos de cinco minutos. Se necesitan 24 capturas comparables; una IP necesita además aparecer en al menos 12 para tener referencia propia. Primero se usa el mismo día de semana y hora UTC si hay al menos tres fechas distintas/24 muestras; después la misma hora UTC con cuatro fechas/48 muestras; en otro caso las últimas 24 horas. Se reutilizan los parámetros configurables de incremento y MAD existentes. La ausencia de una IP en una captura completa es cero; un fallo de recogida no lo es.

La prioridad combina desviación de actividad, endpoints sensibles, POST y dispersión entre dominios/IP, aumentando con la recurrencia hasta cinco capturas. Es un orden de revisión, no una probabilidad. «Posible ataque» requiere desviación respecto a referencia, rutas sensibles y varias señales persistentes. «Pico probablemente legítimo» significa actividad repartida sin rutas sensibles visibles, no validación de legitimidad. La geolocalización utiliza exclusivamente la base local existente; los cambios de procedencia se muestran solo con cobertura suficiente, sin puntuar el país como malicioso.

La salud contrasta CPU, carga, RAM/swap libre, workers, slots, estados y tiempos con su referencia. MRTG sin fecha reciente no confirma degradación. Una bajada de swap libre no demuestra uso total sin capacidad conocida. Los posibles contribuyentes incluyen la captura actual y hasta tres anteriores; nunca se presentan como causas demostradas. «Normal» requiere además cobertura reciente de los cuatro recursos MRTG principales.

Los incidentes de seguridad necesitan al menos tres confirmaciones y la recuperación configurada. Reutilizan el control de idempotencia, huecos, correo y suspensión por fallo SMTP. Conservan una evolución acotada a 288 entradas, incluyendo capturas anteriores a la confirmación; la hora de apertura es la confirmación. No se generan correos al reconstruir agregados antiguos. La evolución de puntuaciones empieza con esta versión: las capturas anteriores sirven de referencia y rankings de actividad, pero sus alertas no se inventan.

Los agregados con IP y endpoints viven en `ServerFrame.details` y caducan a 30 días. La evolución y motivos de incidentes antiguos se depuran, junto con su identidad IP y estados de seguimiento inactivos. El comando de reconstrucción de agregados existente también incorpora estas señales desde workers aún retenidos, de forma idempotente, sin nuevas tablas, fuentes ni credenciales.
