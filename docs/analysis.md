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

En **Correo de la cuenta**, configura servidor SMTP, TLS directo (habitualmente 465) o STARTTLS obligatorio (habitualmente 587), usuario/contraseña si se requieren, remitente y destinatario. La contraseña se cifra con la clave privada de la instalación y nunca vuelve al navegador. El canal está **desactivado por defecto**. No se necesita correo para recoger datos o consultar incidentes.

La cola registra apertura, escalado, resolución y recordatorios con cooldown de una hora. No envía aperturas históricas de más de quince minutos ni entregas pendientes de más de una hora. Un fallo ambiguo de SMTP queda como `uncertain`: no se reintenta automáticamente porque el servidor pudo aceptar el mensaje antes de cortarse la conexión. Un proceso interrumpido durante el envío se marca igualmente para revisión. Consulta «Últimas entregas» en Correo. No se garantiza recepción hasta configurar y validar el proveedor real.

## GeoIP y retención

Country/ASN son enriquecimiento opcional **local** de las IPs ya observadas. Coloca las bases GeoLite2 Country/ASN en `geoip/`, siguiendo su licencia, o instala DB-IP Lite con el comando de la [guía de redes](networks-and-alerts.md). Docker las monta en solo lectura. Sin ellas, o sin coincidencia, aparece «Desconocido». No hay consultas a servicios externos; las consultas locales tienen caché acotada e invalidación al cambiar los archivos. Los datos GeoIP no identifican personas ni demuestran malicia.

Originales cifrados: siete días. Workers/IP/rutas: treinta días, incluidos los detalles coincidentes de incidentes. Series y agregados por dominio: noventa días. La limpieza corre cada hora. El backup diario cifrado y la restauración en una base vacía están descritos en [backups](backups.md). El archivo horario anual sigue pendiente.

API privada: `GET /api/v1/servers/{id}/analysis` (servicio, dominio y periodo opcionales), `GET /api/v1/servers/{id}/incidents` (paginado), `GET/PUT /api/v1/notifications`. Mantienen sesión local, Access en producción y CSRF en mutaciones.

## Resumen temporal en la home

Cada servidor muestra una fila compacta por servicio configurado (incluidos varios del mismo tipo), con las últimas 24 horas en tramos de treinta minutos. En móvil cada fila se reparte en dos líneas. Los avisos de dominio aparecen en Apache; los de recursos se asignan al servicio MRTG de la métrica de evidencia. Los contadores generales conservan también los incidentes antiguos sin procedencia suficiente para asignarles una fila. En escritorio, pasar el ratón por un tramo muestra periodo, cobertura, dominios/recursos, servicio y fechas de apertura/resolución. También funciona con foco de teclado (Escape cierra el detalle) y toque en móvil. «Ver incidentes» abre el listado completo.

El gris rayado indica cobertura insuficiente, nunca un servidor sano. Los tramos sin incidencias registradas tampoco garantizan ausencia de problemas entre recogidas. La prioridad representada es la registrada en el incidente (incluye escalados), no una reconstrucción exacta de cada cambio de severidad. Si se alcanza el límite de registros del resumen se indica que la vista es parcial.

Los incidentes muestran además la fase de evaluación: anomalía vigente, recuperación (muestras válidas respecto al número configurado), espera de datos o recuperación confirmada. El último valor anómalo y su fecha son evidencias históricas; no se presentan como una lectura actual durante la recuperación.

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

**Verde** significa lecturas completas sin avisos registrados, no ausencia garantizada de problemas. Para un tramo se exigen al menos cinco intervalos correctos, y en MRTG todas las métricas seleccionadas de la revisión actual, con fechas de origen recientes. Las lecturas fallidas, parciales o antiguas se muestran en naranja; los huecos, en gris. El estado actual se muestra junto al nombre, incluidas pausa y archivo. Cambiar una revisión deja sin cobertura comparable sus lecturas anteriores.

GoAccess guarda ahora un resultado de comprobación cada cinco minutos, separado del informe deduplicado, con retención de 90 días y limpieza también en backup/restauración. Su franja comienza con esta versión; no inventa comprobaciones pasadas a partir de informes antiguos. Un informe desactualizado permanece en naranja aunque su URL responda.
