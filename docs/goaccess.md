# Fuentes por servidor y GoAccess

## Navegación y configuración

Al entrar, **Inicio → Mis servidores** resume los servidores de la instalación, sus incidentes abiertos y la frescura de cada fuente. **Ver servidor** abre su resumen, la franja temporal de incidencias Apache y las fuentes disponibles. **Ampliar gráficos y rankings** muestra el análisis detallado. Cada fuente tiene además su propio diagnóstico.

En **Añadir servidor**, guarda nombre y descripción; se abre su configuración. Añade únicamente las fuentes disponibles: Apache Status, MRTG o GoAccess. Puedes tener varios servicios del mismo tipo, pausarlos o archivarlos conservando el histórico. No se exige disponer de los tres sistemas.

La cuenta administradora autoriza el origen público exacto al guardar cada fuente. HTTPS es el valor recomendado; HTTP requiere marcar una excepción explícita para ese servicio. No se admiten direcciones internas, credenciales o parámetros en la URL, redirecciones ni certificados inválidos. La autorización no desactiva los controles de DNS y SSRF. Las listas de orígenes del despliegue siguen sirviendo para servicios anteriores sin autorización individual. Las credenciales Basic requieren HTTPS.

Esta versión mantiene **un administrador por instalación**. Su home reúne todos sus servidores y su configuración SMTP es común. No implementa cuentas de clientes aisladas ni asignación de servidores entre usuarios.

## Informes GoAccess

Configura la URL del **informe HTML público**. El worker la consulta cada cinco minutos y lee el JSON embebido en `var json_data`; no ejecuta JavaScript ni inserta el HTML remoto en la aplicación. No accede a logs internos ni necesita shell en el servidor monitorizado.

Se guardan fecha de generación y periodo, peticiones procesadas/válidas, visitantes según GoAccess, bytes, y hasta 500 filas por panel de dominios, peticiones, IPs, códigos HTTP y actividad por fecha. Se conservan los códigos individuales cuando están anidados en grupos. `failed_requests` representa líneas que GoAccess no pudo procesar, **no errores HTTP 500**. No se almacenan las rutas internas de logs incluidas en el informe. Las URLs se guardan sin parámetros ni fragmentos; el contenido se muestra como texto escapado.

Un informe sin cambios no crea cientos de copias: el estado de consulta se actualiza cada cinco minutos y el contenido se deduplica por servicio, revisión y huella. El diagnóstico muestra los últimos 30 informes distintos, el periodo y la fecha del último informe. **No deben sumarse informes sucesivos**, pues sus periodos pueden solaparse. Los rankings GoAccess se presentan separados de las apariciones instantáneas de Apache.

Por defecto un informe de más de **26 horas** figura como desactualizado. El máximo es configurable por fuente (1–720 horas). Una fecha ausente o futura no verificable se marca como parcial. Consultar hoy un informe antiguo no lo convierte en reciente. GoAccess no participa en el motor de anomalías en tiempo real ni genera alertas por cifras históricas. El informe facilitado durante el desarrollo estaba generado el 13 de marzo de 2026; su contenido real no forma parte del repositorio ni de las pruebas.

Los informes se conservan 90 días, excepto el último referenciado por el estado de consulta. Los detalles de IP y peticiones desaparecen a los 30 días desde su primera recogida, también en API y restauración. Se respalda el resumen normalizado, nunca el HTML remoto.

## Fuentes opcionales y límites

Apache aporta presencia instantánea y referencias por dominio; MRTG aporta recursos. Con solo MRTG se muestran recursos e histórico comparable de su configuración actual. Las métricas conocidas se identifican por título y canal; las restantes siguen disponibles en el diagnóstico MRTG para interpretar sus unidades. Sin Apache no se calculan anomalías por dominio. Con solo GoAccess se muestra el informe y su frescura, sin inventar gráficos instantáneos ni exigir una tabla Apache inexistente.

El número de slots libres nunca prueba que el servidor esté sano. Los incidentes correlacionados requieren evidencia Apache/MRTG; los totales históricos GoAccess no sustituyen esa evidencia ni prueban causalidad.

## Correo de la cuenta

Desde Inicio o el menú lateral abre **Correo de la cuenta**. Introduce servidor SMTP, seguridad (TLS directo, normalmente 465, o STARTTLS obligatorio, normalmente 587), usuario/contraseña si corresponden, **email de sistema (remitente)** autorizado por tu proveedor y **destinatario**. Se propone el email de acceso como destinatario; puedes cambiarlo sin cambiar el login. Guarda y activa los avisos cuando hayas calibrado los incidentes.

Ambos modos verifican el certificado. STARTTLS debe completarse antes de enviar credenciales o mensajes; no hay alternativa automática sin cifrar. La contraseña se guarda cifrada y no vuelve al navegador. No se envía ningún mensaje al guardar: los próximos incidentes elegibles usarán el canal activado. Revisa **Últimas entregas**; configurar SMTP no garantiza la recepción hasta validar el proveedor real.
