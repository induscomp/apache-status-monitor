# Arquitectura y seguridad desde el diseño

Estado: requisitos para la implementación; no representan controles ya implementados.

## Componentes

1. Panel web accesible y adaptable a móviles, con autenticación obligatoria y permisos por servidor.
2. API que valida entradas, aplica autorización en cada operación y registra cambios administrativos sin secretos.
3. Recolector independiente, ejecutado por cron bajo una identidad con privilegios mínimos. No expondrá un endpoint público para ejecutar tareas.
4. Base de datos con migraciones, consultas parametrizadas, retención definida y copias de seguridad restaurables.

El MVP será autohospedado. Se evitarán servicios y dependencias innecesarios. La elección de tecnologías quedará registrada con alternativas y versiones soportadas.

## Fronteras de confianza

Las URL configuradas, las respuestas de Apache y las contribuciones al repositorio son entradas no confiables. El recolector tendrá acceso de red limitado a los destinos aprobados. Los usuarios del panel no podrán ampliar por sí solos la política de salida del despliegue.

## Requisitos del recolector

- Prevenir SSRF: permitir únicamente esquemas, hosts y puertos aprobados por el operador; rechazar credenciales en URL y esquemas distintos de HTTPS por defecto.
- Validar todas las direcciones IPv4/IPv6 resueltas antes de conectar y conectar a una dirección validada conservando la verificación TLS del hostname, evitando una segunda resolución vulnerable a DNS rebinding.
- Bloquear loopback, link-local, servicios de metadatos y rangos reservados. Los destinos privados requieren una allowlist explícita del operador y segmentación de red. No habilitar acceso indiscriminado a redes internas.
- Desactivar redirecciones y proxies heredados del entorno por defecto. Un proxy futuro deberá preservar las mismas restricciones de destino.
- Verificar certificados y hostname TLS. Admitir una CA privada configurada, sin desactivar la verificación.
- Fijar límites de conexión y duración total, bytes recibidos y descomprimidos, tamaño del parser y concurrencia. Aplicar reintentos limitados con espera creciente.
- Impedir solapamientos por servidor mediante bloqueo con caducidad; guardar muestras de forma idempotente y registrar timestamps UTC.
- Parsear únicamente el formato esperado; no ejecutar comandos construidos desde URL ni interpretar HTML recibido.

## Panel y datos

- Autenticación con una biblioteca mantenida, autorización en servidor, límites de intentos y sesiones revocables.
- Cookies Secure, HttpOnly y SameSite; protección CSRF para operaciones con cookies, escape de salidas y política CSP restrictiva.
- Separar credenciales de configuración pública; cifrar secretos persistidos con una clave externa a la base de datos y permitir su rotación.
- No registrar contraseñas, tokens, cabeceras de autorización ni respuestas completas de estado. Minimizar IP de clientes, rutas y parámetros de peticiones; conservar métricas agregadas.
- Restringir `/server-status` en Apache al recolector mediante controles de red y acceso. Que este repositorio sea público no implica publicar el panel o los endpoints monitorizados.
- No deducir saturación absoluta sin conocer capacidad y configuración del servidor. Las tasas por intervalo usarán diferencias de contadores y detectarán reinicios; los promedios desde el arranque se etiquetarán como tales.

## Desarrollo y despliegue

- Nunca versionar secretos, datos reales de servidores, volcados o claves privadas. `.gitignore` es una protección auxiliar, no un detector de secretos.
- Añadir lockfiles, auditoría de dependencias y pruebas de seguridad al introducir el stack. Fijar acciones de terceros por SHA y dar permisos mínimos a CI.
- Antes de la primera versión ejecutable, probar SSRF (incluido DNS rebinding e IPv6), TLS inválido, timeouts, respuestas malformadas o excesivas, permisos, sesiones y solapamientos del cron.
- Ejecutar servicios sin root, con exposición de red mínima, política de actualizaciones y procedimiento probado de backup y restauración.

## Fuentes

- [Apache mod_status](https://httpd.apache.org/docs/2.4/mod/mod_status.html)
- [OWASP: SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
