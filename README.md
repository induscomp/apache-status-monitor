# Apache Status Monitor

Monitor web open source para ayudar a webmasters a interpretar el estado de uno o varios servidores Apache y tomar decisiones basadas en su evolución.

**Estado: preparación del proyecto. Todavía no hay aplicación ejecutable, cron ni versión apta para producción.** Los controles de seguridad de la aplicación descritos aquí son requisitos pendientes de implementación y pruebas.

## Objetivo

- Recoger periódicamente métricas de endpoints autorizados `/server-status?auto` mediante un cron que ejecute un recolector interno.
- Mostrar disponibilidad, workers ocupados y libres, tráfico e histórico por servidor.
- Identificar tendencias y ofrecer observaciones con evidencia, intervalo temporal y límites de interpretación.
- Distinguir fallos de recogida y datos ausentes de valores reales de cero.

El producto monitorizará servidores autorizados por su administrador. Las métricas disponibles dependen de la configuración de Apache; no se asumirá que `mod_status` proporciona toda la información necesaria para diagnosticar un servidor.

## Diseño previsto

Panel autenticado → API → almacenamiento de métricas.

Cron interno → recolector aislado → endpoints Apache autorizados → almacenamiento de métricas.

El panel consultará datos almacenados. El cron no dependerá de una ruta HTTP pública. La elección del stack y sus versiones mantenidas se documentará antes de implementar el MVP.

## Documentación

- [Arquitectura y requisitos de seguridad](docs/architecture.md)
- [Hoja de ruta](docs/roadmap.md)
- [Contribuir](CONTRIBUTING.md)
- [Comunicar vulnerabilidades](SECURITY.md)

## Licencia

[MIT](LICENSE). Proyecto independiente, sin afiliación con Apache Software Foundation.

## Referencias

- [Documentación oficial de mod_status](https://httpd.apache.org/docs/2.4/mod/mod_status.html)
- [Prevención de SSRF de OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
