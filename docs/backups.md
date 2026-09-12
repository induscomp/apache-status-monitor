# Backup cifrado y recuperación

## Funcionamiento

El worker comprueba cada hora si existe una copia del día UTC. Al arrancar realiza la primera comprobación, por lo que recupera horarios perdidos. Conserva **siete copias diarias y cuatro semanales** (la primera copia válida de cada semana ISO). La home indica la fecha de la última copia: transcurridas 26 horas sin una copia correcta muestra que falta un backup reciente.

Los archivos `backups/backup-daily-AAAA-MM-DD.smon` y `backup-weekly-AAAA-WNN.smon` contienen una exportación lógica consistente de PostgreSQL. Cada registro se cifra y autentica con Fernet, incluyendo identificador del archivo y posición; una cabecera identifica esquema y clave de aplicación, y un cierre autenticado detecta truncamiento. No se generan archivos temporales en claro. La publicación es atómica y se sincronizan los archivos y el directorio al disco. La rotación solo afecta a nombres de copias reconocidos.

Incluye configuración, cuenta administrativa, revisiones, muestras normalizadas, series e incidentes. **Excluye originales de depuración, sesiones, contadores de intentos, latidos y cola de correo.** Aplica la caducidad de muestras/detalles al exportar y de nuevo al restaurar. No sustituye las migraciones: una copia exige una base vacía con el mismo esquema y una versión compatible del proyecto.

`secrets/backup_key` es una clave diferente de `secrets/encryption_key`. Solo el worker recibe la clave de backup y el volumen de copias; el backend web no puede descargar ni restaurar archivos. El comando de inicialización crea la nueva clave sin sobrescribir secretos existentes:

```bash
python3 scripts/init-secrets.py
docker compose -f compose.yaml -f compose.local.yaml up --build -d --wait
```

Guarda **ambas claves fuera de este equipo**, junto con la versión del proyecto y la configuración de despliegue. Sin la clave de backup no se abre el archivo; sin la clave original de aplicación no se recuperan TOTP ni credenciales cifradas. Nunca subas claves, `.env` ni copias a GitHub. Las copias locales no protegen frente a pérdida del disco/equipo; la transferencia a otro destino no está automatizada en esta versión.

## Comprobación manual

Estas operaciones son sobre la aplicación local; no necesitan acceso shell al servidor Apache monitorizado.

```bash
docker compose -f compose.yaml -f compose.local.yaml exec worker python -m app.backup create
docker compose -f compose.yaml -f compose.local.yaml exec worker python -m app.backup verify /data/backups/backup-daily-AAAA-MM-DD.smon
```

`create` es idempotente durante el mismo día. `verify` comprueba integridad, secuencia, cierre, esquema y correspondencia de clave de aplicación, sin modificar PostgreSQL. Una comprobación criptográfica no sustituye un ensayo de restauración.

## Ensayo aislado de restauración

Sustituye el nombre de archivo por una copia existente. Usa un **nombre de proyecto Docker nuevo**, distinto de la instalación activa. Estos comandos crean únicamente PostgreSQL y el proceso de migración/restauración, sin publicar la web ni arrancar los recolectores:

```bash
docker compose -p smon-restore-check -f compose.yaml -f compose.local.yaml up -d --wait postgres
docker compose -p smon-restore-check -f compose.yaml -f compose.local.yaml run --rm migrate
docker compose -p smon-restore-check -f compose.yaml -f compose.local.yaml run --rm --no-deps worker python -m app.backup restore /data/backups/backup-daily-AAAA-MM-DD.smon
```

No reutilices un proyecto existente para este ensayo. Restaurar en una base con cualquier dato de aplicación se rechaza; no hay opción de sobrescritura. Toda la importación se realiza en una transacción, con bloqueo de tablas y validación completa del archivo antes de insertar. Una segunda validación durante la inserción obliga a rollback ante cambios o daños del archivo.

La restauración elimina los datos que hayan vencido desde que se creó la copia, deja las sesiones revocadas, reinicia las confirmaciones consecutivas de anomalías y **desactiva el correo**. No envía avisos históricos. Conserva incidentes y referencias para revisión. Antes de habilitar una instalación recuperada, revisa URLs autorizadas, acceso local/Cloudflare, TOTP, recogidas y configuración de correo. No arranques dos workers contra la instalación recuperada y original para enviar las mismas alertas.

Tras revisar el ensayo, elimina **solo el proyecto de prueba** y su volumen:

```bash
docker compose -p smon-restore-check -f compose.yaml -f compose.local.yaml down --volumes
```

Para recuperación real, prepara una instalación independiente con la versión compatible, las dos claves originales y una base vacía; sigue el mismo proceso antes de habilitar web/worker. No se borra ni reemplaza automáticamente la instalación anterior.

Los nombres de las nuevas copias incluyen los primeros ocho caracteres de la huella de esquema. Una migración puede generar una nueva copia en el mismo día sin sobrescribir la anterior. La rotación reconoce también los nombres antiguos y conserva siete copias diarias y cuatro semanales; en el mismo periodo prioriza la copia más reciente. La restauración exige un esquema compatible, por lo que deben conservarse la revisión de código y las claves correspondientes.
