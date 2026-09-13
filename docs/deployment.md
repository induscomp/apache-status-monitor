# Instalación y operación de SMON-001

## Local

```bash
cp .env.example .env  # solo si no existe
python3 scripts/init-secrets.py
docker compose -f compose.yaml -f compose.local.yaml up --build -d --wait
```

Secretos creados una vez, sin sobrescribir, modo 0600 y carpeta 0700. Ajusta SMON_UID/SMON_GID para que backend/worker puedan leerlos. Nunca pongas secretos en chat, argumentos del shell, Git o issues.

### Asistente web de primera instalación

Abre **http://localhost:8187**. Este perfil solo publica en loopback y omite Access; **no lo expongas mediante un túnel**.

1. Si no existe un administrador, verás **Configura tu panel**. Abre `secrets/setup_token` en tu editor y copia su contenido en **Clave de instalación**. Este archivo privado se crea con `init-secrets.py`; acredita que eres el propietario de la instalación. No se envía por URL ni aparece en logs.
2. Elige email y contraseña (mínimo 14 caracteres) y repite la contraseña. En producción, el email debe coincidir con Cloudflare Access.
3. En tu aplicación autenticadora, selecciona **añadir cuenta → escanear QR** y escanea el QR de la web. Introduce los seis dígitos que genera para confirmar. El QR se genera localmente con [Segno](https://segno.readthedocs.io/en/latest/), sin servicios externos. La clave manual está disponible como alternativa.
4. Guarda los ocho **códigos de recuperación** en tu gestor de contraseñas. Se muestran una vez y cada uno permite un acceso. Marca que los has guardado y continúa al login.
5. Entra con email, contraseña y el código actual del autenticador, que cambia cada 30 segundos.

La configuración del QR caduca a los diez minutos. Antes de confirmar el código no se crea ninguna cuenta; puedes volver a empezar si caduca o recargas. Después de confirmar, el asistente queda cerrado aunque la clave de instalación siga montada. Si se interrumpe la conexión justo al confirmar, recarga: si aparece el login, el alta se completó y puedes entrar con tu autenticador. Si no recibiste los códigos de recuperación, usa `reset-mfa` desde la terminal local para generar un nuevo juego.

La contraseña y los datos del asistente se mantienen solo durante el flujo, sin almacenamiento local del navegador. Los endpoints exigen la clave de instalación, comprobación de origen y límites de intentos; en producción también exigen un JWT válido de Access. La clave de instalación no permite recuperar ni sustituir una cuenta existente.

### Instalaciones existentes y alternativa por terminal

Antes de actualizar una instalación anterior al asistente, ejecuta `python3 scripts/init-secrets.py`: añade `secrets/setup_token` sin sobrescribir los secretos existentes. Después ejecuta Compose `up --build -d --wait` con tus archivos habituales. Tu administrador y sus datos se conservan, y seguirá apareciendo el login.

El alta por terminal sigue disponible como alternativa:

```bash
docker compose -f compose.yaml -f compose.local.yaml exec backend python -m app.cli create-admin
```

Solicita email y contraseña, muestra un QR en la terminal y exige un código válido antes de guardar. Amplía la terminal si se cortan las filas del QR. Después guarda los ocho códigos de recuperación. Ambos métodos crean el mismo administrador único.

### Ya creé el usuario, pero no tengo el autenticador

Desde la carpeta del proyecto en Kakarot, ejecuta:

```bash
docker compose -f compose.yaml -f compose.local.yaml exec backend python -m app.cli reset-mfa
```

Introduce tu contraseña actual y escanea el nuevo QR siguiendo los pasos anteriores. **No necesitas iniciar sesión en la web ni disponer del código TOTP anterior**: este comando exige acceso a la terminal local y tu contraseña. Al confirmar el nuevo código, reemplaza el autenticador y los códigos de recuperación anteriores y revoca las sesiones abiertas. Guarda los nuevos códigos de recuperación y vuelve a la web con un código actual del nuevo autenticador.

## Configuración de servicios

Ejemplo ficticio en `.env`:

```dotenv
SMON_ALLOWED_MONITOR_ORIGINS=["https://web.example.com","http://metrics.example.com"]
SMON_ALLOWED_HTTP_ORIGINS=["http://metrics.example.com"]
```

Son orígenes exactos sin rutas. Ejecuta Compose `up -d` con los mismos archivos tras cambiarlos. Crea el servidor y servicios en la web con URL completas. MRTG recibe el índice; el conector sigue los enlaces de las imágenes a páginas HTML del mismo origen y directorio.

URL sin credenciales/query/fragmento. Apache `?auto` se configura aparte. Credenciales opcionales cifradas y solo con HTTPS; campos vacíos al editar conservan las anteriores, y la casilla de borrado las elimina.

## Producción con túnel dedicado

1. Crea una aplicación Access para un hostname dedicado, autoriza únicamente tu identidad y no añadas reglas bypass. Habilita HTTPS/HSTS para ese hostname.
2. Crea un túnel dedicado con destino `http://nginx:8080` dentro de Compose. No reutilices túneles de otros proyectos.
3. Guarda su token en `secrets/cloudflare_token`, modo 0600 y propietario SMON_UID. No uses `.env` o argumentos para el token.
4. Completa `.env`: `SMON_ENVIRONMENT=production`, `SMON_PUBLIC_ORIGIN=https://tu-hostname`, `SMON_CF_TEAM_DOMAIN=https://tu-equipo.cloudflareaccess.com`, `SMON_CF_AUDIENCE` con el AUD. Origen sin `/` final.
5. Detén el perfil local sin borrar datos: `docker compose -f compose.yaml -f compose.local.yaml down`.
6. Arranca sin el archivo local: `docker compose --profile tunnel up --build -d --wait`.
7. Abre el hostname autorizado por Access y completa el asistente web si aún no existe administrador, usando la clave de `secrets/setup_token`.

Producción no publica puertos. Sin configuración Access válida no arranca el backend; sin JWT válido se deniega la API. Access no sustituye contraseña/TOTP local. El túnel no se activa durante el desarrollo.

Verifica desde fuera: identidad no autorizada rechazada por Access, identidad permitida llega al login, contraseña/TOTP incorrectos rechazados y logout revoca acceso. Las pruebas de JWT no sustituyen validar la política real de Cloudflare.

## Recuperar una contraseña olvidada desde la web

En el login del dominio protegido, pulsa **He olvidado mi contraseña**. La recuperación exige la identidad firmada de Cloudflare Access con el mismo email del administrador y un código vigente del autenticador del monitor, o uno de sus códigos de recuperación de un solo uso. El código por email de Cloudflare pertenece a la primera capa y no sustituye el segundo factor del monitor.

Introduce una contraseña nueva de al menos 14 caracteres y confírmala. Al guardar se cierra toda sesión local anterior, se registra auditoría y se conserva el autenticador, los servicios y el histórico. No se inicia sesión automáticamente: vuelve al login y, si usaste TOTP, espera al siguiente código. La misma muestra TOTP o código de recuperación no se puede reutilizar, incluso en solicitudes concurrentes.

La API de recuperación comprueba el JWT y su audiencia/identidad, exige origen exacto en las mutaciones y limita los intentos por identidad y globalmente. No requiere SMTP ni usa enlaces de recuperación por email. En desarrollo local no está disponible, porque allí no hay una identidad independiente verificada por Access. Si se han perdido también el autenticador y todos los códigos, este flujo no permite recuperar la cuenta: se necesita un procedimiento del propietario de la instalación.

## Estado, contraseña y MFA

```bash
docker compose -f compose.yaml -f compose.local.yaml ps
docker compose -f compose.yaml -f compose.local.yaml logs --tail=100 backend worker migrate
docker compose -f compose.yaml -f compose.local.yaml exec backend python -m app.cli change-password
docker compose -f compose.yaml -f compose.local.yaml exec backend python -m app.cli reset-mfa
```

En producción omite el archivo local. Migración debe finalizar con código 0; el worker publica heartbeat. Apache recoge según el intervalo configurado; MRTG descubre y recoge las páginas numéricas del índice. Consulta [diagnóstico Apache](apache.md).

Cambiar contraseña/MFA exige contraseña actual y revoca sesiones. Un código de recuperación permite login una vez; no restablece automáticamente el autenticador. No hay recuperación pública ni usuario oculto.

Conserva una copia externa segura de la clave de cifrado: perderla impide descifrar TOTP y credenciales. Regenerar archivos no rota contraseñas PostgreSQL de un volumen existente; deben sincronizarse con sus roles.

## Actualizaciones y datos

Haz copia manual antes de cambiar esquema. Actualiza mediante PR y ejecuta `up --build -d --wait`; la tarea migrate aplica cambios antes de arrancar backend/worker. **No uses `down --volumes` para actualizar: elimina datos.**

El worker realiza backups diarios cifrados con clave separada y conserva siete diarios y cuatro semanales. La home muestra la última copia disponible. Para actualizar una instalación anterior, ejecuta primero `python3 scripts/init-secrets.py`: añade la clave de backup sin cambiar las existentes. Consulta [backup y restauración aislada](backups.md), conserva ambas claves fuera del equipo y verifica una copia compatible antes de cambiar el esquema.

Esta entrega no es una versión auditada para producción. Las pruebas cubren controles implementados, no recolectores futuros ni tu configuración externa de Access.

## Fuentes y correo tras el alta

La home muestra **Mis servidores**. Añade un servidor y configura desde su pantalla las fuentes que publique: Apache Status, MRTG o GoAccess. Cada origen público se autoriza al guardar; HTTP necesita una excepción explícita. Abre **Correo de la cuenta** para definir remitente, destinatario y SMTP. Consulta las [instrucciones completas](goaccess.md).
