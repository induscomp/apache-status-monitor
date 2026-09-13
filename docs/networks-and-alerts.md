# Entender los avisos, proveedores y memoria

## Qué significa un aviso

Un aviso señala un cambio frente al histórico, no un ataque confirmado. En dominios se comparan conexiones activas o apariciones en la tabla Apache. La pantalla indica observado, habitual y, cuando la referencia es mayor que cero, el multiplicador. Si el valor habitual es cero, no se inventa un porcentaje ni un multiplicador infinito.

La prioridad expresa qué conviene revisar primero. «Resuelto» significa que tres muestras válidas volvieron a la referencia; no confirma que se haya detenido un ataque. La fecha de recuperación pertenece al incidente cerrado, no a evaluaciones posteriores del dominio. El servidor puede seguir mostrando un aviso de RAM aunque otro de dominio ya esté resuelto.

Cada tramo de la franja temporal muestra los avisos que seguían abiertos durante esos treinta minutos. Un único aviso persistente puede colorear toda la franja. No representa ataques nuevos en cada tramo.

## IPs y proveedores

En un aviso de dominio se reconstruyen las IPs desde su propia muestra Apache y se filtran por ese dominio. No se atribuyen a ese dominio las IPs de otros sitios del servidor. Si la muestra ha vencido o no está disponible, se indica que no se pueden atribuir las IPs. Los avisos de recursos muestran coincidencias del conjunto del servidor.

Las IPs activas se enriquecen localmente con país, ASN, organización y rango CIDR de la base. La tabla de proveedores resume las conexiones de las IPs mostradas (máximo treinta), no todas las visitas ni todas las conexiones durante el incidente. Un ASN puede corresponder a un operador, cloud o empresa; no identifica a la persona responsable ni demuestra que sea un bot legítimo o un atacante. El rango es el segmento de la base MMDB, no una comprobación de anuncio BGP o un consejo de bloqueo.

La clasificación usa la base instalada actualmente, cuya fecha se muestra. No demuestra quién operaba la dirección cuando ocurrió un incidente antiguo. No se hacen peticiones externas con IPs de visitantes. Los POST a rutas sensibles incluyen últimas peticiones de workers idle y se distinguen de conexiones actualmente activas.

## Instalar las bases locales

Se admiten GeoLite2 Country/ASN y, como alternativa sin token de API, DB-IP Lite Country/ASN. Con el entorno de desarrollo Python preparado:

```bash
cd backend
.venv/bin/python -m app.geo_install --directory ../geoip
```

El comando descarga por HTTPS la edición mensual de DB-IP, limita tamaño comprimido/descomprimido, valida el formato y sustituye cada archivo de forma atómica. Los contenedores ya montan `geoip` en modo lectura. Las búsquedas tienen caché local invalidada al cambiar los archivos. Repite mensualmente para actualizar; si la edición aún no existe, se conservan los archivos anteriores a cada descarga fallida. No se descarga automáticamente una base en cada arranque.

DB-IP Lite se distribuye con [CC BY 4.0 y atribución a DB-IP](https://db-ip.com/db/lite.php), incluida en las vistas que usan los datos. No tiene cobertura completa ni precisión garantizada. Las bases descargadas no forman parte del repositorio. IPinfo es otra posibilidad, pero su API requiere un token y compartir con el proveedor las IPs consultadas; esta entrega utiliza bases locales.

## RAM y swap en unidades legibles

Las tarjetas y gráficos muestran B, kB, MB o GB decimales cuando existe una unidad configurada o una escala coherente entre el comentario numérico y la tabla visible de la misma métrica MRTG. Las unidades binarias configuradas (KiB, MiB, GiB) se convierten primero a bytes. La fuente y el criterio se muestran en «Fuente y fecha».

MRTG puede mostrar `2,22 G` mientras su comentario contiene `2.220.000`: presentar el comentario como `2,22 M` confundía escala interna con unidad física. Ahora se conserva el valor original para el detector y se aplica la escala de visualización por separado. No se recalibran históricos ni se generan incidentes por este cambio de formato.

Las etiquetas heredadas pueden ser incorrectas. Un `B/s` no se transforma en capacidad de memoria. Si no se puede determinar una escala coherente, se indica «Unidad pendiente de confirmar» y el gráfico de memoria deja un hueco; no se adivinan GB. Lo mostrado es memoria libre según MRTG: no permite deducir RAM total, porcentaje usado ni consumo por dominio. Si el servidor publica mal la unidad de swap, debe corregirse o configurarse explícitamente esa métrica.
