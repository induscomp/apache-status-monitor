# Conector MRTG: contrato para SMON-004

**Pendiente.** SMON-001 guarda la URL índice y administra el servicio; no recoge métricas ni analiza imágenes.

## Recorrido requerido

1. Leer el índice configurado.
2. Localizar enlaces `a[href]` que contienen `img`.
3. Resolver URL relativas y deduplicar, manteniendo origen/ruta autorizados.
4. Mostrar páginas descubiertas para seleccionar métricas.
5. Consultar cada cinco minutos las páginas seleccionadas y parsear sus estadísticas numéricas.
6. Redescubrir diariamente o mediante solicitud administrativa encolada.

Los PNG sirven para descubrir las páginas: **los datos están en las páginas enlazadas por las imágenes**. No usar OCR ni seguir enlaces externos o eludir 403 de archivos `.log`.

## Parser y pruebas

Preferir comentarios MRTG `cuin`, `cuout`, `avin`, `avout`, `maxin`, `maxout`; tablas visibles como alternativa. Conservar canales y ventanas `d`, `w`, `m`, `y` separadas. Registrar fuente, parser, hora de recogida y fecha de actualización.

Unidades/escalas por métrica, sin asumir que «B/s» de una plantilla sea correcto para CPU/carga. «×100» requiere conversión explícita. Semántica no verificada implica pendiente de interpretación y exclusión de alertas. Una fecha sin zona requiere configurar la zona de la fuente.

Pruebas: enlaces relativos/externos, imágenes decorativas, duplicados, respuestas excesivas, páginas ausentes, comentarios ausentes, tablas alternativas, unidades ambiguas y datos antiguos.
