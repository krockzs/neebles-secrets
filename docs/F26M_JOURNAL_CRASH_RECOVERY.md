# F26-M — Recuperación ante interrupción del journal de solicitudes

**Estado:** candidato exclusivamente en fuentes. No publica `vault.request`, no ejecuta KDBX ni configura permisos de consumidores.

## Problema observado en F26-L

`persist()` crea un temporal privado `.tmp-<UUIDv4>`, sincroniza los bytes y publica mediante `rename`. Si el proceso cae antes del `rename`, el temporal remanente provocaba `request_journal_incomplete_transaction` y podía impedir que Secrets iniciara. El registro anterior sigue siendo la autoridad; el temporal no es un commit.

## Corrección

`Journal::open()` reconcilia **solo** temporales con nombre UUIDv4 exacto, fichero regular, propiedad del UID actual, un único hardlink, permisos 0600 y tamaño <=1024 bytes. Comprueba `O_NOFOLLOW` e identidad de inode antes de eliminar, y sincroniza el directorio después. No borra archivos `request-*.json`, no inspecciona KDBX y no acepta nombres inesperados, symlinks, tamaños desmesurados o permisos inseguros.

**Límite de amenaza:** la carpeta es privada del mismo UID; esta validación evita errores accidentales y entradas inseguras, no pretende defenderse de procesos arbitrarios maliciosos del mismo usuario. El worker actual serializa el controlador de bóvedas.

## Semántica de reintentos

- Caída antes de confirmar el rename: solo existe el temporal descartable; la solicitud aún no está confirmada.
- Caída tras confirmar `pending`: la intención se recupera de `request-*.json`, sin ejecutar la operación al inicio.
- Caída después de crear la bóveda y antes de marcar `succeeded`: al desbloquear, `ensure` debe verificar la bóveda existente y marcar éxito sin crear otra.
- Caída después de marcar `succeeded`: la misma `request_id` conserva el resultado. Si falta el KDBX, se devuelve error y nunca se recrea silenciosamente.
- Cualquier timeout de Boss no autoriza un retry indiscriminado tras despacho: se utiliza estado/identidad de solicitud.

## QA

Pruebas añadidas: 4, incluidas temporales vacíos, parciales, symlinks, nombres desconocidos, tamaños excesivos y preservación de registros confirmados. Verificación física con el Ryzen pendiente.
