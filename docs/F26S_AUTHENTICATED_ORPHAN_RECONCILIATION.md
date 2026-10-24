# F26-S — Conciliación autenticada de temporales KDBX

F26-R reconoce archivos `.vault-{module}-{32hex}.pending.kdbx` sin tocarlos. F26-S agrega una conciliación **después del desbloqueo** que exige un journal `pending` para ese mismo módulo y exactamente un archivo candidato. La verificación de la KDBX se realiza con la Master Key vigente mediante el `db_verify()` del worker KeePassXC, antes de publicar o eliminar nombres.

## Procedimiento

1. Inspeccionar y rechazar metadatos anómalos; no confiar en nombres sueltos.
2. Exigir solicitud `pending` persistente y un solo candidato para el módulo.
3. Comprobar encabezado KDBX; verificar descifrado con la Master Key activa.
4. Rechazar archivos reemplazados, destinación no relacionada o nombres múltiples.
5. Si aún no existe destino, publicarlo por hardlink sin sobrescritura y con sincronización de directorio (F26-Q). Si existe el hardlink correcto (caída antes del unlink), conservarlo.
6. Eliminar **solo el nombre temporal idéntico** luego de la publicación validada y sincronizada; el contenido cifrado permanece en el nombre definitivo.
7. Volver a verificar el destino en `ensure()` y recién entonces permitir `complete_module()` en el journal.

No hay reintento de escritura tras timeout ambiguo. Si la contraseña es errónea o los archivos son ambiguos, queda todo intacto; no se inventa un nuevo candidato. `vault-general` sigue excluido de esta ruta, por ser personal y no estar asociado al journal de módulos.

## Alcance de QA

Cinco tests F26-S usan bytes **ficticios**, con verificador privado simulado para ejercitar el orden de filesystem; no simulan ni demuestran que KeePassXC descifra una KDBX real. El código productivo utiliza `db_verify()`, pero sigue sin instalarse. No se accede a KDBX reales ni a Master Keys durante el QA. Compilación a ejecutar en el Ryzen con Rust 1.98.1 y el resto de tests anteriores. No cambia Boss/Registry/CUSTOM/Connect ni services.
