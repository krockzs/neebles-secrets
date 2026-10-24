# F26-L — Durabilidad de solicitudes KDBX e idempotencia (preactivación)

## Implementado

- `VaultController` recupera solicitudes identificadas tras reiniciar, desde `.request-journal` (directorio 0700 dentro del directorio KDBX). El archivo por solicitud tiene permiso 0600 y contiene solamente `{schema,module,request_id,state}`.
- `request_with_id(module, request_id)` registra la intención en disco **antes** de llamar al constructor existente; un `request_id` repetido del mismo módulo no solicita crear una bóveda nueva si la operación ya finalizó.
- Una operación pendiente conserva el estado hasta que la Master Key permite verificar o crear la KDBX. `fulfill_pending` completa el journal después de `ensure`.
- Después de un fallo entre publicar el KDBX y registrar éxito, la recuperación vuelve a verificar su existencia/clave con el mismo flujo `create_once`; el KDBX nunca se sobrescribe.
- Registro corrupto, permisos inseguros, symlinks o nombres desconocidos causan rechazo. La sincronización de archivo y directorio reduce pérdida ante cortes.
- Pruebas negativas usan directorios descartables, sin KDBX ni Master Key real.

## Pendientes antes de anunciar `vault.request`

1. El método `request_with_id` es interno del worker, **NO** está conectado aún a un endpoint de Boss. Esto evita activar escrituras sin autorización e idempotencia certificadas.
2. Definir el contrato de `request_id` en el consumidor, y la política de conciliación/consulta; registrar errores parciales de `setup/unlock` sin confundir `unlock` con `fulfill_pending`.
3. Validar la propiedad de durabilidad con reinicio real del daemon y KDBX de prueba, y simular corte antes/después de cada sync. La recuperación de archivos temporales huérfanos actualmente **falla de forma cerrada**, requiere reparación explícita y segura antes de producción.
4. Este journal tiene límite de 4096 registros y 32 módulos pendientes; hace falta política documentada de compactación/retención de solicitudes ya finalizadas, o paginación para operación prolongada.
5. La operación legacy `request(module)` sigue disponible, con comportamiento anterior para los consumidores antiguos. Solo la ruta autenticada nueva usa ID estable.
6. El modelo general `require_replica` sigue pendiente, así como grants, pruebas contra Boss instalado y publicación.

El ZIP solo modifica las fuentes `neebles-secrets`, no toca ninguna bóveda existente ni instala servicios.
