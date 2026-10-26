# Secrets 1.0.5 — Motor universal, núcleo funcional previo al release

**Estado:** fuentes candidatas sin publicación; no constituye aceptación QA-07/08.

## Contrato interno, módulo propietario

La operación llega por el broker autenticado actual. La identidad se valida contra el peer real; `module` en JSON solo selecciona el propio namespace. Las operaciones `structure.*` NO se anuncian aún en `contracts/commands.json` ni se conceden grants. No se usa `vault-general` por consumidores. El almacenamiento es `vault-<module-id>.kdbx` exclusivamente, cifrado mediante las funciones existentes de KeePassXC.

Operaciones y argumentos:

- `structure.schema_define`: `{op,module,schema}`. `schema={id,version,require_replica,fields,unique?}`. Repetición idéntica sin cambio; definición diferente requiere migración explícita.
- `structure.schema_get`: `{op,module,schema_id}`.
- `structure.put`: `{op,module,schema_id,id,value,expected_revision?}`. `expected_revision` ausente significa creación exclusiva; valor entero esperado significa sustitución optimista. No hay patch parcial implícito.
- `structure.get`: `{op,module,schema_id,id}`.
- `structure.list`: `{op,module,schema_id,cursor?,limit?}`. Solo retorna IDs y cursor, sin secretos.
- `structure.delete`: `{op,module,schema_id,id,expected_revision}`. Deniega borrado con referencias entrantes.

Tipos admitidos: `string`, `secret`, `integer`, `number`, `boolean`, `reference` con `target_schema`. `required`, `max_length` y `default` tipado. Los defaults nunca pueden ser secretos ni referencias. `unique` es una matriz de claves compuestas, por ejemplo `[["node","port"]]` para puertos VS Code únicos por nodo.

`require_replica=false`: ID único `primary`; `true`: 0..N registros con IDs estables y revisiones incrementales. Cada operación comprueba definición y valores. Las operaciones se serializan en el worker existente.

La implementación usa entradas `s-schema-<id>` y `s-LL-<schema>-<record>` para evitar colisiones entre pares de nombres que contienen guiones; son *entradas KDBX*, nunca ficheros JSON externos. Las entradas `record-*` de la API anterior permanecen intactas. No se migra ni elimina nada durante este sprint.

## Límites y bloqueos a resolver ANTES de publicar

1. La capa física `vault_records` todavía limita el índice completo a 256 entradas y cada valor a 8192 bytes. La prueba de 1024 registros de esta fase valida el modelo en memoria, **no** autoriza declarar 1000 KDBX físicos. Siguiente paso obligatorio: índices fragmentados protegidos, páginas KDBX atómicas y benchmarks 10/100/1000+.
2. Migraciones de esquema/versiones y de datos legados se rechazan con `schema_migration_required` hasta implementar su transición reversiblemente y probarla contra KDBX descartables. No se borran registros antiguos.
3. El control de unicidad y referencias presupone el único worker serializado. Añadir test de competencia real, límites de memoria y recuperación inducida con KDBX antes de activar escrituras vía Boss.
4. Deben cerrarse nuevos endpoints Boss y `ipc_invoke_allow`, evitar secretos en trabajos retenidos por Boss y certificar ejecución de IPC real antes de anunciar esta API.
5. La UI, Crypto Lab, Batch, exportaciones, Backup/Restore y QA-09..11 siguen pendientes de aceptación integral.

**Regla de release:** nunca publicar los commits, ejecutar pipeline de release, cambiar CUSTOM/Registry ni instalar 1.0.5 por aprobar este paso. Mantener QA-01=PASS; QA-02..18=pendientes, incluidos QA-07/08 hasta finalización real.
