# F26-R — Inventario conservador de temporales KDBX huérfanos

Secrets 1.0.5 / Boss 2.0.8, fase de fuentes.

F26-Q.1 confirmó 53 pruebas Rust. El proceso puede caer luego de `db-create` y antes de publicar la KDBX, dejando `.vault-{module}-{32hex}.pending.kdbx` en el directorio privado. El inventario F26-R comprueba nombre y nonce exactos, propietario, modo `0600`, archivo regular y número de enlaces; si hay dos enlaces, requiere coincidencia de inode con `vault-{module}.kdbx`. Rechaza archivos extraños o manipulados en vez de borrarlos.

**No hay limpieza ni publicación automática.** La fase no dispone de la Master Key en el arranque; promocionar o borrar un temporal cifrado sin validación criptográfica puede perder datos. `VaultController::new` solo inspecciona; `status` expone `vault_recovery_required: boolean`, sin divulgar rutas ni módulos; `create_once` deniega nuevas creaciones del mismo módulo si existe un temporal propio no conciliado. Bóvedas existentes siguen prevaleciendo.

La conciliación criptográfica después de desbloquear, con retención ante ambigüedad y comprobación de journal, corresponde a la siguiente etapa. Las pruebas de F26-R usan bytes ficticios y no abren KeePassXC.

## Limitaciones

- Fuente todavía no instalada; requiere QA Rust 1.98.1 en el Ryzen.
- No se prueba con KDBX reales ni contra Boss instalado.
- Los archivos de prueba no simulan pérdida física de energía.
- No modifica Connect, Boss, grants, Registry, CUSTOM, /opt ni los datos cifrados existentes.
