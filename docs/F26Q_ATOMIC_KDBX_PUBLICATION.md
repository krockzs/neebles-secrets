# F26-Q — Confirmación durable de publicación KDBX (fuentes)

**Alcance:** refuerzo de `create_once()` antes de que `Journal::complete_module()` marque solicitudes como `succeeded`. No habilita instalaciones, grants ni servicios de Boss. No modifica bóvedas reales.

## Secuencia de confirmación

1. El worker comprueba la identidad autenticada y persiste `Pending` con `request_id` (F26-L a F26-P).
2. KeePassXC crea el ciphertext temporal, con permisos `0600`, y lo verifica usando la Master Key ya desbloqueada.
3. `publish_prepared_vault()` abre el temporal con `O_NOFOLLOW`, verifica tipo, dueño, enlace único y permisos; ejecuta `sync_all()` sobre el archivo antes de publicar.
4. Publica con `hard_link()` (crear solo si no existe) y confirma la identidad del inode de destino. **Nunca** reemplaza una KDBX existente.
5. Confirma con `sync_all()` el directorio que contiene la KDBX; luego elimina el nombre temporal y vuelve a sincronizar el directorio. Solo entonces `create_once()` puede informar éxito.
6. `ensure()` comprueba criptográficamente una KDBX preexistente con la Master Key antes de permitir que el journal pase a `Succeeded`.
7. Ante error o pérdida de energía tras la publicación y antes de la confirmación del journal: la solicitud queda `Pending`. Tras un nuevo desbloqueo, Secrets verifica la KDBX existente y completa el journal. **No hay reenvío automático por timeout del proveedor.**

Si un `sync_all()` falla después de crear el enlace, la operación devuelve error sin anunciar `Succeeded`; la conciliación posterior decidirá el estado mediante `request_status`. La publicación de dos temporales concurrentes se resuelve con un único ganador debido a la semántica de `hard_link()` sin sustitución.

## QA

Tres tests `vault::tests::f26q_`: publicación única, productores concurrentes y rechazo de fuentes inseguras o simbólicas. Esos tests utilizan bytes ficticios, no KeePassXC/KDBX reales; **no certifican persistencia tras un corte de energía real** ni sustituyen las pruebas E2E pendientes con Boss instalado.

## Seguridad / límites

- No manipular manualmente `/opt`, daemon, systemd, Registry, grants ni KDBX.
- No hacer rollback de F23-F26-P ni reemplazar archivos acumulados.
- Permanecen por validar recuperación de temporales KDBX huérfanos, fallo de fsync simulado e integración real del servicio.
