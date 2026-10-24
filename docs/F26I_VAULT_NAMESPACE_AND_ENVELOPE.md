# F26-I — Reglas de namespace KDBX y validación del sobre IPC (preparación)

Resultado de F26-H confirmado: 17 pruebas específicas Rust PASS, endpoints de bóvedas aún no anunciados.

F26-H comparaba `module_id` contra las reglas léxicas amplias de Boss. Sin embargo, el broker FD (`ipc_bridge.rs`) y `VaultController` usan identificadores de **2 a 64 bytes**, iniciados en letra minúscula, solo `[a-z0-9-]`, sin `--`, sin guion final y distintos de `general`. La autorización previa ahora emplea exactamente la intersección para evitar autorizar algo que el worker denegaría después.

F26-I también rechaza en la etapa de guard sobres IPC con `contract` no esperado, `args` no vacíos, payload de tipos incorrectos o campos desconocidos. Nunca extrae un `module_id` defectuoso y lo sustituye silenciosamente por la identidad propia. Los clientes todavía no pueden utilizar estos endpoints: **continúan sin declararse en `commands.json`, sin anunciarse y sin grants**. Ninguna prueba escribe, desbloquea, abre ni modifica KDBX.

## Criterio de avance

- `cargo check` + 8 pruebas de `boss_scope` + regresiones del proveedor y UI.
- Siguiente trabajo: acordar y probar la **delegación autenticada** entre el daemon exterior y el worker KDBX por `SCM_RIGHTS`, sin permitir que otro proceso con el mismo UID se suplante vía socket privado.
- Mantener prioridad en Secrets 1.0.5: NO hacer update de Boss, no dar acceso a Connect todavía.
