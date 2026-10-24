# F26-J — Delegación autenticada Boss → Secrets KDBX (solo lectura, preparada)

Estado de entrada: F26-I PASS (20 tests Rust), proveedor aún sin instalar ni grants.

## Frontera implementada

1. Boss autentica el consumidor y fija `neebles_authenticated_module` y `neebles_authenticated_session` en el mensaje invocable.
2. El daemon exterior de Secrets comprueba sesión, sobre, identidad y pertenencia a la bóveda (`boss_scope`).
3. Para **únicamente** `secrets.vault.exists.v1`, el daemon crea un par de sockets **anónimos**. Entrega un descriptor al worker KeePassXC aislado por el canal privado `SCM_RIGHTS` heredado (`ipc_bridge`) con la identidad autenticada, nunca la declarada por el consumidor.
4. El worker exige `peer == module` y ejecuta `vault.exists` de manera no mutante. El daemon retransmite únicamente `exists` y `locked` booleanos; jamás replica arbitrariamente el resultado o los errores del worker.
5. Si algo falla, responde 503 sin datos sensibles. Para identidades o payloads inválidos responde 403 sin transferir ningún FD.

## Protección de alcance

`commands.json` sigue anunciando SOLO `secrets.health.v1`. No existen permisos `ipc_invoke_allow` para bóvedas. La instalación 1.0.4 sigue intacta. Ningún binario se publica ni se ejecuta contra datos reales en este incremento. No se activa `vault.request`, `secret.get/put`, `vault-general`, Master Key ni Backup/Restore. La futura publicación requiere grants, revisión del contrato `commands`, pruebas de límites y jobs, más verificación real de Boss 2.0.8.

## QA

- Prueba de transferencia de descriptor y peer autenticado usando un **worker simulado** sin KDBX.
- Rechazo de solicitudes falsificadas **antes** de transferir descriptor.
- Respuesta de identidad cruzada y error de worker no deben filtrarse.
- `cargo check`, tests de bridge, regressión Boss scope/runtime, `git diff --check`.

No interpretar la prueba de worker simulado como certificación de bóvedas o integración instalada.
