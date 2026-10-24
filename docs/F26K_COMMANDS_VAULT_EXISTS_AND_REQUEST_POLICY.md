# F26-K — Contrato read-only de bóveda + política previa a escrituras

**Base**: F26-J PASS, Secrets candidato 1.0.5, Boss 2.0.8 instalado.

## Entregable en código

- `contracts/commands.json` declara `vault_exists` → `secrets.vault.exists.v1`, `requires_root=false`, `lifecycle=runtime`, `state_mode=preserve`, metadatos `read_only`.
- `boss_runtime.rs` anuncia el endpoint **por su identidad física declarada** y conserva `secrets.health.v1`.
- El handler continúa requiriendo identidad reservada de Boss, sobre tipado estricto y scope propio antes de transferir FD anónimo a KeePassXC.
- El daemon retorna solamente `exists` y `locked`; no revela contraseñas, entradas KDBX ni errores del worker.
- Pruebas simulan registro + invoke + SCM_RIGHTS a worker falso, así como denegación cross-vault antes del handoff.

**IMPORTANTE**: declararlo/anunciarlo no concede permisos. Boss exige además `ipc_invoke_allow` en el snapshot instalado del proveedor. No se agregan grants a Connect ni a otros consumidores todavía. La instalación 1.0.4 sigue inalterada. No se tocan bóvedas ni se publica.

## Contrato de `vault.request` (aprobación técnica pendiente)

No anunciar `secrets.vault.request.v1` antes de tener durabilidad e idempotencia definidas. La operación puede crear KDBX: un timeout del consumidor **no** cancela necesariamente la escritura. Reglas obligatorias:

1. Identidad y bóveda derivadas exclusivamente del contexto autenticado Boss.
2. Asociar cada solicitud a `request_id` único y persistible por identidad, operación y versión de contrato. Nunca reutilizar un ID para payload diferente.
3. Estado transaccional: `pending_locked`, `in_progress`, `succeeded`, `failed_retryable`, `failed_final`; definir terminalidad y consulta.
4. En caso de respuesta ambigua, consultar estado y/o verificar existencia antes de iniciar trabajo nuevo. Jamás repetir creación después de despacho confirmado sin idempotencia.
5. Recuperación después de reinicio, respetando la Master Key vigente, sin almacenar secretos en pending ni journals.
6. `create_once` ya evita reemplazos: integrar esa propiedad con recuperación y journal; analizar errores parciales de `fulfill_pending`.
7. Ensayar simultaneidad, reinicios en cada etapa y fail-closed. Solo entonces declarar/grantear el endpoint de escritura.

Estos puntos son **diseño**, no implementación todavía. Ningún cambio de Boss requerido.

## Criterios de aceptación del incremento

- Código fuente + SHA F26-J conservados; `git diff --check` sin errores.
- `cargo check --locked --offline --bins` y pruebas de Boss scope/runtime/bridge/UI con Rust 1.98.1.
- Prueba cruzada con socket falso: anuncio, petición propia, transferencia de FD, respuesta sanitizada y denegación a bóveda ajena.
- Validar que el contrato no exponga `vault.request`, `secret.put/get`, `Master Key` ni acceso general.

No confundir pruebas con Boss falso con certificación end-to-end de Boss instalado. El RuntimeLease/grants se comprobarán después de publicación coordinada.
