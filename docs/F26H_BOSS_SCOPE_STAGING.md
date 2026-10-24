# F26-H — Frontera de identidad Boss → Secrets (preparación)

Este incremento NO ofrece endpoints de bóveda. La lista declarativa `contracts/commands.json` continúa anunciando solo `secrets.health.v1`.

Boss 2.0.8 establece los atributos de origen `context.neebles_authenticated_module` y `context.neebles_authenticated_session` después de verificar la sesión IPC del consumidor. El proveedor Secrets acepta esos campos únicamente sobre su socket autenticado a Boss, y exige que el destino solicitado coincida con la identidad del consumidor; nunca concede permisos por `payload.module_id`, `context.caller` o parámetros de UI. La validación se mantiene separada de los permisos `ipc_invoke_allow`, que Boss debe resolver ANTES del despacho.

Las rutas futuras `secrets.vault.exists.v1` y `secrets.vault.request.v1` permanecen sin declarar y sin anunciar. Si una llega accidentalmente al proveedor, responde `403` (scope no validado) o `503` (todavía inactiva). Ninguna rama invoca `VaultController`, el broker privado ni KeePassXC.

Siguiente etapa: diseñar la delegación autenticada del consumidor desde el proceso exterior Secrets hacia el worker vía el canal `SCM_RIGHTS` ya existente; después abrir endpoints y grants conjuntamente. Probar negativas cross-vault, instancia de módulo ausente y retención de respuesta antes de habilitar cualquier escritura.

Base exacta: F26-G.1 sobre F22 + F23 + F24 + F26-A...F26-F. Solo fuentes; sin commit, instalación, Boss, Connect, CUSTOM ni KDBX.
