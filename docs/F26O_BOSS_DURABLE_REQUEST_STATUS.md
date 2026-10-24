# NEEBLES Secrets 1.0.5 — F26-O (read-only reconciliation via Boss 2.0.8)

## Alcance

- Declara y anuncia `secrets.vault.request_status.v1` como endpoint de solo lectura.
- Conecta Boss `execute` -> proveedor persistente -> `SCM_RIGHTS` -> worker aislado -> journal `vault.request_status`.
- `payload` EXCLUSIVAMENTE `{ "request_id": "..." }`, `args: []`, contrato `commands`.
- El nombre de módulo NO puede venir del payload; se deriva de `context.neebles_authenticated_module` inyectado por Boss.
- El `request_id` usa la MISMA validación del journal: 16–72 ASCII minúsculas/dígitos/guiones, primer carácter alfanumérico, último no guion.
- Respuesta limitada a `{ "state": "pending|succeeded|not_found" }`; no se transmiten rutas, contraseñas, keys ni errores internos.
- Se valida que `module` y `request_id` de la respuesta coincidan con la solicitud y el estado pertenezca al conjunto permitido.
- Si el worker está caído, el proveedor responde `503` sanitizado; jamás reenvía automáticamente `vault.request_id`.

## Límites expresos

- `secrets.vault.request.v1` NO queda declarado, anunciado, invocable ni concedido.
- NO se actualiza Boss Registry ni `ipc_invoke_allow`, ni la instalación 1.0.4.
- No se escriben ni leen KDBX reales: pruebas con socket Unix simulado y worker ficticio.
- Para uso real deben existir permisos individuales otorgados por Boss, release/publicación y certificación en equipos instalados.

## Tests del incremento

- Rechazo de payload manipulado y falta de contexto autenticado ANTES de enviar FD.
- Sanitarización de datos del worker y de estados no reconocidos.
- Roundtrip Boss/worker simulado por socket Unix.
- Regresión de F26-L/M/N, salud y aislamiento.
