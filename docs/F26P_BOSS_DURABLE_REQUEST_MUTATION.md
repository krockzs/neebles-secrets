# NEEBLES Secrets 1.0.5 — F26-P / solicitud duradera de bóveda por Boss

## Alcance de fuente

- `secrets.vault.request.v1` se declara y anuncia como operación **mutante e idempotente**.
- Entrada obligatoria: `contract=commands`, `args=[]`, `payload={"request_id":"..."}` con gramática del journal; el consumidor no puede enviar nombre de módulo ni contraseña.
- Boss 2.0.8 suministra `context.neebles_authenticated_module` y sesión autenticada; Secrets revalida el contexto y el worker autentica por FD `SCM_RIGHTS` privado.
- La operación interna `vault.request_id` persiste el ID **antes** de intentar crear la bóveda, devuelve `pending` o `succeeded`.
- El resultado remoto solo tiene `state` y `replayed`. No expone `exists`, rutas, contraseñas o información interna del worker.
- `secrets.vault.request_status.v1` es el camino de consulta tras un timeout o respuesta ambigua. `not_found` es un estado de consulta, no una orden de reenvío.
- Nunca reintentar una operación mutante automáticamente después de transferir el FD. Una respuesta `503` NO prueba que no hubo creación.

## Seguridad y estado

- El contrato aún **no está instalado**. No hay grants en `ipc_invoke_allow`; Boss Registry, Boss ejecutándose, Connect, servicios y KDBX reales quedan intactos.
- Boss puede rechazar por políticas/grants aunque el proveedor anuncie su endpoint en esta fuente candidata.
- Durante las pruebas se utilizan workers falsos y sockets Unix aislados. No implica certificación de flujo real instalado.
- Todo worker de prueba recibe como máximo una invocación por entrega; se prueba además que una desconexión después del despacho se devuelve `503` sin redespacho.
- El siguiente trabajo deberá verificar concurrencia, recuperación de caída entre archivo KDBX y actualización del journal, publicación coordinada y grants específicos, **antes de depender del endpoint en producción**.

## Compatibilidad

- Respeta Rust 1.98.1, Boss 2.0.8, CUSTOM V2 y el entrypoint del daemon 1.0.5.
- No introduce ninguna conexión nueva hacia `secrets.sock` del escritorio, ni modifica la UI.
