# F26-C: convivencia del proveedor persistente y ventana Qt

Estado: **STAGED / no publicado / no instalado**.

La versión instalada 1.0.4 mantiene `entrypoint: runtime/neebles-secrets-ui`.
Bajo esa identidad, el CLI de UI conserva el flujo anterior de registro gobernado.

Cuando la release posterior declare de forma ATÓMICA `entrypoint: runtime/neebles-secrets`,
el daemon exterior podrá registrar un runtime invocable y publicar variables por otro socket
`register_service`; el worker KeePassXC permanece aislado. La UI entonces deja de
registrar un segundo runtime y opera como ventana cliente.

## Bloqueos de activación y requisitos finales

1. Migrar junto con la versión de Rust, manifest, lifecycle, surfaces, CUSTOM V2,
   Registry y `ipc_invoke_allow` (no fragmentar la instalación).
2. `open` canónico de Boss está ocupado por el runtime persistente. Launcher/Tray
   necesitarán una transición de superficie declarativa **distinta de `open`**
   (p. ej. `show-ui`) con Construction autorizada y sesión gráfica.
3. Validar efectivamente la acción de superficie ante runtime `Open`; el botón
   administrativo Open de la pestaña Modules no representa apertura de la ventana.
4. Impedir ventanas duplicadas o definir activación/foco de ventana existente.
5. Probar certificado de identidad PID/exe, publisher simultáneo, reinicio de Boss,
   service disable/uninstall, errores de registro, y que Qt abra/cierre sin parar daemon.
6. Pruebas end-to-end de `execute` y `job_query` con grants reales después de publicar.

F26-C únicamente prepara la separación desde Secrets y NO cambia la instalación.
