# F26-F — Secrets 1.0.5: entrypoint del daemon + Construction de interfaz

Estado: **preparado en fuentes; no publicado ni instalado**.

## Objetivo

La arquitectura Boss 2.0.8 dispone de una única sesión invocable por módulo. La sesión la ocupa el daemon `runtime/neebles-secrets`, registrado mediante `modules.sock`. La UI Qt no registra una segunda sesión cuando el manifiesto instalado declara al daemon como entrypoint.

Se coordinan estos cambios de fuente:
- `manifest.json`: versión `1.0.5` y entrypoint `runtime/neebles-secrets`.
- `runtime/Cargo.toml` y `Cargo.lock`: versión 1.0.5 consistente.
- `contracts/commands.json`: health se describe como candidato de daemon persistente (sin credenciales).
- `neebles-custom/runtime/construction/neebles-secrets.json`: `open-ui` ejecuta `neebles-secrets-ui --intent show-ui`.

La declaración Construction conserva `runtime_authority=modules.runtime`, `execution=persistent` y **`session=true`**. Es crucial: `session=true` aporta la autoridad de sesión gráfica, DISPLAY y XAUTHORITY; **no significa registrar otra sesión de módulo en `modules.sock`**. La propia implementación Rust `ui_open.rs` evita el segundo registro en modo `show-ui`.

Launcher/Tray usan la transición `show-ui` desde F26-D. F26-E protege la instancia única de la ventana.

## Restricciones para la publicación final

**No publicar con este parche por sí solo.** Todavía faltan los endpoints reales de Secrets, permisos `ipc_invoke_allow`, el motor universal de estructuras, QA y certificación integral. Este parche no hace commit/push.

Construction conserva `fetch` y `checkout` fijados al commit F22 de Secrets 1.0.4. **No cambiar ese commit a una conjetura**: se actualizará únicamente cuando exista un commit real definitivo, con `Construction`, Registry, MaterialBinding y release certificados conjuntamente.

`lifecycle.open` (administrativo legado) permanece declarado pero no debe utilizarse para abrir Qt con un daemon activo. Las superficies Launcher y Tray declaran `show-ui`; antes de publicar deben realizarse pruebas reales de acceso gráfico desde el runtime controlado y de reinicio de servicio.

Bóvedas y Master Key no se abren, migran ni recrean por F26-F.
