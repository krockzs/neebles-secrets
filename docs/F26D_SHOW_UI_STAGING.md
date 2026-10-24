# F26-D — Surface show-ui / Lifecycle independiente de Open

Estado: **fuentes preparadas, NO instaladas ni publicadas**.

## Datos cotejados contra Boss 2.0.8

- `modules.rs::execute_surface_action` resuelve el action y transition instalados.
- `execute_governor_target_with_observer` solo llama `begin_opening` cuando `action == "open"`.
- El botón administrativo `Open` sigue siendo canónico, y no debe emplearse para una UI si el daemon ocupa el runtime.
- `surfaces.json` mantiene IDs `open.launcher` y `open.tray` para preservar la identidad de los controles, pero declara acción y transición `show-ui` (no canónica).
- `lifecycle.json` declara `show-ui` con `boss.workspace_execution`, step `open-ui`, independiente del `open` legado.
- `runtime/neebles-secrets-ui --intent show-ui` solo es válido cuando el manifest instalado declara daemon como entrypoint; con entrypoint legado solo permite `--intent open`.

## Faltantes antes de activar

1. Construction en CUSTOM V2: actualizar **el mismo step** `open-ui` para pasar `--intent show-ui`, con certificado RootFS y MaterialBinding. Este cambio en CUSTOM se hace en una fase coordinada, NO en F26-D.
2. Versiones Rust, manifest, Registry y grants alineados en 1.0.5. Actualmente permanecen 1.0.4.
3. Proveedor del daemon debe estar registrado en `modules.sock` y validado con Boss real.
4. Una única ventana Qt por usuario y reactivación/foco en apertura repetida. Sin esto, el usuario podría generar dos ventanas.
5. Verificar que `workspace_execution` en mundo `modules.rust-qt` dispone de sesión gráfica y ejecuta la transición con runtime daemon en Open.
6. Validar ausencia de efecto en disable/uninstall, ventanas abiertas, reinicio y fallos de Boss.

No publicar ni invocar `show-ui` con manifest 1.0.4 instalado. El patch NO instala, cambia el daemon, el Registry, Boss ni KDBX.
