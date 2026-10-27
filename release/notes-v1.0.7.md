# NEEBLES Secrets 1.0.7 — restauración Governor Open

## Corrección puntual

Se recupera el contrato de apertura gráfica que utilizaba Secrets 1.0.4:

- El entrypoint instalado vuelve a `runtime/neebles-secrets-ui`.
- Launcher, Tray y Boss utilizan la acción canónica `open`.
- El lifecycle conserva `governor.open` y elimina la ruta paralela `show-ui`.
- CUSTOM V2 requiere el mismo `--intent open` en el paso `open-ui`.
- El servicio persistente `neebles-neebles-secrets-daemon.service` y el manejo de bóvedas permanecen intactos.

## Cambio de titularidad IPC

Boss permite un runtime registrado por módulo. Por lo tanto, con el entrypoint
UI vuelve a ser la sesión gráfica quien registra el runtime; el daemon no
registra el proveedor persistente del módulo bajo el mismo identificador.
Esto recupera la semántica de `governor.open` de 1.0.4 pero deja pendiente
un diseño separado para disponer simultáneamente de endpoints IPC persistentes.

## Alcance del cierre

Fuente, tests Rust y construcción Qt 6.8.2 con Esbirro; nuevos ELF y hashes
SHA-256 certificados. La ejecución instalada y apertura real en Boss se prueban
posteriormente. No se modifican vaults ni Master Key.
