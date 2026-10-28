# N.E.E.B.L.E.S. Secrets 1.0.7

**Estado documental: 28-10-2026.** Secrets 1.0.7 está publicado en el repositorio y seleccionado por el Registry de Boss. Es el custodio de bóvedas y estructuras cifradas consumidas por Connect 1.0.2. Esta página describe la implementación vigente; la visión original anterior a 1.0.7 permanece consultable en el historial Git.

## Responsabilidad y frontera de autoridad

**Boss gobierna; Secrets custodia y ejecuta; los consumidores declaran y solicitan.** Secrets es un módulo estructural con manifiesto schema 4, Lifecycle gobernado, daemon persistente de sesión y UI propia. No debe confundirse su carácter crítico para otros módulos con un permiso para saltarse la instalación, el modelo de autorizaciones o sus contratos.

- Módulo: `neebles-secrets`; versión declarada en `manifest.json` y `runtime/Cargo.toml`: **1.0.7**.
- UI canónica de apertura: `runtime/neebles-secrets-ui`, acción Governor `open`, paso Construction `open-ui`.
- Servicio de usuario declarado: `neebles-neebles-secrets-daemon.service`; entrada daemon `runtime/neebles-secrets --serve`.
- La recuperación del flujo UI de `open` es el cambio documentado de la release 1.0.7. **El daemon y la UI no son simultáneamente dos providers registrados con la misma identidad de runtime Boss**; el diseño de endpoints persistentes de Boss sigue siendo una cuestión distinta, según `release/notes-v1.0.7.md`.
- La configuración de Master Key y el estado de bloqueo/desbloqueo son propiedad de Secrets; publica variables de estado `master_key` y `unblock` (strings `"true"` / `"false"`) para los gates que Boss autorice.

## Bóvedas KDBX

El motor de custodia utiliza KeePass/KDBX mediante herramientas y material confinados en los mundos autorizados, no un KeePassXC encontrado casualmente en el host. El directorio privado del usuario se resuelve desde `XDG_DATA_HOME` o, en su defecto, `~/.local/share`:

```text
${XDG_DATA_HOME:-$HOME/.local/share}/neebles-secrets/vaults/
    vault-general.kdbx
    vault-neebles-connect.kdbx
    vault-<id-del-modulo>.kdbx
```

`vault-general.kdbx` es de uso personal, no una bóveda compartida entre módulos. Cada consumidor queda limitado a su propia bóveda bajo identidad autenticada; el nombre indicado en un JSON no reemplaza la identidad de su peer. El daemon no debe aceptar accesos directos no autorizados, y Connect nunca debe editar KDBX ni almacenar credenciales en Settings.

La creación de una bóveda con `vault.ensure` es idempotente. Ni Install, ni Update, ni Uninstall deben **borrar o reemplazar automáticamente** una KDBX existente. Un caso de migración incompatible requiere una decisión específica, una operación separada y comprobación del estado de los procesos.

## Estructuras cifradas consumidas por Connect 1.0.2

Secrets expone a su consumidor autenticado las operaciones privadas `structure.schema_define`, `structure.schema_get`, `structure.put`, `structure.get`, `structure.list`, `structure.delete` y `structure.batch`. La definición de esquema es idempotente si coincide; un esquema incompatible no se sobreescribe silenciosamente. Las operaciones aplican validaciones de campos, referencias, unicidad y revisiones para actualizaciones seguras.

La versión de Connect seleccionada utiliza tres esquemas en **su** bóveda:

| Esquema | Contenido | Regla |
|---|---|---|
| `myconnect` | Equipo, IP, usuario y grupos opcionales de credenciales SSH/VNC/Sunshine | Un registro por equipo; credenciales sensibles como campos `secret` |
| `vscode` | Instancias por equipo (`equipment`, nombre, puerto, credencial) | Cero a N; referencia al equipo y unicidad (`equipment`, `port`) |
| `dashboard` | Distribución personal del Dashboard | Documento cifrado de configuración |

La validación de grupos condicionales opcionales y rangos de puerto que el esquema genérico no expresa continúa en Connect. Para el contrato de campos, consultar `neebles-connect/docs/CONNECT_MYCONNECT_STRUCTURE_V1.md` y `ui/desktop/ConnectStructures.cpp`.

La transición excepcional de Connect 1.0.2 contempló renovar **solo** `vault-neebles-connect.kdbx` para adoptar los nuevos esquemas, nunca `vault-general.kdbx`, la Master Key o bóvedas ajenas. No existe autorización implícita para repetir esa operación en futuras actualizaciones; **este README no es una orden de borrado**.

## Capacidades adicionales y privacidad

El árbol contiene generación de secretos, primitivas criptográficas, almacenamiento personal, operaciones de backup/restore y motor de estructuras. El alcance puntual de cada endpoint debe comprobarse contra `runtime/src/main.rs`, `runtime/src/vault.rs`, `runtime/src/structured_records.rs`, contratos de `contracts/` y las pruebas de esa release, no inferirse de la visión histórica. Los valores sensibles no se publican como resultados de diagnóstico, logs o archivos secundarios.

Separación de caminos:

```text
Boss Registry / grants / Lifecycle
            |
Secrets daemon y UI de sesión
            |
Broker privado autenticado / validación de peer
            |
Bóveda KDBX exclusiva del consumidor
```

Los sockets privados y el IPC de módulos de Boss **no son el mismo canal**. El Registry `ipc_invoke_allow` es una autorización explícita para endpoints de Boss, no una autorización universal para abrir bóvedas.

## Construcción, release y QA

- Contratos: `manifest.json`, `lifecycle.json`, `contracts/commands.json`, `surfaces.json`.
- Rust: `runtime/src/`; UI Qt: `ui/desktop/`.
- Material privado de runtime: CUSTOM V2, Construction y RootFS seleccionados; compilación/certificación Qt en Esbirro, separadas de Rust.
- Release fuente y artefactos: commit `d61e3aa916d7c5863ae7dc9bb29661b711753a30`, versión **1.0.7**; consultar `release/notes-v1.0.7.md` y sus artefactos autenticados.
- Revalidar los flujos instalados con Boss y el servicio de usuario antes de atribuirles resultados de una futura versión. Una compilación verde no sustituye una prueba real bajo RuntimeLease.

## Integraciones y continuidad

El consumidor activo documentado es **NEEBLES Connect 1.0.2**. La prueba funcional de Connect (equipos, credenciales independientes y VNC de dos monitores) fue comunicada por el operador el 28-10-2026; no equivale a una matriz exhaustiva de backup/restore, fallos inducidos o portabilidad universal de Secrets.

Para desarrollar nuevos módulos, primero definir los datos estructurados y su autorización, luego consumir el broker privado, y finalmente ejecutar los gates de CUSTOM V2, Esbirro y Boss. Nunca sustituir la autoridad de Secrets por acceso directo a KDBX, KeePassXC del host o JSON de contraseñas.
