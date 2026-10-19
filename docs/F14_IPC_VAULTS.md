# NEEBLES Secrets F14 — Contrato IPC y primera bóveda

## Arquitectura exigida

- El instalador de Secrets debe preparar **solo** el servicio/socket y `vault-general.kdbx` (bóveda personal). La interfaz Qt permite configuración inicial y desbloqueo; conectar esa configuración al asistente gobernado de instalación sigue pendiente.
- **Ningún Vault de módulo se crea durante el `require` / instalación del módulo.**
- Cada consumidor (`neebles-connect`, en esta fase) expone su propio control "Vault no instalado". El usuario abre la interfaz Secrets para desbloquear una vez. Entonces el **módulo** solicita `vault.ensure` a Secrets usando el socket.
- Secrets crea `vault-<module>.kdbx` **solo a solicitud del módulo**, solamente desbloqueado, sin sobrescribir la base existente, y nunca recibe una segunda contraseña del módulo.
- `vault-general.kdbx` no es la bóveda de un módulo ni se abre automáticamente a otros módulos. Su futuro contenido corresponde al usuario y las capacidades criptográficas del Arsenal.

## IPC JSON — longitud de frame uint32 BE + JSON

```
{"op":"vault.status"}                      -> {"ok":true,"data":{"locked":true|false,"initialized":true|false,...}}
{"op":"vault.setup","password":"..."}     -> SOLO primera configuración (crea vault-general)
{"op":"vault.unlock","password":"..."}    -> Verifica contraseña global contra vault-general
{"op":"vault.lock"}                        -> Desbloqueo termina, claves se descartan del estado del servicio
{"op":"vault.exists","module":"neebles-connect"} -> {"ok":true,"data":{"module":"neebles-connect","exists":bool,"locked":bool}}
{"op":"vault.ensure","module":"neebles-connect"} -> {"ok":true,"data":{"module":"neebles-connect","created":bool,"exists":true}}
```

`vault.ensure` retorna `vault_locked` mientras Secrets no esté desbloqueado. `created=false` significa que existe y fue preservado. No existe endpoint para enumerar o leer secretos entre módulos. El módulo no transmite contraseña.

Los nombres `general`, rutas, valores con `.` o `/`, mayúsculas y segmentos vacíos son rechazados como identificadores de módulo.

## Custodia

- `~/.local/share/neebles-secrets/vaults/`, modo `0700`.
- `vault-*.kdbx`, modo `0600`, cifrado por KeePassXC CLI, sin guardar contraseña en un archivo, log, argumento de proceso o variable de entorno.
- CLI de KeePassXC es requerida en el mundo de ejecución donde opera el backend: `/usr/bin/keepassxc-cli`.
- Archivo temporal se publica con hard-link **sin reemplazo** sobre la ruta de destino.
- Errores no revelan contraseña ni texto de salida de KeePass.

## Alcance NO resuelto por F14

- **No es release ni certificación**: falta instalación/Construction/Preinstall/Registry, socket unit y servicio persistente gobernado; Boss queda intacto.
- F14 cambia los fuentes Rust/Qt. Después del APPLY hay que **recompilar** Rust y Qt; F11 y F12 antiguos solo certifican sus binarios anteriores.
- La API del socket es accesible a procesos del mismo UID; **la autenticación fuerte del módulo solicitante** y el permiso de namespace contra suplantación deben verificarse antes de habilitar operaciones productivas sobre credenciales. Esta versión expone únicamente `vault.exists/ensure`; jamás las lecturas/escrituras de secretos de terceros.
- Los materiales KeePass están verificados dentro de CUSTOM, pero no se probó `keepassxc-cli` real en el mundo runtime de Secrets. Por ello solo está preparado el código, no la creación KDBX verificada en Ryzen.
- La interfaz Connect (`My Connections`: "Vault no instalado", botón para abrir Secrets y solicitud `vault.ensure`) será una integración posterior, no una capacidad atribuida a Secrets Qt.
