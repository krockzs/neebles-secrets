# Secrets F10 — implementación inicial Quick + Qt

## Alcance implementado

- Backend Rust autónomo de laboratorio: `runtime/src/main.rs`, `--serve`, `--status`, `--self-test`.
- Socket Unix `XDG_RUNTIME_DIR/neebles-secrets/secrets.sock`, modo `0600`, carpeta modo `0700`.
- Protocolo: JSON con prefijo `u32` big endian (una operación por conexión, máximo 16 KiB).
- `status` y `quick.generate` reales: contraseña configurable sin sesgo modular, token hex,
  token Base64URL y UUID v4. Aleatoriedad del kernel `/dev/urandom`.
- `vault.list`, `secret.*` y `vault.*` se **deniegan** mientras no haya desbloqueo real.
- Qt6 UI con logo existente, splash 3 segundos, barra lateral fija, una pestaña compartida
  (Dashboard, Quick Secrets, My Secrets) y encabezado de estado/botón Unlock.
- No hay Tray propio, no se tocan archivos KDBX ni se recopilan contraseñas maestras.
- El resultado Quick nunca se escribe en disco por Secrets; se borra del campo al salir de la vista.
  Si se utiliza Copiar, el portapapeles pertenece al escritorio y puede retener el valor.

## Alcance pendiente / no afirmar productivo

- Autenticación de usuario Linux y desbloqueo de KeePass/KDBX.
- Vault general y vault dinámicos reales, IPC de credenciales con autorización por módulo.
- Arranque automático opcional, bloqueo manual, sesiones y cierre de sesión.
- Integración con Boss Module IPC/Construction/Lifecycle y autoridad de sesión para el socket.
- Certificación Esbirro de build Qt6 + Rust y de runtime instalado.

**No desplegar F10 con Boss**: `manifest.json` todavía declara entrypoint reservado, sin
`governor.open` ni Construction. Este hito prueba el motor Quick y la UX inicial fuera del
instalador gobernado, como laboratorio local explícito.

## Compilación Rust controlada

Usar Rust 1.98.1 según el contrato de Esbirro/Boss. El `Cargo.lock` de F10 se deriva
únicamente del lock ya fijado en Connect (`serde_json=1.0.151`), sin resolver
nuevas versiones en internet.

```
cd "$HOME/NEEBLES/neebles-secrets/runtime"
cargo test --locked
cargo build --release --locked
./target/release/neebles-secrets --self-test
```

Prueba de socket local: desde una terminal ejecuta `./target/release/neebles-secrets --serve`,
y desde otra `./target/release/neebles-secrets --status`. El primer proceso sigue
atendiendo cuando se cierra la ventana Qt.

## Compilación Qt — CONSTRUIR SOLO CON ESBIRRO

El `CMakeLists.txt` exige `CMAKE_SYSROOT` y `NEEBLES_SECRETS_CONTROLLED_SYSROOT` idénticos,
además de Qt 6.8.2 exacto (Widgets + Network). No usa Qt arbitrario del host.
La configuración concreta de compilación debe reutilizar el procedimiento controlado
que ya funcionó para Connect, adaptando el nombre de proyecto y eliminando overlays
SSH/VNC. No ejecutar un build desde Qt 6.10 del host para marcar un falso PASS.

La interfaz requiere el árbol instalado conteniendo `manifest.json`, `assets/` y `bin/`.
Esta fase no publica binarios ni certifica un build.
