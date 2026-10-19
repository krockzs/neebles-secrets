# F16 — Apertura independiente de Secrets (candidato)

- `runtime/neebles-secrets`: servicio Rust autónomo `--serve`; mantiene socket y clave mientras la sesión siga desbloqueada.
- `runtime/neebles-secrets-ui`: ejecutable nuevo de enlace con Module IPC de Boss; ejecuta Qt y termina al cerrar Qt.
- `lifecycle.json`: `governor.open` usa operación `open-ui` de Construction.
- `surfaces.json`: accesos en UI, Launcher y Tray **de Boss**, no un tray propio.
- `integration/systemd-user/neebles-secrets.service`: CANDIDATO. No se instala, habilita ni inicia en F16.
- CUSTOM Construction incluye los 3 RootFS; sus refs a Git todavía usan el commit publicado F09S. Hay que reemplazar el pin por una release certificada antes de instalación real.
- Ninguna actualización en Boss o Connect.

## Limitaciones pendientes

1. F16 no arranca ni instala el daemon. Integrar habilitación de systemd --user durante la instalación gobernada, sin sudo ni duplicar Vaults.
2. Contraseña maestra y creación real de `vault-general` deben validarse con `keepassxc-cli` en RootFS keepass real (no en host).
3. Garantizar que el puente de UI dispone del display y del socket Boss dentro de RuntimeLease.
4. Hacer release y actualizar commits inmutables de Registry y Construction.
5. Ningún Vault de módulo se crea en la instalación. Connect usa `vault.request` solo por interacción del usuario.
