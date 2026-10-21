# Secrets 1.0.2 — API mínima para My Connect

## Almacenamiento

- Vault `vault-<module>.kdbx` existente, siempre dentro de `~/.local/share/neebles-secrets/vaults` (0700), 0600 para los archivos.
- No se migra ni se reescribe `vault-general.kdbx`: solo lo usa la Master Key y su finalidad futura queda fuera de alcance.
- El proveedor sigue siendo `keepassxc-cli` bajo RootFS certificado, sin .env, SQLite, JSON plano ni perfiles de prueba.
- `vault.ensure` crea solo si no existe; nunca reemplaza vault existente. `secret.put/update/delete` modifican una copia cifrada transaccional que se valida y publica con rename atómico.

## IPC (uint32 BE + JSON), solo mientras Secrets unlocked

Operaciones requieren `module` coincidente con el módulo ejecutable autenticado mediante SO_PEERCRED + manifiesto instalado inmutable. Se permiten ejecutables `runtime/<module>` y `bin/<module>-desktop` dentro de `/opt/neebles/modules/<module>` con propiedad root y sin escritura group/other.

- `{ "op": "secret.put", "module": "neebles-connect", "id": "ryzen", "value": {"ip":"192.168.1.2","user":"u","password":"p","ssh_port":22,"vnc_port":5900} }`
- `{ "op": "secret.get", "module": "neebles-connect", "id": "ryzen" }`
- `{ "op": "secret.update", "module": "neebles-connect", "id": "ryzen", "value": {...} }` (requiere existencia)
- `{ "op": "secret.delete", "module": "neebles-connect", "id": "ryzen" }`
- `{ "op": "vault.list", "module": "neebles-connect" }` y `secret.list` = ids en vault cifrado; nunca enumera otros vaults

Payload de valor JSON arbitrario, límite 8KiB, máximo 256 IDs por vault. Los nombres de entradas son ids no confidenciales y el contenido completo se guarda en el campo PASSWORD protegido de KeePassXC codificado Base64URL (sin datos sensibles en argv). Índice de IDs almacenado como entrada cifrada protegida en el mismo KDBX. No se guardan copias JSON locales. Ninguna llamada reenvía Master Key desde Connect.

## Requisitos de certificación no omitibles

1. `cargo test --locked --bins`; build release usando Rust/Esbirro.
2. Prueba real de add/show/edit/rm/ls del `keepassxc-cli` instalado en RootFS keepass-full (no asumir éxito por tests unitarios).
3. Probar que cliente externo/suplantador no puede consultar secret.get; prueba con ejecutable Connect autorizado sí.
4. Prueba Update 1.0.1→1.0.2 con persistencia bit-a-bit de vault-general + Master Key, y restauración del daemon post restart.
5. Validar source pin CUSTOM, manifests de tres rootfs, registry y release notes antes de publicación.

## Threat model

La validación del ejecutable del peer impide la suplantación trivial a través de un cliente arbitrario de socket del mismo UID. No sustituye la separación completa por UID/sandbox independiente o un broker de capacidades de Boss; procesos maliciosos ejecutados por el propietario de escritorio siguen perteneciendo al mismo dominio de confianza del usuario.
