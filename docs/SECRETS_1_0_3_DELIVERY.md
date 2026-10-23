# N.E.E.B.L.E.S. Secrets 1.0.3 — Implementación y control de entrega

## Arquitectura certificada en fuente

Secrets sigue siendo el dueño exclusivo de las credenciales KDBX. `vault-general.kdbx` es solo para uso personal de Secrets; cada consumidor conserva su bóveda `vault-<module>.kdbx`. El daemon persistente gobierna autenticación, cifrado, desbloqueo, Backup & Restore y las operaciones IPC.

El broker externo verifica `SO_PEERCRED` y procedencia del ejecutable instalado, antes de pasar el descriptor mediante `SCM_RIGHTS` al trabajador KeePassXC aislado. Solo el Desktop oficial autenticado puede administrar la Master Key y bloqueo. Connect no puede administrar la bóveda de otro módulo.

Boss 2.0.7 controla dependencias a partir del Registry. `master_key=true` + `unblock=true` son condiciones de instalación de Connect; el bloqueo posterior deshabilita el acceso a secretos, no desinstala ni desactiva Connect. Quick Connect permanece independiente.

No hay Feature `open.ui` declarada para Secrets. Launcher y Tray permanecen.

## Pruebas ejecutadas antes de esta fase

- F18: 65+3 Rust OK; KDBX ignored en corrida común por necesitar KeePassXC real (previamente ejecutadas en el RootFS autorizado).
- F11-H: 2 pruebas de restauración sobre KDBX descartables OK.
- F12: 1 prueba de exportación portátil KDBX descartable OK.
- F13: 12 pruebas criptográficas en mundo aislado OK.
- F17: integridad ANTES sobre 2 bóvedas cifradas de Secrets 1.0.2 guardada en `$HOME/.local/state/neebles-secrets-qa/f17-before-1.0.3.json`.

## Gates de cierre después de preparar la fuente (no aprobados todavía)

1. Revisar manifest/código, compilar Rust y Qt sin recurrir al host fuera de mundos autorizados.
2. Certificar el cliente Connect 1.0.1 en instalación real contra Secrets 1.0.3; los peers sin procedencia deben rechazarse.
3. Probar lock/unlock; comprobar que solo My Connect dependa del desbloqueo; no reescribir KDBX durante comparación de integridad.
4. QA de UI Backup & Restore y exportación KDBX únicamente con recursos de laboratorio.
5. Actualizar mediante Boss/CUSTOM V2 con commit inmutable; configurar `runtime/construction/neebles-secrets.json` y Registry en sus repos correspondientes solo después de certificar la fuente.
6. Ejecutar F17 `after` y comparar *bytes cifrados idénticos* de las dos bóvedas existentes.
7. Solo al pasar esos gates y publicar/taguear puede comunicarse release 1.0.3 terminada.

No tocar `/opt` manualmente, no resetear Master Key, no regenerar hashes de material CUSTOM V2 sin cambios físicos.
