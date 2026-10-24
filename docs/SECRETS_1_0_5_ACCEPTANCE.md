# NEEBLES — 18 hitos de aceptación (fuente: Documento Maestro, 23/10/2026)

Este tablero se actualiza exclusivamente con evidencia verificable. **F26-A…Y son incrementos técnicos, NO hitos de aceptación**. Los 18 hitos corresponden a los QA-01…QA-18 del documento maestro. En particular, pasar un test aislado no equivale a certificar una instalación. No se contarán dos veces las pruebas.

| Hito | Criterio de salida | Estado al 24/10, antes del sprint |
|---|---|---|
| QA-01 | Boss 2.0.8 instalado; sockets; solicitud admin real y solicitud módulo autenticada | PARCIAL (sockets verificados en F26-U, Boss autenticado aislado F26-Y; falta completar aceptación en vivo) |
| QA-02 | Secrets 1.0.5 proveedor registrado instalado; endpoints + grants; denegación sin grant | PENDIENTE (código probado aislado, 1.0.4 instalada) |
| QA-03 | Connect propia bóveda; request repetido preserva; pending/unlock/succeeded | PENDIENTE (Secrets probado aislado; Connect no migrado) |
| QA-04 | Setup/unlock con Master Key creada/existente y KDBX preservada | PENDIENTE (KDBX descartables con Secrets en F26-V) |
| QA-05 | Lock/reinicio daemon, bloqueo My y Quick operativo, variables dinámicas | PENDIENTE |
| QA-06 | Denegación cross-vault/vault-general de consumidores reales | PENDIENTE (mocks de identidad aprobados) |
| QA-07 | Schema versiones, require_replica, 0..N, unicidad, IDs estables | PENDIENTE |
| QA-08 | CRUD/migración, altos recuentos, paginación, recuperación KDBX | PENDIENTE |
| QA-09 | Quick/Batch/Lab; vectores, límites, GUI, progreso/cancelación | PENDIENTE |
| QA-10 | Export TXT/CSV/JSON/KDBX portable, lectura KeePass y no filtrar | PENDIENTE |
| QA-11 | Backup/Restore total e individual en KDBX descartables | PENDIENTE |
| QA-12 | Connect CRUD nodos y secretos SSH/VNC independientes, VS Code N | PENDIENTE |
| QA-13 | Connect Quick/My SSH/VNC, lock solo My y unlock sin autoconectar | PENDIENTE |
| QA-14 | UI Compact/Expanded y copiar scrollback SSH/monitor VNC | PENDIENTE |
| QA-15 | VNC 1/multimonitor, escala, mouse, teclado | PENDIENTE |
| QA-16 | Sunshine/VS Code integrados o limitación sustentada | PENDIENTE |
| QA-17 | Build Rust/Qt certificado, ELF, material RootFS/RuntimeLease, hashes | PENDIENTE |
| QA-18 | CUSTOM V2, Construction, Registry, commits inmutables, update tras reboot | PENDIENTE |

## Regla de numeración

**N/18** = cantidad exacta de gates QA-01…QA-18 con evidencia física completa, no número de ZIPs ni fases preparadas. QA-01 solo se contabiliza cuando se cumpla entero. El reporte generado por este paquete **no concede por sí solo QA-02**, ya que la versión instalada sigue siendo 1.0.4.

## Próxima ejecución

La primera parte ejecuta solicitudes de solo lectura reales contra Boss instalado, toma snapshot del publisher autenticado y comprueba que un ping de módulo sin registro no sea aceptado. No registra ni suplanta módulos. La segunda parte, QA-02, requerirá publicar la candidata 1.0.5 con commit/pin válido y probar sus grants. No cambiar `/opt`, Registry ni bóvedas manualmente.
