# NEEBLES Secrets 1.0.5 — Release candidate (NOT published)

Base de trabajo: 1.0.4; fuente candidata 1.0.5. Este documento NO afirma despliegue ni actualización instalada.

## Cambios acumulados

- Separación entre daemon persistente proveedor de Boss 2.0.8 y apertura de UI Qt (`show-ui`, instancia única).
- IPC registrado con cuatro comandos: `secrets.health.v1`, `secrets.vault.exists.v1`, `secrets.vault.request_status.v1`, `secrets.vault.request.v1`.
- Identidad autenticada por sesión Boss y control por módulo, con puente privado `SCM_RIGHTS`. No confiar en identidad remitida por el consumidor.
- Journal durable y solicitudes idempotentes mediante `request_id`, sin almacenar Master Keys en el journal.
- Recuperación de temporales interrumpidos; no sustituir KDBX existentes y no reintentar automáticamente escritura de estado incierto.
- Conciliación autenticada y bloqueo seguro ante clave inválida/estado ambiguo.

## Evidencia acumulada

- F26-S: 61 pruebas Rust seleccionadas aprobadas; simulación con archivos descartables.
- F26-V: 64 pruebas, incluidas 3 con KeePassXC real en Bubblewrap.
- F26-W: 65 pruebas, incluida integración IPC Secrets con Boss simulado y KDBX real.
- F26-X.1 y F26-Y: servidor auténtico Boss 2.0.8 y sesión Rust auténtica Secrets, ambos aislados; rechazo duplicados/identidades/capacidades.

## Pendiente para RELEASE

- Ejecutar daemon `--serve` instalado mediante Boss y certificar grants, execute/job_query y reinicio.
- QA-01...QA-18 del Documento Maestro.
- Construcción certificada Rust 1.98.1 y Qt 6.8.2 mediante CUSTOM V2, hash ELF, commit inmutable y pin en Registry.
- QA de My Secrets, Quick, Crypto Lab, Batch, exportaciones y Backup/Restore con datos descartables.
- Integración Connect solo después de cierre Secrets.

**No promover un release desde este documento.** El commit local solo congela una fuente candidata para poder construir material reproducible.
