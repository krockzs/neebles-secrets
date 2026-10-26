# NEEBLES Secrets 1.0.6 — candidato de integración (NO PUBLICADO)

## Alcance

- Reemisión de Secrets sobre la fuente 1.0.5 y alineación de las identidades 1.0.6 en manifest, Cargo/lock, pruebas del runtime y etiquetas de UI Qt.
- Normalización del formato Rust para cumplir el gate `cargo fmt --all -- --check`.
- Mantiene las funciones existentes y la compatibilidad contractual del middleware Boss; no introduce una ruta alternativa para el host ni cambios en bóvedas.

## Gates de publicación (no asumir aprobados)

1. Tests de Rust y build release con Rust 1.98.1; registrar evidencia verificable.
2. Qt 6.8.2 recompilado exclusivamente con laboratorio controlado Esbirro; instalación DESTDIR y auditoría ELF.
3. Validar `runtime/neebles-secrets`, `runtime/neebles-secrets-ui` y `bin/neebles-secrets-desktop`; generar `release/artifacts-v1.0.6.json` solamente con SHA256 de los bytes finales.
4. Inspeccionar y conservar la modificación local en `neebles-custom/runtime/construction/neebles-secrets.json` antes de editarla. Fijar SHA inmutable de Secrets y coherencia de selectors/material certificables.
5. Publicar primero el commit inmutable de Secrets; después CUSTOM V2; finalmente actualizar y publicar selector de Boss Registry con nuevo SHA/versión. No inventar versiones de Boss.
6. Probar update y Open desde Boss real, IPC real, servicio persistente, Master Key y vaults reales sin pérdida; QA en entornos descartables para escrituras destructivas.

Este documento no es una certificación ni una release publicada.
