# NEEBLES Secrets — F02: armazón inicial (19-10-2026)

Esta fase crea exclusivamente el esqueleto documental y declarativo de un módulo NEEBLES.
No constituye release, servicio criptográfico funcional ni módulo instalable certificado.

- Se conservó intacto el `README.md` histórico del repositorio.
- La nueva dirección incluye **bóveda cifrada de usuario** y **motor de operaciones criptográficas**
  (contraseñas, tokens, claves, peppers, hashes, etc.) reutilizables por otros módulos.
- El README histórico habla de `Vital Component`; actualmente se evaluará su integración
  como dependencia de `neebles-connect` mediante el mecanismo multi-módulo de Boss.
  La política de componente vital / instalación / desinstalación se cerrará en una fase posterior.
- `manifest.json` contiene un `entrypoint` **reservado y todavía inexistente**;
  `lifecycle.json` no declara Open y no hay runtime productivo ni Construction.
- `contracts/commands.json` no registra endpoints operativos.
- `surfaces.json` está vacío; no se ha diseñado ni habilitado la UI.
- Assets son los tres PNG aprobados y `icon.png` es copia idéntica del icon principal.
- Idiomas básicos `en_US` y `es_CL` son un punto de partida, no la traducción final.
- La bóveda debe persistir fuera del directorio de instalación; no se crea ni almacena aquí.
- **NO registrar este candidato en Boss ni instalarlo** hasta definir runtime, CUSTOM V2,
  autoridades, servicios e IPC. Su primera instalación de laboratorio será por `require`
  desde una nueva release de NEEBLES Connect, según decisión del ingeniero.
- Los RootFS `keepass-full` y `keepass-minimal` permanecen intactos en CUSTOM
  hasta auditoría y migración explícita. No se elige lenguaje en F02.
