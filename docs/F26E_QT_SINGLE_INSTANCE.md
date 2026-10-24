# F26-E — Singleton Qt para NEEBLES Secrets 1.0.5

Estado: parche de fuentes, pendiente de QA/aceptación en Ryzen. **No activa el proveedor persistente**.

- `SingleInstanceGate` aplica lock de proceso (`QLockFile`) y socket de notificación (`QLocalServer`) dentro de un directorio de runtime propio, 0700 y perteneciente al usuario.
- Una segunda solicitud `show-ui` no inicia otra ventana; entrega `ACTIVATE` y recibe confirmación. Si falla la notificación, termina con error (fail-closed).
- La instancia principal hace `raise()`/`activateWindow()` y restaura la ventana minimizada. Las solicitudes que llegan durante el splash se aplican cuando MainWindow aparece.
- El bloqueo vive exclusivamente en el proceso de escritorio Qt. No comparte lock con daemon Secrets, broker KDBX ni Boss.
- Se mantiene la compatibilidad con `open` del modelo legado y con `show-ui` del modelo futuro; ni Construction ni manifest ni Registry cambian aquí.
- QA headless opcional: `-DNEEBLES_SECRETS_BUILD_TESTS=ON`, `ctest` con Qt del sysroot Esbirro. El test crea directorios temporales, nunca KDBX.
- Condición a certificar al publicar: repetición desde Launcher/Tray con ventana abierta, minimizada, durante splash y cerrada; foco bajo KDE/X11; salida limpia del helper Lifecycle.

La mera compilación no certifica la integración real con Boss ni la ejecución con Wayland. No publicar aún.
