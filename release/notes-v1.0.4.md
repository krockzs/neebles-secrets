# N.E.E.B.L.E.S. Secrets v1.0.4 — Corrected binary publication

- Rebuild and publish the complete executable payload for the Secrets 1.0.3 feature set: Rust daemon, Rust UI bridge, and Qt 6.8.2 desktop.
- Correct the governed UI bridge's installed manifest version check to v1.0.4.
- Update the actual Qt desktop version labels to v1.0.4.
- Preserve 1.0.3 features: My Secrets, Quick/Batch Generator, Cryptographic Lab, encrypted export, transactional KDBX Backup/Restore, brokered IPC, per-module vault boundaries, and es_CL/en_US UI.
- Preserve Launcher and Tray; do not create a Boss Feature.

Upgrade through Boss/CUSTOM V2 only. Do not recreate the Master Key or existing KDBX files. Verify installed executable hashes against the certified release after updating.
