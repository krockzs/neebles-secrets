# NEEBLES Secrets 1.0.2 — Vault records for Connect

- Adds guarded `secret.put`, `secret.get`, `secret.update`, `secret.delete`, `vault.list` and `secret.list` commands to the existing session IPC.
- Per-module secret values and the listing index are stored exclusively as protected password entries **inside the module KDBX**. No plaintext profiles or sidecar JSON database.
- `secret.update` maintains the same connection identifier. Put / Update / Delete use encrypted KDBX staging and atomic publication.
- Secret RPCs are restricted to the matching installed module executable, authenticated with Linux peer credentials and root-owned path checks.
- `vault-general.kdbx`, `vault.setup`, `vault.unlock`, existing vault paths, initial provisioning and persistence remain unchanged.
- Runtime, Qt and manifest version aligned to 1.0.2.

Certification prerequisite: verify the KeePassXC CLI arguments against the pinned CUSTOM V2 keepass-full RootFS on the Ryzen, Rust tests, Boss-governed Update and KDBX hashes before and after restart. This source candidate is **not** a published release.
