# N.E.E.B.L.E.S. Secrets v1.0.3 — Personal vault, crypto and IPC integration

## New capabilities

- Secrets personal **My Secrets** CRUD inside `vault-general.kdbx` only.
- Quick Generator and Batch Generator; TXT, CSV, JSON and portable encrypted KDBX export. Portable KDBX uses a separate export password, never the Secrets Master Key.
- Cryptographic Lab: SHA-256/512, SHA3-256/512, BLAKE2, HMAC, Argon2id, PBKDF2 and scrypt; hashing and verification with bounded parameters.
- Encrypted KDBX backup, guarded restore preparation and multiple-vault transactional restore, with recovery journal.
- Brokered Unix IPC via `SO_PEERCRED` and `SCM_RIGHTS`, preserving the authenticated `neebles-secrets` Desktop identity across the sandbox boundary, and protecting per-module vault namespaces.
- Bilingual desktop UI (es_CL/en_US); Secrets exposes Launcher and Tray actions but **does not publish a Boss Feature**.

## Upgrade policy

- Update exclusively via Boss/CUSTOM V2. Do not manually install files under `/opt`.
- Retain the existing Master Key and all KDBX ciphertexts; **do not recreate or reset** the vaults.
- Existing Connect remains independently installed; installed Boss governs its `depends_install` requirements.
- The daemon's restart during the module update may lock the in-memory session. Unlock again with the existing Master Key when prompted.
- Save work before an update or reboot. A Boss Critical Update modal may request a reboot.

## QA evidence available as of source preparation

- Rust F18: 65 runtime tests + 3 ui_open passed, 0 failed, with 3 ignored KDBX integration tests run separately.
- F11-H: two authentic disposable KeePassXC KDBX restore tests passed in keepass-full.
- F12: authentic disposable portable KDBX exporter test passed in keepass-full.
- F13: 12 Crypto Lab tests passed in isolated world.
- F17: BEFORE fingerprint of two installed 1.0.2 encrypted KDBX files saved privately by the operator.
- Boss 2.0.7: installed dependency preflight and Launcher/Tray visual behavior approved by the operator.

**Release gate pending:** real installed 1.0.3 peer provenance with Connect, Qt->daemon KDBX workflows, and F17 AFTER byte-for-byte upgrade comparison. Source preparation does not mean these gates have passed or that this version has been published.
