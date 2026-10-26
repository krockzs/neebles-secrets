# Secrets 1.0.5 — atomic structured batch and forward-only schema migrations

**SOURCE-ONLY, NOT FOR RELEASE.** Base: last accepted universal core and physical index v2 on Git HEAD `007842709ecacd22bcb84992287c19d9b7526655`.

- Private authenticated broker adds `structure.batch` with `operations` array (1..32). Peer module identity is assigned by Unix broker. JSON claims never authorize a module.
- Atomic envelope uses existing KDBX transaction copy and rename; no plaintext sidecars. A stable parent-directory Linux flock serializes writer transactions even if the KDBX file inode is replaced. Each internal entity operation writes to the private transaction KDBX without recursively locking the folder.
- Staging overlay validates all operations, references, uniqueness, revision preconditions and unknown fields before writing *anything*. Failure during KeePassXC write or final validation discards the whole encrypted temporary vault.
- Explicit `migrate` increments schema version by **exactly one**, checks all existing records with new field types/defaults/uniqueness/references, and updates schema + entity revisions atomically. No implicit migration and no downgrade. Existing fields cannot be silently removed when data is present.
- Maximum 1,024 records per one schema-migration batch pending a paged, crash-resumable migration design; up to 32 mixed operations per batch. This is not yet the final migration solution for 16k records, and is NOT permission to release.
- Source-only tests exercise atomic grouped CRUD, dependent deletes, forward migrations, incompatible schema rejection, revision conflicts and spoofed envelope fields. One ignored Rust integration test uses real KeePassXC and disposable KDBX in the read-only keepass-full Bubblewrap world; it checks encrypted bytes are unchanged after a failed grouped write.

**Remaining before release:** migrate large schemas in chunks with crash recovery; optimize KDBX index paging and transport >8KiB/16KiB limits; Boss public schema contracts & grants; physical UI/crypto/export/restore QA; CUSTOM V2 and release under Boss. No release or Registry changes in this package.
