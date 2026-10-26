# NEEBLES Secrets 1.0.5 — KDBX v2 paged physical index + QA regression repair

**NO RELEASE.** This increment builds on the already applied universal-structures core, HEAD `007842709ecacd22bcb84992287c19d9b7526655`. Never overwrite data in `/opt` or real vaults.

## Functional changes

1. Fix F16 status/Quick regression correctly: its historical test fixture intentionally had **no directory**, contrary to the constructor's guaranteed `0700` directory. The test now builds and removes an empty private disposable directory; production validation stays fail-closed.
2. Keep the `__neebles_secret_index_v1` encrypted index completely intact for existing KDBX; transparently write `__neebles_secret_index_v2` plus encrypted 64-ID pages when the old 256-item or 8KiB index ceiling would be exceeded. The v2 marker is authoritative after successful writes on a **transactional copy of the KDBX**. No plaintext sidecars.
3. Fail closed on missing/invalid pages, inconsistent counts, duplicate IDs or unsorted shards. Permits up to **16,384 identifiers per KDBX** with a bounded in-memory index. Preserves old v1 protected entry, even after upgrading.
4. Raises KeePass output pipe cap to **64KiB** solely so old v1 indices with up to 256 long identifiers remain readable. Individual secret payloads **remain capped at 8192 bytes**, and the broker's **16KiB framed IPC limit remains unresolved**.
5. Adds five non-ignored v2 index tests (256→1024, 2048/pruning, corruption, long legacy v1, hard bound) and one genuine KeePassXC **ignored** sandbox test that writes a 280-ID v2 index to a new scratch KDBX.
6. Removes unused import in `structured_records.rs`.

## Work remaining BEFORE publication

Physical index v2 tests and one scratch KDBX are NOT yet a 1000-entity real KDBX throughput certificate: mutations currently re-read/shard the index and re-open KeePassXC repeatedly. Need paging/batch transport, proper atomic multi-entity transactions, migration plans for schema revisions and legacy records, Boss contracts/grants for generic APIs, stress tests and QA-09..11 of UI/crypto/export/restore. No Boss/CUSTOM/Connect edits here.

## Execute on Ryzen

```bash
unzip -o "$HOME/Downloads/NEEBLES_SECRETS105_INDEX_KDBX_V2_20261024.zip" -d "$HOME/Downloads"
python3 -B "$HOME/Downloads/NEEBLES_SECRETS105_INDEX_KDBX_V2_20261024/ejecutar_index_v2.py" --run
```

Generates `~/Downloads/NEEBLES_SECRETS_INDEX_V2_RESULTADO_*.txt`, including on error. `--check` and `--verify` do not mutate sources. `--run` never commits or publishes.
