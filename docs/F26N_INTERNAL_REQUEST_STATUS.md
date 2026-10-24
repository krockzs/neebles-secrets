# F26-N — Internal idempotent vault request/status (staging)

This increment adds worker-only `vault.request_id` and `vault.request_status` behind the existing authenticated SCM_RIGHTS peer. Only matching installed module identity can request its own vault; extra fields are rejected. The caller supplies a stable request_id for retries and reconciliation. The journal stores metadata only. A locked worker records Pending, without opening or creating a KDBX; after unlock, the existing pending fulfillment commits the status.

**Not published in Boss**: `contracts/commands.json`, `ipc_invoke_allow`, provider advertisement and Registry are unchanged; public `secrets.vault.request.v1` remains unavailable. Installed Secrets and real KDBX remain untouched. Later integration must not blindly retry an ambiguous write, and should query request status with the same ID.

QA uses Rust 1.98.1 offline on the Ryzen and scratch directories under `/tmp`, with no services started. Any failure is included in a generated TXT.
