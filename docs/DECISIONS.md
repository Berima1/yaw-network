# Decisions

Each entry: what was decided, why, and what would change it. Status `open` means it needs the owner's call.

**D1. Cloud Run + Firestore (decided by the owner).** Serverless, no servers to patch, scale to zero, pay per use. Firestore gives transactions and strong consistency. Trade-off: not built for high write throughput on a single document.

**D2. Single-operator proof of authority.** The old design claimed Byzantine consensus but never implemented it. One signing key is honest, simple and testable. Revisit only with a real multi-party design.

**D3. Integer base units, 6 decimals (open).** `1 YAW = 1,000,000` units, stored as integers below 2^53, so there is no floating-point money. The decimals value is a technical choice I made; the owner should confirm it before any public launch because changing it later is breaking.

**D4. secp256k1 via `@noble` libraries.** Familiar to wallet developers, audited, pure JavaScript. The old `elliptic` dependency was dropped.

**D5. Address = `yaw` + 20 bytes of sha256(public key).** Hash of the key, not a slice of it (the old code used the first 20 hex characters of the key, which all start with `04`).

**D6. Mempool slot per (sender, nonce).** Bounds the pending set to funded accounts x 16 and removes the need for a composite index. Cost: no replace-by-fee.

**D7. No composite Firestore indexes.** Fewer moving parts to deploy and forget.

**D8. Block production: instant mode and/or Scheduler.** Instant mode gives immediate confirmation on a testnet. Scheduler (minimum one minute) suits low-cost operation. Both call the same code.

**D9. Region (open).** Firestore supports `africa-south1` (Johannesburg). It is the natural choice for "built for Africa" and data locality, but latency from Ghana to Johannesburg has not been measured and could be worse than a European region because of subsea routing. Firestore location cannot be changed after creation (a new database can be created and data moved). Cloud Run must use the same region. Recommendation: measure from Ghana first; default to `africa-south1` if the difference is small.

**D10. Tests first, deploy second.** Nothing is deployed until the test suite has actually run and the result is recorded in STATUS.md.

**D11. Fixes on a branch, not `main`.** `main` is untouched until the branch is verified.

**D12. Genesis allocations are explicit config, never invented.** No token supply, faucet or economics were assumed. The owner defines them in `GENESIS_ALLOCATIONS` when the chain is created.
