# Architecture

```
  wallet / frontend (signs on the user's device)
          |  HTTPS  JSON
          v
  Cloud Run: yaw-ledger-api  (Node 24, Express, stateless)
          |  Firestore server SDK (service account, no keys)
          v
  Firestore (Native mode)  <-- Cloud Scheduler (optional) POST /internal/produce-block
```

The service holds no state. Any instance can serve any request. All consistency comes from Firestore transactions.

## Data model (Firestore collections)

| Collection | Document id | Purpose |
|---|---|---|
| `meta` | `chain` | chain id, height, head hash/timestamp, tx count, total supply, operator public key and address, fee recipient, genesis allocations |
| `accounts` | address | `balance` (integer base units), `nonce` (next expected), timestamps |
| `blocks` | height zero-padded to 12 digits | hash, prevHash, timestamp, merkleRoot, txIds, txCount, producer, signature |
| `mempool` | `<sender>-<nonce>` | pending transactions; one slot per (sender, nonce) |
| `txs` | transaction id | final records: `confirmed` (with block height/hash/index) or `rejected` (with reason) |

An optional `COLLECTION_PREFIX` namespaces all collections (used by tests so they never share data).

No composite indexes are required: every query uses a single field (`orderBy('createdAt')`, `orderBy('height')`, `where('id','==',...)`).

## Identity and signatures

- Key pair: secp256k1. Public key is the 33-byte compressed form (66 hex chars).
- Address: `yaw` + last 20 bytes of `sha256(publicKey)` as lowercase hex.
- Signature: ECDSA, 64-byte compact form (128 hex chars), **low-S only** (rejects malleable twins).
- Libraries: `@noble/curves` and `@noble/hashes` (audited, no native code).

## Transaction lifecycle

1. Client builds `{to, amount, fee, nonce}` and signs the id `sha256(payload)` where
   `payload = "yaw-tx-v1\n<chainId>\n<from>\n<to>\n<amount>\n<fee>\n<nonce>"`.
   The chain id is inside the payload, so a signature is valid on one chain only.
2. `POST /v1/transactions` checks format, signature, fee floor, `nonce >= account.nonce`, `nonce < account.nonce + 16`, and `balance >= amount + fee` (confirmed balance only).
3. The transaction is written to `mempool/<sender>-<nonce>` with `create()`. A second transaction for the same slot fails (`nonce_slot_taken`).
4. A block producer applies pending transactions in one Firestore transaction (see below).

Admission does **not** reserve funds. Two pending transactions that together exceed the balance both pass admission; the second is rejected at block time (`insufficient-funds`). Rejection frees the slot, the nonce is not consumed, and the sender may resubmit.

## Block production

`produceBlock()` runs inside one Firestore transaction:

1. read `meta/chain` and up to `MAX_TX_PER_BLOCK` oldest mempool entries (default 50, max 80);
2. re-verify every signature;
3. load all involved accounts;
4. apply them with the pure function `applyTransactions` (`src/apply.js`): per sender strict nonce order, funds check, fee to the fee recipient;
5. write: confirmed/rejected records, updated accounts, the block (`create()`, so a height can never be written twice), updated `meta`.

Concurrent producers are safe: they serialise on `meta/chain`, the loser retries and sees an empty mempool. A block is created only if at least one transaction executed.

Block hash = `sha256("yaw-block-v1\n<chainId>\n<height>\n<prevHash>\n<timestamp>\n<merkleRoot>\n<txCount>\n<producer>")`, signed by the operator key. `txCount` is committed so the odd-leaf duplication in the merkle tree cannot be abused.

Two ways to trigger production:

- `INSTANT_BLOCKS=true`: every accepted transaction triggers a block attempt (best for a testnet).
- Cloud Scheduler calling `POST /internal/produce-block` (minimum interval one minute).

## Integrity checks

- `verifyChain({deep})`: recomputes every hash, link, merkle root and producer signature; `deep` also re-verifies every confirmed transaction.
- `auditSupply()`: scans all accounts; balances must be non-negative safe integers and sum to the genesis supply (fees are redistributed, never burned, so the sum is constant).
- Both are exposed at `GET /internal/audit` (token protected). Run them on a schedule once deployed.

## Limits to know

- Firestore allows roughly one sustained write per second per document; `meta/chain` is written once per block, so keep block rate at or below ~1/s.
- A Firestore transaction allows at most 500 writes, hence the 80-transactions-per-block cap.
- Amounts are integers in base units (1 YAW = 1,000,000) and must stay below 2^53. Total supply is validated at genesis, which makes overflow impossible.
- `GENESIS_ALLOCATIONS` allows at most 400 accounts and is read only when the chain is first created.
