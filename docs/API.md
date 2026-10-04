# API

Base URL: the Cloud Run service URL. JSON in, JSON out. All amounts, fees and nonces are **decimal strings** (no leading zeros) in base units; 1 YAW = 1,000,000 units. Hex is always lowercase.

Errors look like `{ "error": { "code": "...", "message": "..." } }`.

## Read endpoints

| Method and path | Returns |
|---|---|
| `GET /health` | `{status:"ok"}` (liveness, no dependencies) |
| `GET /ready` | 200 if Firestore is reachable and the chain exists, else 503 |
| `GET /v1/chain` | chain id, consensus label, height, head hash, total supply, operator address/public key, symbol, decimals |
| `GET /v1/accounts/:address` | `{address, balance, nonce, exists}` (unknown addresses read as zero) |
| `GET /v1/blocks?from=0&limit=20` | up to 100 blocks starting at height `from` |
| `GET /v1/blocks/:height` | one block |
| `GET /v1/transactions/:id` | `{id, status, from, to, amount, fee, nonce, blockHeight?, blockHash?, reason?}`; status is `pending`, `confirmed` or `rejected` |

## Submit a transaction

`POST /v1/transactions`

```json
{
  "publicKey": "02...66 hex chars...",
  "to": "yaw...40 hex chars...",
  "amount": "1000",
  "fee": "0",
  "nonce": "0",
  "signature": "...128 hex chars..."
}
```

Unknown fields are rejected. The sender is derived from `publicKey`; it is never sent.

Responses: `201` confirmed (instant mode), `202` pending, `400` validation or signature errors, `409` duplicate / stale nonce / slot taken, `429` rate limited.

Error codes: `invalid_request`, `invalid_json`, `bad_signature`, `fee_too_low`, `invalid_amount`, `number_out_of_range`, `self_transfer`, `nonce_too_far`, `stale_nonce`, `nonce_slot_taken`, `duplicate_transaction`, `insufficient_funds`.

### Signing (reference, JavaScript)

```js
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';

const publicKey = bytesToHex(secp256k1.getPublicKey(privateKeyHex, true));
const from = 'yaw' + bytesToHex(sha256(hexToBytes(publicKey)).slice(-20));
const payload = `yaw-tx-v1\n${chainId}\n${from}\n${to}\n${amount}\n${fee}\n${nonce}`;
const id = bytesToHex(sha256(utf8ToBytes(payload)));
const signature = secp256k1.sign(id, privateKeyHex).toCompactHex();
```

`backend/src/crypto.js` contains the same logic as `signTransaction()`; the tests use it as the reference client.

A wallet must keep the nonce itself (start at the account's `nonce` from `GET /v1/accounts/:address`, then increment). Nonces up to `account.nonce + 15` are accepted at once.

## Operator endpoints

Require `Authorization: Bearer <PRODUCER_TOKEN>`. If `PRODUCER_TOKEN` is not configured they return 503 (fail closed).

| Method and path | Purpose |
|---|---|
| `POST /internal/produce-block` | run one block production attempt; `{produced, block}` |
| `GET /internal/audit` | `verifyChain({deep:true})` + `auditSupply()`; `{ok, supply, chain}` |

## Limits

- Body size 16 KB.
- Rate limit per instance and IP: 120 requests per minute overall, 30 transaction submissions per minute (configurable).
- CORS is closed unless `CORS_ORIGINS` lists browser origins.
