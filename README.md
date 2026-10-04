# YAW Network

A small, honest ledger API for the YAW testnet, running on **Google Cloud Run + Firestore**.

> **Status: testnet, unaudited. Do not use it to hold real value.**
> The code on this branch has not yet been executed against a real Firestore. See [docs/STATUS.md](docs/STATUS.md) for exactly what has and has not been verified.

## What it is

- A **single-operator, proof-of-authority** ledger: one operator key signs blocks. It is not decentralised.
- Accounts and transactions are authenticated with **secp256k1 signatures** made on the user's device. The server never sees private keys.
- State lives in **Firestore** (accounts, blocks, transactions, mempool). Every block is hash-linked and signed, and the whole chain can be re-verified at any time.
- Stateless **Node.js** service, designed to run on **Cloud Run** (scale to zero, no servers to manage).

## What it is not (and was never)

The earlier prototype advertised quantum-resistant cryptography, zero-knowledge proofs, a Byzantine "Ubuntu" consensus and triple-layer encryption. In the old code those were simulations or crashed on startup. They have been **removed, not hidden**. See [docs/LEGACY.md](docs/LEGACY.md).

## Layout

```
backend/
  src/        crypto.js  apply.js  ledger.js  app.js  config.js  server.js ...
  test/       unit tests + Firestore-emulator tests
  Dockerfile  firestore.rules  .env.example
docs/
  ARCHITECTURE.md  API.md  SECURITY.md  DECISIONS.md  RUNBOOK.md  STATUS.md  LEGACY.md
  ci/backend-ci.yml   (copy to .github/workflows/ - see RUNBOOK)
frontend/     (not yet migrated to the new API)
```

## Run the tests

Unit tests need only Node 22+:

```bash
cd backend && npm install && npm run test:unit
```

Emulator tests need Java 21+ (the Firestore emulator) and run everything against a local Firestore:

```bash
npm run test:emulator
```

## Docs

| File | Read it when |
|---|---|
| [STATUS.md](docs/STATUS.md) | you want the truth about what works today |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | you want to understand or change the design |
| [API.md](docs/API.md) | you are building a wallet or frontend |
| [SECURITY.md](docs/SECURITY.md) | before any real user touches it |
| [DECISIONS.md](docs/DECISIONS.md) | you wonder why something is the way it is |
| [RUNBOOK.md](docs/RUNBOOK.md) | you deploy, roll back or debug |
| [LEGACY.md](docs/LEGACY.md) | you find references to the old Render/in-memory prototype |
