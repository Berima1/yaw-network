# Legacy prototype (Render, in-memory)

This records why the old code was replaced, so nobody resurrects it by accident. Everything below was found by reading the real repository (`main`) and the real Render account on 2026-10-03.

## Deployment problems

- `backend/server.js` required `./yaw-blockchain-core`, which does not exist (the file was `backend/src/blockchain/core.js`); used `redis` without importing it; `elliptic` was not in `package.json`.
- Root `Dockerfile`: first line `BLOCKCHAIN DOCKERFILE` is not a valid instruction; it also copied the wrong `package.json` and started a file that did not exist at that path.
- `render.yaml` referenced a database `yaw-mongodb` that it never defined, declared Redis and Postgres the app never used, and hard-coded a paid plan.
- Several conflicting deploy configs existed side by side (Render, Docker, Railway, PM2, docker-compose).
- Cluster mode forked one worker per CPU, each with its own in-memory chain and JWT secret.
- The chain lived in memory and reset on every restart.

## Logic problems

- `createTransaction` signed with the caller's key but stamped a freshly generated random public key on the transaction, so no signature could ever verify.
- No account ever had a balance (no genesis allocation), so every transaction failed validation. The `balance` option does not affect that check.
- Block production could never succeed: validators had no private keys, consensus recomputed hashes differently from the chain, and the difficulty could ratchet up inside a synchronous loop that froze the server.
- `/api/auth/register` never checked the signature; `ADMIN_KEY` unset meant admin routes were open; contract routes were registered after the catch-all 404.
- Token contract `transfer` accepted negative amounts.
- `crypto.createCipher` (used for the "triple-layer encryption") was removed in Node 22.

## Claims that were not true

Quantum-resistant lattice keys, zk-SNARK proofs, Byzantine "Ubuntu" consensus and triple-layer encryption were placeholders or crashed. Network statistics (hashrate, security score, decentralisation, Africa representation) were hard-coded constants. The simplified "Ubuntu" server that once ran on Render generated random transactions on a timer; the blocks it reported were not user activity.

## What happened to the old code

It is kept only in git history (`main` before the migration PR). The migration branch removes the broken server, core and deploy files. Other leftovers (`railway.toml`, `ecosystem.config.js`, `docker-compose.yml`, the Render `render.yaml` if still present) should be reviewed and removed in the merge PR.

## Render

The service from the original dashboard (`yaw-network-1`) was not present in the connected Render account. After the Cloud Run deployment is verified, decommission any remaining Render YAW services to avoid confusion and cost.
