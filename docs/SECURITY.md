# Security

Status: **testnet, unaudited**. Treat everything below as the current truth, not a promise.

## What is protected

- **Authorisation is cryptographic.** Spending requires a valid signature from the sender's key. There are no passwords, sessions or API keys to steal.
- **No cross-chain or cross-time replay.** The chain id and a per-account nonce are part of the signed payload.
- **No signature malleability.** Low-S enforcement; the transaction id is the hash of the payload, not of the signature.
- **Input is validated strictly** (zod, strict objects, canonical decimal strings, lowercase hex, size limits).
- **Operator endpoints fail closed**: without `PRODUCER_TOKEN` they are disabled; token comparison is constant time.
- **Secrets** live in Secret Manager, injected as environment variables; nothing is committed.
- **Firestore is not reachable by clients**: rules deny everything; only the backend's service account (IAM) can read or write.
- **Tampering is detectable**: `verifyChain` and `auditSupply` catch edited blocks and forged balances (tested).

## Known limitations (read before inviting users)

1. **Single operator.** The operator key owner can censor, delay or reorder transactions. This is a managed ledger, not a decentralised network.
2. **Operator key compromise = chain compromise.** There is no key rotation yet. Store the key only in Secret Manager; never paste it in chat or logs.
3. **Firestore admins can change data.** Detection exists; prevention does not. Restrict IAM on the project, enable audit logs, run `/internal/audit` on a schedule and alert on failure.
4. **No wallet is shipped.** Users must custody their own private keys; there is no recovery. A wallet app is a separate piece of work.
5. **Funds are not reserved at admission**, there is no cancel or replace-by-fee, and a rejected transaction with a lower nonce leaves higher-nonce ones waiting until the sender resubmits.
6. **Rate limiting is per Cloud Run instance** (in memory). For real abuse protection put Cloud Armor in front.
7. **Interim scheduler auth**: if Cloud Scheduler is used, the bearer token sits in the job's header. The planned improvement is verifying Google-signed OIDC tokens.
8. **Throughput is bounded** by Firestore (~1 block/s, 80 transactions per block).
9. **Not audited** by a third party. No penetration test has been done.
10. **Nothing here has been run against production yet** (see STATUS.md).

## Claims that must not be made

The following were advertised by the old prototype and are **false** for this system. Do not use them in marketing, docs or the UI:

- "quantum-resistant" / "lattice" / "Kyber" (it was random numbers, not Kyber),
- "zero-knowledge proofs" / "zk-SNARK" (placeholder code),
- "Byzantine" / "Ubuntu consensus" (simulated voting; the real design is single-operator PoA),
- "military-grade triple-layer encryption" (crashed on modern Node),
- any hashrate, security score or decentralisation score (the old values were constants).

If these become goals, they go on a roadmap with real, audited implementations.

## Before real value touches this (checklist)

- [ ] Tests green in CI and recorded in STATUS.md
- [ ] Smoke test against the deployed service recorded
- [ ] Independent security review of `crypto.js`, `ledger.js`, `app.js`
- [ ] Operator key rotation and recovery procedure
- [ ] Scheduled `/internal/audit` with alerting
- [ ] Firestore backups / point-in-time recovery enabled and a restore tested
- [ ] Cloud Armor or equivalent in front of the public API
- [ ] Legal review of what the token is and who may hold it in Ghana and target markets
