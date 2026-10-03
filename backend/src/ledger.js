import { FieldPath } from '@google-cloud/firestore';
import { ApiError } from './errors.js';
import {
  ADDRESS_RE,
  HEX64_RE,
  addressFromPublicKey,
  blockHash,
  merkleRoot,
  publicKeyFromPrivate,
  signHash,
  verifyHash,
  verifyTransactionSignature,
} from './crypto.js';
import { applyTransactions } from './apply.js';

const ZERO_HASH = '0'.repeat(64);
export const MAX_NONCE_AHEAD = 16;
export const DECIMALS = 6;
const TX_OPTIONS = { maxAttempts: 10 };
const pad = (height) => String(height).padStart(12, '0');

function formatTx(d, status) {
  return {
    id: d.id,
    status,
    from: d.from,
    to: d.to,
    amount: String(d.amount),
    fee: String(d.fee),
    nonce: String(d.nonce),
    createdAt: d.createdAt,
    ...(d.blockHeight !== undefined && { blockHeight: d.blockHeight, blockHash: d.blockHash, index: d.index }),
    ...(d.reason && { reason: d.reason }),
  };
}

export class Ledger {
  constructor({ db, config, log }) {
    this.db = db;
    this.config = config;
    this.log = log;
    const p = config.collectionPrefix;
    this.meta = db.collection(`${p}meta`).doc('chain');
    this.accounts = db.collection(`${p}accounts`);
    this.blocks = db.collection(`${p}blocks`);
    this.txs = db.collection(`${p}txs`); // final records: confirmed or rejected
    this.mempool = db.collection(`${p}mempool`); // pending, one slot per (sender, nonce)
    this.operatorPublicKey = publicKeyFromPrivate(config.operatorPrivateKey);
    this.operatorAddress = addressFromPublicKey(this.operatorPublicKey);
    this.feeRecipient = config.feeRecipient || this.operatorAddress;
  }

  // Idempotent. Creates the genesis block on first run, otherwise checks that this process is
  // configured for the chain that already exists (wrong secret / wrong chain id => fail fast).
  async init() {
    const { chainId, genesisAllocations } = this.config;
    await this.db.runTransaction(async (t) => {
      const snap = await t.get(this.meta);
      if (snap.exists) {
        const m = snap.data();
        if (m.chainId !== chainId) throw new Error(`chain id mismatch: stored=${m.chainId} configured=${chainId}`);
        if (m.operatorPublicKey !== this.operatorPublicKey) throw new Error('operator key mismatch: this chain was created with a different key');
        if (m.feeRecipient !== this.feeRecipient) throw new Error('fee recipient mismatch');
        return;
      }
      const now = Date.now();
      let totalSupply = 0;
      for (const [address, amount] of Object.entries(genesisAllocations)) {
        totalSupply += amount;
        t.set(this.accounts.doc(address), { address, balance: amount, nonce: 0, createdAt: now, updatedAt: now });
      }
      const root = merkleRoot([]);
      const hash = blockHash({ chainId, height: 0, prevHash: ZERO_HASH, timestamp: now, merkleRoot: root, txCount: 0, producer: this.operatorAddress });
      t.create(this.blocks.doc(pad(0)), {
        height: 0,
        hash,
        prevHash: ZERO_HASH,
        timestamp: now,
        merkleRoot: root,
        txIds: [],
        txCount: 0,
        producer: this.operatorAddress,
        signature: signHash(hash, this.config.operatorPrivateKey),
      });
      t.create(this.meta, {
        schema: 1,
        chainId,
        height: 0,
        headHash: hash,
        headTimestamp: now,
        txCount: 0,
        totalSupply,
        operatorPublicKey: this.operatorPublicKey,
        operatorAddress: this.operatorAddress,
        feeRecipient: this.feeRecipient,
        genesisAllocations,
        createdAt: now,
      });
    }, TX_OPTIONS);
  }

  async getChainInfo() {
    const snap = await this.meta.get();
    if (!snap.exists) throw new ApiError(503, 'not_initialized', 'chain is not initialized');
    const m = snap.data();
    return {
      chainId: m.chainId,
      consensus: 'single-operator-proof-of-authority',
      height: m.height,
      headHash: m.headHash,
      headTimestamp: m.headTimestamp,
      txCount: m.txCount,
      totalSupply: String(m.totalSupply),
      operatorAddress: m.operatorAddress,
      operatorPublicKey: m.operatorPublicKey,
      feeRecipient: m.feeRecipient,
      symbol: 'YAW',
      decimals: DECIMALS,
    };
  }

  async getAccount(address) {
    if (!ADDRESS_RE.test(address)) throw new ApiError(400, 'invalid_address', 'address must be "yaw" followed by 40 lowercase hex characters');
    const snap = await this.accounts.doc(address).get();
    const d = snap.exists ? snap.data() : { balance: 0, nonce: 0 };
    return { address, balance: String(d.balance), nonce: String(d.nonce), exists: snap.exists };
  }

  async getBlock(height) {
    if (!Number.isSafeInteger(height) || height < 0) throw new ApiError(400, 'invalid_height', 'height must be a non-negative integer');
    const snap = await this.blocks.doc(pad(height)).get();
    if (!snap.exists) throw new ApiError(404, 'block_not_found', `no block at height ${height}`);
    return snap.data();
  }

  async listBlocks(from, limit) {
    const snap = await this.blocks.orderBy('height').startAt(from).limit(limit).get();
    return snap.docs.map((d) => d.data());
  }

  async getTransaction(id) {
    if (!HEX64_RE.test(id)) throw new ApiError(400, 'invalid_transaction_id', 'transaction id must be 64 lowercase hex characters');
    const final = await this.txs.doc(id).get();
    if (final.exists) return formatTx(final.data(), final.data().status);
    const pending = await this.mempool.where('id', '==', id).limit(1).get();
    if (!pending.empty) return formatTx(pending.docs[0].data(), 'pending');
    throw new ApiError(404, 'transaction_not_found', 'transaction not found');
  }

  // Admission control only. Funds are not reserved: a second pending transaction from the same
  // sender can still be rejected at block time (see produceBlock / applyTransactions).
  async submitTransaction(input) {
    const { chainId, minFee } = this.config;
    const amount = Number(input.amount);
    const fee = Number(input.fee);
    const nonce = Number(input.nonce);
    for (const [name, value] of [['amount', amount], ['fee', fee], ['nonce', nonce], ['amount+fee', amount + fee]]) {
      if (!Number.isSafeInteger(value)) throw new ApiError(400, 'number_out_of_range', `${name} is out of range`);
    }
    if (amount < 1) throw new ApiError(400, 'invalid_amount', 'amount must be at least 1');
    if (fee < minFee) throw new ApiError(400, 'fee_too_low', `minimum fee is ${minFee}`);

    let check;
    try {
      check = verifyTransactionSignature({
        chainId,
        publicKey: input.publicKey,
        signature: input.signature,
        to: input.to,
        amount: input.amount,
        fee: input.fee,
        nonce: input.nonce,
      });
    } catch {
      check = { ok: false };
    }
    if (!check.ok) throw new ApiError(400, 'bad_signature', 'signature does not match this transaction, chain and public key');
    const { id, from } = check;
    if (from === input.to) throw new ApiError(400, 'self_transfer', 'sender and recipient must differ');

    const createdAt = Date.now();
    const txRef = this.txs.doc(id);
    const slotRef = this.mempool.doc(`${from}-${nonce}`);
    const accountRef = this.accounts.doc(from);

    await this.db.runTransaction(async (t) => {
      const [txSnap, slotSnap, accountSnap] = await t.getAll(txRef, slotRef, accountRef);
      if (txSnap.exists) throw new ApiError(409, 'duplicate_transaction', 'this transaction was already processed');
      if (slotSnap.exists) throw new ApiError(409, 'nonce_slot_taken', 'a transaction with this sender and nonce is already pending');
      const account = accountSnap.exists ? accountSnap.data() : { balance: 0, nonce: 0 };
      if (nonce < account.nonce) throw new ApiError(409, 'stale_nonce', `account nonce is ${account.nonce}`);
      if (nonce >= account.nonce + MAX_NONCE_AHEAD) throw new ApiError(400, 'nonce_too_far', `nonce must be below ${account.nonce + MAX_NONCE_AHEAD}`);
      if (account.balance < amount + fee) throw new ApiError(400, 'insufficient_funds', `balance is ${account.balance}, need ${amount + fee}`);
      t.create(slotRef, { id, from, to: input.to, amount, fee, nonce, publicKey: input.publicKey, signature: input.signature, createdAt });
    }, TX_OPTIONS);

    return { id, from, status: 'pending' };
  }

  // Applies pending transactions and appends at most one block. Safe to call concurrently:
  // Firestore transactions serialise on the chain head, and the block document is created
  // with create(), so two producers can never write the same height.
  async produceBlock({ now = Date.now() } = {}) {
    const { chainId, maxTxPerBlock } = this.config;

    return this.db.runTransaction(async (t) => {
      const metaSnap = await t.get(this.meta);
      if (!metaSnap.exists) throw new Error('chain is not initialized');
      const meta = metaSnap.data();

      const pendingSnap = await t.get(this.mempool.orderBy('createdAt').limit(maxTxPerBlock));
      if (pendingSnap.empty) return null;
      const pending = pendingSnap.docs.map((d) => ({ ref: d.ref, ...d.data() }));

      // Defence in depth: signatures are verified again at block time.
      const valid = [];
      const rejected = [];
      for (const tx of pending) {
        let ok = false;
        try {
          const check = verifyTransactionSignature({
            chainId,
            publicKey: tx.publicKey,
            signature: tx.signature,
            to: tx.to,
            amount: String(tx.amount),
            fee: String(tx.fee),
            nonce: String(tx.nonce),
          });
          ok = check.ok && check.id === tx.id && check.from === tx.from;
        } catch {
          ok = false;
        }
        if (ok) valid.push(tx);
        else rejected.push({ tx, reason: 'bad-signature' });
      }

      const addresses = [...new Set([this.feeRecipient, ...valid.flatMap((tx) => [tx.from, tx.to])])];
      const snaps = await t.getAll(...addresses.map((a) => this.accounts.doc(a)));
      const accounts = {};
      snaps.forEach((snap, i) => {
        const d = snap.exists ? snap.data() : { balance: 0, nonce: 0 };
        accounts[addresses[i]] = { balance: d.balance, nonce: d.nonce, existed: snap.exists };
      });

      const result = applyTransactions({ accounts, txs: valid, feeRecipient: this.feeRecipient });
      rejected.push(...result.rejected);
      const { executed } = result;
      if (executed.length === 0 && rejected.length === 0) return null; // nothing changed

      // ---- all reads are done; writes below ----
      for (const { tx, reason } of rejected) {
        const { ref, ...rest } = tx;
        t.set(this.txs.doc(tx.id), { ...rest, status: 'rejected', reason, rejectedAt: now });
        t.delete(ref);
      }
      if (executed.length === 0) return null;

      const height = meta.height + 1;
      const timestamp = Math.max(now, meta.headTimestamp + 1);
      const txIds = executed.map((tx) => tx.id);
      const root = merkleRoot(txIds);
      const hash = blockHash({ chainId, height, prevHash: meta.headHash, timestamp, merkleRoot: root, txCount: txIds.length, producer: this.operatorAddress });
      const block = {
        height,
        hash,
        prevHash: meta.headHash,
        timestamp,
        merkleRoot: root,
        txIds,
        txCount: txIds.length,
        producer: this.operatorAddress,
        signature: signHash(hash, this.config.operatorPrivateKey),
      };
      t.create(this.blocks.doc(pad(height)), block);
      t.update(this.meta, { height, headHash: hash, headTimestamp: timestamp, txCount: meta.txCount + txIds.length });

      executed.forEach((tx, index) => {
        const { ref, ...rest } = tx;
        t.set(this.txs.doc(tx.id), { ...rest, status: 'confirmed', blockHeight: height, blockHash: hash, index, confirmedAt: timestamp });
        t.delete(ref);
      });
      for (const address of result.touched) {
        const a = accounts[address];
        t.set(
          this.accounts.doc(address),
          { address, balance: a.balance, nonce: a.nonce, updatedAt: timestamp, ...(a.existed ? {} : { createdAt: timestamp }) },
          { merge: true },
        );
      }
      return block;
    }, TX_OPTIONS);
  }

  // Recomputes every hash, link, merkle root and producer signature. `deep` also re-verifies
  // every confirmed transaction record. Cost: one read per block (and per tx when deep).
  async verifyChain({ deep = false } = {}) {
    const errors = [];
    const metaSnap = await this.meta.get();
    if (!metaSnap.exists) return { ok: false, height: -1, blocks: 0, errors: ['chain is not initialized'] };
    const meta = metaSnap.data();

    let prev = null;
    let expected = 0;
    let from = 0;
    let count = 0;
    for (;;) {
      const snap = await this.blocks.orderBy('height').startAt(from).limit(100).get();
      if (snap.empty) break;
      for (const doc of snap.docs) {
        const b = doc.data();
        count += 1;
        try {
          if (b.height !== expected) errors.push(`expected height ${expected} but found ${b.height}`);
          if (b.prevHash !== (prev ? prev.hash : ZERO_HASH)) errors.push(`block ${b.height}: prevHash does not link to the previous block`);
          if (!Array.isArray(b.txIds) || b.txCount !== b.txIds.length) errors.push(`block ${b.height}: txCount does not match txIds`);
          else if (merkleRoot(b.txIds) !== b.merkleRoot) errors.push(`block ${b.height}: merkle root mismatch`);
          const recomputed = blockHash({ chainId: meta.chainId, height: b.height, prevHash: b.prevHash, timestamp: b.timestamp, merkleRoot: b.merkleRoot, txCount: b.txCount, producer: b.producer });
          if (recomputed !== b.hash) errors.push(`block ${b.height}: hash mismatch`);
          if (b.producer !== meta.operatorAddress) errors.push(`block ${b.height}: unexpected producer`);
          if (!verifyHash(b.hash, b.signature, meta.operatorPublicKey)) errors.push(`block ${b.height}: invalid producer signature`);
          if (prev && b.timestamp < prev.timestamp) errors.push(`block ${b.height}: timestamp goes backwards`);
          if (deep && b.height > 0) await this.#verifyBlockTransactions(b, meta, errors);
        } catch (err) {
          errors.push(`block ${b.height}: malformed (${err.message})`);
        }
        prev = b;
        expected = b.height + 1;
      }
      from = prev.height + 1;
    }

    if (!prev) errors.push('no blocks found');
    else {
      if (prev.hash !== meta.headHash) errors.push('chain head does not match meta.headHash');
      if (prev.height !== meta.height) errors.push('chain height does not match meta.height');
    }
    return { ok: errors.length === 0, height: prev ? prev.height : -1, blocks: count, errors };
  }

  async #verifyBlockTransactions(b, meta, errors) {
    for (let i = 0; i < b.txIds.length; i += 100) {
      const ids = b.txIds.slice(i, i + 100);
      const snaps = await this.db.getAll(...ids.map((id) => this.txs.doc(id)));
      snaps.forEach((snap, k) => {
        const id = ids[k];
        if (!snap.exists) return errors.push(`block ${b.height}: transaction ${id} is missing`);
        const d = snap.data();
        if (d.status !== 'confirmed' || d.blockHeight !== b.height || d.blockHash !== b.hash || d.index !== i + k) {
          errors.push(`block ${b.height}: transaction ${id} has inconsistent block metadata`);
        }
        let ok = false;
        try {
          const check = verifyTransactionSignature({ chainId: meta.chainId, publicKey: d.publicKey, signature: d.signature, to: d.to, amount: String(d.amount), fee: String(d.fee), nonce: String(d.nonce) });
          ok = check.ok && check.id === id;
        } catch {
          ok = false;
        }
        if (!ok) errors.push(`block ${b.height}: transaction ${id} has an invalid signature`);
      });
    }
  }

  // Full scan of accounts: balances must be non-negative integers and sum to the genesis supply.
  async auditSupply() {
    const metaSnap = await this.meta.get();
    if (!metaSnap.exists) return { ok: false, total: 0, expected: 0, accounts: 0, negative: 0 };
    const expected = metaSnap.data().totalSupply;
    let total = 0;
    let accounts = 0;
    let negative = 0;
    let last = null;
    for (;;) {
      let q = this.accounts.orderBy(FieldPath.documentId()).limit(500);
      if (last) q = q.startAfter(last);
      const snap = await q.get();
      if (snap.empty) break;
      for (const d of snap.docs) {
        const balance = d.data().balance;
        if (!Number.isSafeInteger(balance) || balance < 0) negative += 1;
        total += balance;
        accounts += 1;
      }
      last = snap.docs[snap.docs.length - 1];
    }
    return { ok: total === expected && negative === 0, total, expected, accounts, negative };
  }
}
