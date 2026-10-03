import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, signTransaction } from '../src/crypto.js';
import { loadConfig } from '../src/config.js';
import { Ledger } from '../src/ledger.js';
import { closeAll, emulatorReady, makeLedger, silent } from './helpers.js';

const ready = emulatorReady();
const it = (name, fn) => test(name, { skip: ready ? false : 'FIRESTORE_EMULATOR_HOST not set' }, fn);
after(closeAll);

const k = () => generateKeyPair();
const send = (ctx, from, to, amount, fee, nonce) =>
  ctx.ledger.submitTransaction(signTransaction({ chainId: ctx.config.chainId, privateKey: from.privateKey, to: to.address, amount, fee, nonce }));
const code = (expected) => (err) => {
  assert.equal(err.code, expected, `expected error code ${expected}, got ${err.code}: ${err.message}`);
  return true;
};

it('creates the genesis block once, is idempotent and refuses a mismatched configuration', async () => {
  const alice = k();
  const ctx = await makeLedger({ allocations: { [alice.address]: 1_000_000 } });
  const info = await ctx.ledger.getChainInfo();
  assert.equal(info.height, 0);
  assert.equal(info.totalSupply, '1000000');
  assert.equal(info.consensus, 'single-operator-proof-of-authority');
  assert.equal((await ctx.ledger.getAccount(alice.address)).balance, '1000000');
  assert.equal((await ctx.ledger.getBlock(0)).hash, info.headHash);

  await ctx.ledger.init();
  assert.equal((await ctx.ledger.getChainInfo()).headHash, info.headHash);

  const otherChain = new Ledger({ db: ctx.db, config: loadConfig({ ...ctx.env, CHAIN_ID: 'other-chain' }), log: silent });
  await assert.rejects(otherChain.init(), /chain id mismatch/);
  const otherKey = new Ledger({ db: ctx.db, config: loadConfig({ ...ctx.env, OPERATOR_PRIVATE_KEY: k().privateKey }), log: silent });
  await assert.rejects(otherKey.init(), /operator key mismatch/);

  const verdict = await ctx.ledger.verifyChain({ deep: true });
  assert.deepEqual(verdict.errors, []);
  assert.equal(verdict.ok, true);
});

it('moves funds, pays the fee to the operator and confirms in a block', async () => {
  const alice = k();
  const bob = k();
  const ctx = await makeLedger({ allocations: { [alice.address]: 1_000_000 } });

  const sub = await send(ctx, alice, bob, 1000, 10, 0);
  assert.equal(sub.status, 'pending');
  assert.equal((await ctx.ledger.getTransaction(sub.id)).status, 'pending');
  assert.equal((await ctx.ledger.getAccount(alice.address)).balance, '1000000', 'nothing moves before a block');

  const block = await ctx.ledger.produceBlock();
  assert.equal(block.height, 1);
  assert.equal(block.txCount, 1);
  assert.deepEqual(block.txIds, [sub.id]);

  const a = await ctx.ledger.getAccount(alice.address);
  assert.equal(a.balance, String(1_000_000 - 1010));
  assert.equal(a.nonce, '1');
  assert.equal((await ctx.ledger.getAccount(bob.address)).balance, '1000');
  assert.equal((await ctx.ledger.getAccount(ctx.ledger.operatorAddress)).balance, '10');

  const tx = await ctx.ledger.getTransaction(sub.id);
  assert.equal(tx.status, 'confirmed');
  assert.equal(tx.blockHeight, 1);
  assert.equal(tx.blockHash, block.hash);
  assert.equal(await ctx.ledger.produceBlock(), null, 'no empty blocks');

  const verdict = await ctx.ledger.verifyChain({ deep: true });
  assert.deepEqual(verdict.errors, []);
  const audit = await ctx.ledger.auditSupply();
  assert.equal(audit.ok, true);
  assert.equal(audit.total, 1_000_000);
});

it('rejects invalid submissions with specific error codes', async () => {
  const alice = k();
  const bob = k();
  const carol = k();
  const ctx = await makeLedger({ allocations: { [alice.address]: 10_000 }, env: { MIN_FEE: '2' } });
  const sign = (over = {}) => signTransaction({ chainId: ctx.config.chainId, privateKey: alice.privateKey, to: bob.address, amount: 100, fee: 2, nonce: 0, ...over });

  await assert.rejects(ctx.ledger.submitTransaction({ ...sign(), amount: '101' }), code('bad_signature'));
  await assert.rejects(ctx.ledger.submitTransaction(sign({ chainId: 'other-chain' })), code('bad_signature'));
  await assert.rejects(ctx.ledger.submitTransaction({ ...sign(), publicKey: 'zz' }), code('bad_signature'));
  await assert.rejects(ctx.ledger.submitTransaction(sign({ fee: 1 })), code('fee_too_low'));
  await assert.rejects(ctx.ledger.submitTransaction(sign({ amount: 0 })), code('invalid_amount'));
  await assert.rejects(ctx.ledger.submitTransaction(sign({ amount: '9999999999999999' })), code('number_out_of_range'));
  await assert.rejects(ctx.ledger.submitTransaction(sign({ to: alice.address })), code('self_transfer'));
  await assert.rejects(ctx.ledger.submitTransaction(sign({ nonce: 16 })), code('nonce_too_far'));
  await assert.rejects(ctx.ledger.submitTransaction(sign({ amount: 20_000 })), code('insufficient_funds'));
  await assert.rejects(
    ctx.ledger.submitTransaction(signTransaction({ chainId: ctx.config.chainId, privateKey: carol.privateKey, to: bob.address, amount: 1, fee: 2, nonce: 0 })),
    code('insufficient_funds'),
  );
  assert.equal((await ctx.ledger.getChainInfo()).height, 0);
});

it('blocks duplicates, nonce-slot reuse and replays', async () => {
  const alice = k();
  const bob = k();
  const ctx = await makeLedger({ allocations: { [alice.address]: 10_000 } });
  const signed = signTransaction({ chainId: ctx.config.chainId, privateKey: alice.privateKey, to: bob.address, amount: 100, fee: 0, nonce: 0 });

  await ctx.ledger.submitTransaction(signed);
  await assert.rejects(ctx.ledger.submitTransaction(signed), code('nonce_slot_taken'));
  const different = signTransaction({ chainId: ctx.config.chainId, privateKey: alice.privateKey, to: bob.address, amount: 200, fee: 0, nonce: 0 });
  await assert.rejects(ctx.ledger.submitTransaction(different), code('nonce_slot_taken'));

  await ctx.ledger.produceBlock();
  await assert.rejects(ctx.ledger.submitTransaction(signed), code('duplicate_transaction'));
  await assert.rejects(ctx.ledger.submitTransaction(different), code('stale_nonce'));
  assert.equal((await ctx.ledger.getAccount(bob.address)).balance, '100', 'the replay must not pay twice');
});

it('executes out-of-order nonces from one sender in nonce order within a single block', async () => {
  const alice = k();
  const bob = k();
  const ctx = await makeLedger({ allocations: { [alice.address]: 10_000 } });
  const t2 = await send(ctx, alice, bob, 30, 0, 2);
  const t1 = await send(ctx, alice, bob, 20, 0, 1);
  const t0 = await send(ctx, alice, bob, 10, 0, 0);
  const block = await ctx.ledger.produceBlock();
  assert.equal(block.txCount, 3);
  assert.deepEqual(block.txIds, [t0.id, t1.id, t2.id]);
  assert.equal((await ctx.ledger.getAccount(bob.address)).balance, '60');
  assert.equal((await ctx.ledger.getAccount(alice.address)).nonce, '3');
});

it('rejects at block time what no longer fits, and frees the nonce slot', async () => {
  const alice = k();
  const bob = k();
  const ctx = await makeLedger({ allocations: { [alice.address]: 100 } });
  await send(ctx, alice, bob, 80, 0, 0);
  const second = await send(ctx, alice, bob, 80, 0, 1); // each passes admission on its own

  const block = await ctx.ledger.produceBlock();
  assert.equal(block.txCount, 1);
  const rejected = await ctx.ledger.getTransaction(second.id);
  assert.equal(rejected.status, 'rejected');
  assert.equal(rejected.reason, 'insufficient-funds');
  const a = await ctx.ledger.getAccount(alice.address);
  assert.equal(a.balance, '20');
  assert.equal(a.nonce, '1');

  const retry = await send(ctx, alice, bob, 20, 0, 1);
  await ctx.ledger.produceBlock();
  assert.equal((await ctx.ledger.getTransaction(retry.id)).status, 'confirmed');
  assert.equal((await ctx.ledger.getAccount(alice.address)).balance, '0');
});

it('records rejections even when no block is produced', async () => {
  const alice = k();
  const bob = k();
  const ctx = await makeLedger({ allocations: { [alice.address]: 100 }, env: { MAX_TX_PER_BLOCK: '1' } });
  await send(ctx, alice, bob, 100, 0, 0);
  const doomed = await send(ctx, alice, bob, 50, 0, 1);

  assert.equal((await ctx.ledger.produceBlock()).height, 1);
  assert.equal(await ctx.ledger.produceBlock(), null, 'rejected-only batches do not create a block');
  const tx = await ctx.ledger.getTransaction(doomed.id);
  assert.equal(tx.status, 'rejected');
  assert.equal((await ctx.ledger.getChainInfo()).height, 1);
  assert.equal(await ctx.ledger.produceBlock(), null);
});

it('sends fees to a configured fee recipient', async () => {
  const alice = k();
  const bob = k();
  const treasury = k();
  const ctx = await makeLedger({ allocations: { [alice.address]: 1000 }, env: { FEE_RECIPIENT: treasury.address } });
  await send(ctx, alice, bob, 100, 7, 0);
  await ctx.ledger.produceBlock();
  assert.equal((await ctx.ledger.getAccount(treasury.address)).balance, '7');
  assert.equal((await ctx.ledger.getAccount(ctx.ledger.operatorAddress)).balance, '0');
  assert.equal((await ctx.ledger.auditSupply()).ok, true);
});

it('never double-applies a transaction under concurrent block producers', async () => {
  const senders = Array.from({ length: 4 }, k);
  const recipients = Array.from({ length: 4 }, k);
  const allocations = Object.fromEntries(senders.map((s) => [s.address, 100_000]));
  const ctx = await makeLedger({ allocations, env: { MAX_TX_PER_BLOCK: '8' } });

  const ids = [];
  for (let nonce = 0; nonce < 5; nonce += 1) {
    for (let i = 0; i < 4; i += 1) ids.push((await send(ctx, senders[i], recipients[i], 10, 1, nonce)).id);
  }
  assert.equal(ids.length, 20);

  const settled = await Promise.allSettled([1, 2, 3, 4].map(() => ctx.ledger.produceBlock()));
  assert.ok(settled.some((r) => r.status === 'fulfilled'), 'at least one producer must succeed');
  let guard = 0;
  while (await ctx.ledger.produceBlock()) {
    guard += 1;
    assert.ok(guard < 10, 'mempool did not drain');
  }

  const info = await ctx.ledger.getChainInfo();
  assert.equal(info.txCount, 20);
  const blocks = await ctx.ledger.listBlocks(1, 100);
  assert.equal(blocks.reduce((sum, b) => sum + b.txCount, 0), 20);
  assert.deepEqual(blocks.map((b) => b.height), blocks.map((_, i) => i + 1), 'heights are consecutive, no forks');

  const seen = new Set();
  for (const id of ids) {
    const tx = await ctx.ledger.getTransaction(id);
    assert.equal(tx.status, 'confirmed');
    seen.add(`${tx.blockHeight}:${tx.index}`);
  }
  assert.equal(seen.size, 20, 'every transaction has its own slot in exactly one block');

  for (const r of recipients) assert.equal((await ctx.ledger.getAccount(r.address)).balance, '50');
  assert.equal((await ctx.ledger.getAccount(ctx.ledger.operatorAddress)).balance, '20');
  const verdict = await ctx.ledger.verifyChain({ deep: true });
  assert.deepEqual(verdict.errors, []);
  const audit = await ctx.ledger.auditSupply();
  assert.equal(audit.ok, true);
  assert.equal(audit.total, 400_000);
});

it('detects tampering with a stored block', async () => {
  const alice = k();
  const bob = k();
  const ctx = await makeLedger({ allocations: { [alice.address]: 1000 } });
  await send(ctx, alice, bob, 10, 0, 0);
  await ctx.ledger.produceBlock();
  assert.equal((await ctx.ledger.verifyChain()).ok, true);

  await ctx.db.collection(`${ctx.config.collectionPrefix}blocks`).doc('000000000001').update({ timestamp: 1 });
  const verdict = await ctx.ledger.verifyChain();
  assert.equal(verdict.ok, false);
  assert.ok(verdict.errors.some((e) => /hash mismatch/.test(e)), `expected a hash mismatch, got ${JSON.stringify(verdict.errors)}`);
});

it('detects a forged balance in the supply audit', async () => {
  const alice = k();
  const ctx = await makeLedger({ allocations: { [alice.address]: 1000 } });
  assert.equal((await ctx.ledger.auditSupply()).ok, true);
  await ctx.db.collection(`${ctx.config.collectionPrefix}accounts`).doc(alice.address).update({ balance: 5000 });
  const audit = await ctx.ledger.auditSupply();
  assert.equal(audit.ok, false);
  assert.equal(audit.total, 5000);
  assert.equal(audit.expected, 1000);
});
