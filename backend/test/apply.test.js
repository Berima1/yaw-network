import test from 'node:test';
import assert from 'node:assert/strict';
import { applyTransactions } from '../src/apply.js';

const FEE = 'FEE';
let seq = 0;
const mk = (from, to, amount, fee, nonce, createdAt) => {
  seq += 1;
  return { id: `tx${String(seq).padStart(5, '0')}`, from, to, amount, fee, nonce, createdAt: createdAt ?? seq };
};
function world(balances) {
  const acc = { [FEE]: { balance: 0, nonce: 0, existed: false } };
  for (const [name, balance] of Object.entries(balances)) acc[name] = { balance, nonce: 0, existed: true };
  return acc;
}
const total = (acc) => Object.values(acc).reduce((sum, a) => sum + a.balance, 0);

test('executes sequential nonces and pays the fee to the fee recipient', () => {
  const acc = world({ A: 1000, B: 0 });
  const r = applyTransactions({ accounts: acc, txs: [mk('A', 'B', 100, 5, 0), mk('A', 'B', 50, 5, 1)], feeRecipient: FEE });
  assert.equal(r.executed.length, 2);
  assert.equal(r.rejected.length, 0);
  assert.equal(acc.A.balance, 840);
  assert.equal(acc.B.balance, 150);
  assert.equal(acc.FEE.balance, 10);
  assert.equal(acc.A.nonce, 2);
  assert.equal(total(acc), 1000);
  assert.deepEqual([...r.touched].sort(), ['A', 'B', 'FEE']);
});

test('a later nonce created first still executes after its predecessor', () => {
  const acc = world({ A: 1000, B: 0 });
  const second = mk('A', 'B', 10, 0, 1, 1);
  const first = mk('A', 'B', 10, 0, 0, 2);
  const r = applyTransactions({ accounts: acc, txs: [second, first], feeRecipient: FEE });
  assert.deepEqual(r.executed.map((t) => t.nonce), [0, 1]);
  assert.equal(r.skipped.length, 0);
});

test('a nonce gap is skipped, not rejected, and changes nothing', () => {
  const acc = world({ A: 1000, B: 0 });
  const r = applyTransactions({ accounts: acc, txs: [mk('A', 'B', 10, 0, 1)], feeRecipient: FEE });
  assert.equal(r.executed.length, 0);
  assert.equal(r.rejected.length, 0);
  assert.equal(r.skipped.length, 1);
  assert.equal(acc.A.balance, 1000);
  assert.equal(acc.A.nonce, 0);
});

test('insufficient funds are rejected without consuming the nonce or charging a fee', () => {
  const acc = world({ A: 100, B: 0 });
  const r = applyTransactions({
    accounts: acc,
    txs: [mk('A', 'B', 80, 0, 0), mk('A', 'B', 80, 5, 1), mk('A', 'B', 5, 0, 2)],
    feeRecipient: FEE,
  });
  assert.equal(r.executed.length, 1);
  assert.equal(r.rejected.length, 1);
  assert.equal(r.rejected[0].reason, 'insufficient-funds');
  assert.equal(r.skipped.length, 1, 'nonce 2 waits because nonce 1 was never consumed');
  assert.equal(acc.A.balance, 20);
  assert.equal(acc.A.nonce, 1);
  assert.equal(acc.FEE.balance, 0);
});

test('a stale nonce (replay) is rejected', () => {
  const acc = world({ A: 100, B: 0 });
  acc.A.nonce = 3;
  const r = applyTransactions({ accounts: acc, txs: [mk('A', 'B', 10, 0, 1)], feeRecipient: FEE });
  assert.equal(r.rejected[0].reason, 'stale-nonce');
  assert.equal(acc.A.balance, 100);
});

test('recipient can also be the fee recipient', () => {
  const acc = world({ A: 100 });
  const r = applyTransactions({ accounts: acc, txs: [mk('A', FEE, 10, 2, 0)], feeRecipient: FEE });
  assert.equal(r.executed.length, 1);
  assert.equal(acc.A.balance, 88);
  assert.equal(acc.FEE.balance, 12);
  assert.equal(total(acc), 100);
});

test('sender can also be the fee recipient', () => {
  const acc = world({ B: 0 });
  acc.FEE.balance = 50;
  const r = applyTransactions({ accounts: acc, txs: [mk(FEE, 'B', 10, 3, 0)], feeRecipient: FEE });
  assert.equal(r.executed.length, 1);
  assert.equal(acc.FEE.balance, 40);
  assert.equal(acc.B.balance, 10);
  assert.equal(total(acc), 50);
});

function mulberry32(seed) {
  let a = seed;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

test('property: supply is conserved, balances never go negative, nonces advance one by one', () => {
  for (const seed of [1, 2, 3, 42, 2024]) {
    const rand = mulberry32(seed);
    const names = 'ABCDEFGHIJ'.split('');
    const acc = world(Object.fromEntries(names.map((n) => [n, 1000])));
    const txs = [];
    for (let i = 0; i < 300; i += 1) {
      const from = names[Math.floor(rand() * names.length)];
      let to = names[Math.floor(rand() * names.length)];
      if (to === from) to = names[(names.indexOf(from) + 1) % names.length];
      txs.push(mk(from, to, 1 + Math.floor(rand() * 400), Math.floor(rand() * 6), Math.floor(rand() * 7), i));
    }
    const r = applyTransactions({ accounts: acc, txs, feeRecipient: FEE });

    assert.equal(total(acc), 10000, `seed ${seed}: supply must be conserved`);
    for (const [name, a] of Object.entries(acc)) assert.ok(a.balance >= 0, `seed ${seed}: ${name} went negative`);

    const perSender = {};
    for (const t of r.executed) (perSender[t.from] ??= []).push(t.nonce);
    for (const [name, nonces] of Object.entries(perSender)) {
      assert.deepEqual(nonces, nonces.map((_, i) => i), `seed ${seed}: ${name} nonces must be 0,1,2,...`);
      assert.equal(acc[name].nonce, nonces.length);
    }

    const all = [...r.executed, ...r.rejected.map((x) => x.tx), ...r.skipped].map((t) => t.id);
    assert.equal(all.length, 300, `seed ${seed}: every tx must be accounted for exactly once`);
    assert.equal(new Set(all).size, 300);
  }
});
