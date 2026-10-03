import test from 'node:test';
import assert from 'node:assert/strict';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  ADDRESS_RE,
  addressFromPublicKey,
  blockHash,
  generateKeyPair,
  merkleRoot,
  sha256Hex,
  signHash,
  signTransaction,
  txIdFor,
  verifyHash,
  verifyTransactionSignature,
} from '../src/crypto.js';

const CHAIN = 'yaw-testnet-1';

test('addresses are well formed, deterministic and unique', () => {
  const kp = generateKeyPair();
  assert.match(kp.address, ADDRESS_RE);
  assert.equal(kp.publicKey.length, 66);
  assert.equal(addressFromPublicKey(kp.publicKey), kp.address);
  assert.notEqual(generateKeyPair().address, kp.address);
});

test('a signed transaction verifies and reports the sender', () => {
  const alice = generateKeyPair();
  const bob = generateKeyPair();
  const tx = signTransaction({ chainId: CHAIN, privateKey: alice.privateKey, to: bob.address, amount: 5, fee: 1, nonce: 0 });
  const check = verifyTransactionSignature({ chainId: CHAIN, ...tx });
  assert.equal(check.ok, true);
  assert.equal(check.from, alice.address);
  assert.equal(check.id, txIdFor({ chainId: CHAIN, from: alice.address, to: bob.address, amount: '5', fee: '1', nonce: '0' }));
});

test('any change to the transaction invalidates the signature', () => {
  const alice = generateKeyPair();
  const bob = generateKeyPair();
  const mallory = generateKeyPair();
  const tx = signTransaction({ chainId: CHAIN, privateKey: alice.privateKey, to: bob.address, amount: 5, fee: 1, nonce: 0 });
  assert.equal(verifyTransactionSignature({ chainId: CHAIN, ...tx, amount: '6' }).ok, false);
  assert.equal(verifyTransactionSignature({ chainId: CHAIN, ...tx, fee: '0' }).ok, false);
  assert.equal(verifyTransactionSignature({ chainId: CHAIN, ...tx, nonce: '1' }).ok, false);
  assert.equal(verifyTransactionSignature({ chainId: CHAIN, ...tx, to: mallory.address }).ok, false);
  assert.equal(verifyTransactionSignature({ chainId: CHAIN, ...tx, publicKey: mallory.publicKey }).ok, false);
});

test('a signature is only valid on the chain it was made for (no cross-chain replay)', () => {
  const alice = generateKeyPair();
  const bob = generateKeyPair();
  const tx = signTransaction({ chainId: 'other-chain', privateKey: alice.privateKey, to: bob.address, amount: 5, fee: 1, nonce: 0 });
  assert.equal(verifyTransactionSignature({ chainId: CHAIN, ...tx }).ok, false);
  assert.equal(verifyTransactionSignature({ chainId: 'other-chain', ...tx }).ok, true);
});

test('high-S (malleable) signatures are rejected', () => {
  const kp = generateKeyPair();
  const hash = sha256Hex('hello');
  const sig = signHash(hash, kp.privateKey);
  const parsed = secp256k1.Signature.fromCompact(sig);
  const highS = new secp256k1.Signature(parsed.r, secp256k1.CURVE.n - parsed.s).toCompactHex();
  assert.equal(verifyHash(hash, sig, kp.publicKey), true);
  assert.equal(verifyHash(hash, highS, kp.publicKey), false);
});

test('garbage keys and signatures never verify', () => {
  const kp = generateKeyPair();
  const hash = sha256Hex('x');
  assert.equal(verifyHash(hash, 'zz', kp.publicKey), false);
  assert.equal(verifyHash(hash, signHash(hash, kp.privateKey), '05' + 'ab'.repeat(32)), false);
  assert.throws(() => verifyTransactionSignature({ chainId: CHAIN, publicKey: 'zz', signature: 'aa', to: kp.address, amount: '1', fee: '0', nonce: '0' }));
});

test('merkle root: empty, single, order-sensitive', () => {
  const a = sha256Hex('a');
  const b = sha256Hex('b');
  const c = sha256Hex('c');
  assert.equal(merkleRoot([]), sha256Hex(''));
  assert.equal(merkleRoot([a]), a);
  assert.notEqual(merkleRoot([a, b]), merkleRoot([b, a]));
  assert.notEqual(merkleRoot([a, b, c]), merkleRoot([a, b]));
  assert.equal(merkleRoot([a, b, c]).length, 64);
});

test('block hash commits to every field, including txCount', () => {
  const base = { chainId: CHAIN, height: 1, prevHash: '0'.repeat(64), timestamp: 1000, merkleRoot: sha256Hex('r'), txCount: 2, producer: 'yaw' + '1'.repeat(40) };
  const h = blockHash(base);
  for (const [key, value] of Object.entries({ chainId: 'x-chain', height: 2, prevHash: '1'.repeat(64), timestamp: 1001, merkleRoot: sha256Hex('s'), txCount: 3, producer: 'yaw' + '2'.repeat(40) })) {
    assert.notEqual(blockHash({ ...base, [key]: value }), h, `${key} must change the hash`);
  }
});
