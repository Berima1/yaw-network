// Cryptography for the YAW ledger. All primitives come from the audited @noble libraries.
// Signature scheme: ECDSA over secp256k1, compact 64-byte signatures, low-S enforced (no malleability).
// Address: "yaw" + last 20 bytes of sha256(compressed public key), lowercase hex.
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';

export const ADDRESS_RE = /^yaw[0-9a-f]{40}$/;
export const HEX64_RE = /^[0-9a-f]{64}$/;

export function sha256Hex(input) {
  return bytesToHex(sha256(typeof input === 'string' ? utf8ToBytes(input) : input));
}

export function publicKeyFromPrivate(privateKeyHex) {
  return bytesToHex(secp256k1.getPublicKey(privateKeyHex, true));
}

export function addressFromPublicKey(publicKeyHex) {
  return 'yaw' + bytesToHex(sha256(hexToBytes(publicKeyHex)).slice(-20));
}

export function generateKeyPair() {
  const privateKey = bytesToHex(secp256k1.utils.randomPrivateKey());
  const publicKey = publicKeyFromPrivate(privateKey);
  return { privateKey, publicKey, address: addressFromPublicKey(publicKey) };
}

export function signHash(hashHex, privateKeyHex) {
  return secp256k1.sign(hashHex, privateKeyHex).toCompactHex();
}

export function verifyHash(hashHex, signatureHex, publicKeyHex) {
  try {
    return secp256k1.verify(signatureHex, hashHex, publicKeyHex) === true;
  } catch {
    return false;
  }
}

// ---- Transactions -------------------------------------------------------------------------
// The chain id is part of the signed payload, so a signature is only valid on one chain.
export function txPayload({ chainId, from, to, amount, fee, nonce }) {
  return `yaw-tx-v1\n${chainId}\n${from}\n${to}\n${amount}\n${fee}\n${nonce}`;
}

// The transaction id is the hash that gets signed.
export function txIdFor(fields) {
  return sha256Hex(txPayload(fields));
}

// Client-side helper (used by tests and documentation). A real wallet does this on the user's device.
export function signTransaction({ chainId, privateKey, to, amount, fee, nonce }) {
  const publicKey = publicKeyFromPrivate(privateKey);
  const from = addressFromPublicKey(publicKey);
  const fields = { chainId, from, to, amount: String(amount), fee: String(fee), nonce: String(nonce) };
  return {
    publicKey,
    to,
    amount: fields.amount,
    fee: fields.fee,
    nonce: fields.nonce,
    signature: signHash(txIdFor(fields), privateKey),
  };
}

// Returns { ok, id, from }. Throws on malformed hex; callers treat a throw as "invalid".
export function verifyTransactionSignature({ chainId, publicKey, signature, to, amount, fee, nonce }) {
  const from = addressFromPublicKey(publicKey);
  const id = txIdFor({ chainId, from, to, amount, fee, nonce });
  return { ok: verifyHash(id, signature, publicKey), id, from };
}

// ---- Blocks -------------------------------------------------------------------------------
export function merkleRoot(txIds) {
  if (txIds.length === 0) return sha256Hex('');
  let level = txIds.map((id) => hexToBytes(id));
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = level[i + 1] ?? level[i];
      const buf = new Uint8Array(64);
      buf.set(left, 0);
      buf.set(right, 32);
      next.push(sha256(buf));
    }
    level = next;
  }
  return bytesToHex(level[0]);
}

// txCount is committed in the hash so the odd-leaf duplication in merkleRoot cannot be abused.
export function blockHash({ chainId, height, prevHash, timestamp, merkleRoot: root, txCount, producer }) {
  return sha256Hex(`yaw-block-v1\n${chainId}\n${height}\n${prevHash}\n${timestamp}\n${root}\n${txCount}\n${producer}`);
}
