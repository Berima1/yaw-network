import http from 'node:http';
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.js';
import { generateKeyPair, signTransaction } from '../src/crypto.js';
import { closeAll, emulatorReady, makeLedger, silent } from './helpers.js';

const ready = emulatorReady();
const it = (name, fn) => test(name, { skip: ready ? false : 'FIRESTORE_EMULATOR_HOST not set' }, fn);

const servers = [];
after(async () => {
  await Promise.all(
    servers.map(
      (s) =>
        new Promise((resolve) => {
          s.closeAllConnections?.();
          s.close(resolve);
        }),
    ),
  );
  await closeAll();
});

async function startApp(options) {
  const ctx = await makeLedger(options);
  const app = createApp({ ledger: ctx.ledger, config: ctx.config, log: silent });
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  servers.push(server);
  return { ...ctx, base: `http://127.0.0.1:${server.address().port}` };
}

const post = (base, path, body, headers = {}) =>
  fetch(base + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });

function rawGet(base, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.get(base + path, { headers }, (res) => {
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers }));
    });
    req.on('error', reject);
  });
}

const k = () => generateKeyPair();

it('serves health, readiness, chain info and security headers', async () => {
  const app = await startApp({});
  const health = await fetch(`${app.base}/health`);
  assert.equal(health.status, 200);
  assert.equal(health.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(health.headers.get('x-powered-by'), null);
  assert.equal((await fetch(`${app.base}/ready`)).status, 200);
  const chain = await (await fetch(`${app.base}/v1/chain`)).json();
  assert.equal(chain.chainId, app.config.chainId);
  assert.equal(chain.height, 0);
  assert.equal(chain.consensus, 'single-operator-proof-of-authority');
});

it('full flow: signed transaction is confirmed instantly and queryable', async () => {
  const alice = k();
  const bob = k();
  const app = await startApp({ allocations: { [alice.address]: 500_000 }, env: { INSTANT_BLOCKS: 'true' } });
  const body = signTransaction({ chainId: app.config.chainId, privateKey: alice.privateKey, to: bob.address, amount: 1000, fee: 0, nonce: 0 });

  const res = await post(app.base, '/v1/transactions', body);
  assert.equal(res.status, 201);
  const tx = await res.json();
  assert.equal(tx.status, 'confirmed');
  assert.equal(tx.blockHeight, 1);
  assert.equal(tx.amount, '1000');

  assert.equal((await (await fetch(`${app.base}/v1/accounts/${bob.address}`)).json()).balance, '1000');
  assert.equal((await (await fetch(`${app.base}/v1/accounts/${alice.address}`)).json()).nonce, '1');
  const list = await (await fetch(`${app.base}/v1/blocks?limit=5`)).json();
  assert.equal(list.blocks.length, 2);
  assert.equal(list.blocks[1].txIds[0], tx.id);
  const block = await (await fetch(`${app.base}/v1/blocks/1`)).json();
  assert.equal(block.hash, tx.blockHash);
  assert.equal((await (await fetch(`${app.base}/v1/transactions/${tx.id}`)).json()).status, 'confirmed');

  const dup = await post(app.base, '/v1/transactions', body);
  assert.equal(dup.status, 409);
  assert.equal((await dup.json()).error.code, 'duplicate_transaction');
});

it('without instant blocks a transaction stays pending (202) until a block is produced', async () => {
  const alice = k();
  const bob = k();
  const app = await startApp({ allocations: { [alice.address]: 10_000 } });
  const body = signTransaction({ chainId: app.config.chainId, privateKey: alice.privateKey, to: bob.address, amount: 5, fee: 0, nonce: 0 });
  const res = await post(app.base, '/v1/transactions', body);
  assert.equal(res.status, 202);
  assert.equal((await res.json()).status, 'pending');
  assert.equal((await (await fetch(`${app.base}/v1/accounts/${bob.address}`)).json()).balance, '0');
});

it('rejects malformed input with clear errors and never a 500', async () => {
  const alice = k();
  const bob = k();
  const app = await startApp({ allocations: { [alice.address]: 10_000 } });
  const good = signTransaction({ chainId: app.config.chainId, privateKey: alice.privateKey, to: bob.address, amount: 5, fee: 0, nonce: 0 });

  const invalidJson = await post(app.base, '/v1/transactions', '{nope');
  assert.equal(invalidJson.status, 400);
  assert.equal((await invalidJson.json()).error.code, 'invalid_json');

  const empty = await post(app.base, '/v1/transactions', {});
  assert.equal(empty.status, 400);
  assert.equal((await empty.json()).error.code, 'invalid_request');

  assert.equal((await post(app.base, '/v1/transactions', { ...good, extra: 1 })).status, 400);
  assert.equal((await post(app.base, '/v1/transactions', { ...good, signature: good.signature.toUpperCase() })).status, 400);
  assert.equal((await post(app.base, '/v1/transactions', { ...good, amount: 5 })).status, 400, 'amounts must be strings');
  assert.equal((await post(app.base, '/v1/transactions', { ...good, amount: '05' })).status, 400, 'no leading zeros');

  const tampered = await post(app.base, '/v1/transactions', { ...good, amount: '6' });
  assert.equal(tampered.status, 400);
  assert.equal((await tampered.json()).error.code, 'bad_signature');

  const huge = await post(app.base, '/v1/transactions', JSON.stringify({ junk: 'x'.repeat(20_000) }));
  assert.equal(huge.status, 413);

  const badAddress = await fetch(`${app.base}/v1/accounts/notanaddress`);
  assert.equal(badAddress.status, 400);
  assert.equal((await badAddress.json()).error.code, 'invalid_address');
  assert.equal((await fetch(`${app.base}/v1/blocks/abc`)).status, 400);
  assert.equal((await fetch(`${app.base}/v1/blocks/999`)).status, 404);
  assert.equal((await fetch(`${app.base}/v1/blocks?limit=1000`)).status, 400);
  assert.equal((await fetch(`${app.base}/v1/transactions/${'0'.repeat(64)}`)).status, 404);
  assert.equal((await fetch(`${app.base}/v1/transactions/xyz`)).status, 400);

  const missing = await fetch(`${app.base}/nope`);
  assert.equal(missing.status, 404);
  assert.equal((await missing.json()).error.code, 'not_found');
});

it('operator endpoints require the producer token', async () => {
  const alice = k();
  const bob = k();
  const app = await startApp({ allocations: { [alice.address]: 10_000 } });
  const auth = { authorization: `Bearer ${'p'.repeat(40)}` };

  assert.equal((await fetch(`${app.base}/internal/audit`)).status, 401);
  assert.equal((await fetch(`${app.base}/internal/audit`, { headers: { authorization: 'Bearer wrong' } })).status, 401);
  assert.equal((await post(app.base, '/internal/produce-block', {})).status, 401);

  const empty = await (await post(app.base, '/internal/produce-block', {}, auth)).json();
  assert.equal(empty.produced, false);

  await post(app.base, '/v1/transactions', signTransaction({ chainId: app.config.chainId, privateKey: alice.privateKey, to: bob.address, amount: 5, fee: 0, nonce: 0 }));
  const produced = await (await post(app.base, '/internal/produce-block', {}, auth)).json();
  assert.equal(produced.produced, true);
  assert.equal(produced.block.height, 1);

  const audit = await (await fetch(`${app.base}/internal/audit`, { headers: auth })).json();
  assert.equal(audit.ok, true);
  assert.equal(audit.supply.total, 10_000);
  assert.deepEqual(audit.chain.errors, []);
});

it('operator endpoints are disabled (fail closed) when no token is configured', async () => {
  const app = await startApp({ env: { INSTANT_BLOCKS: 'true', PRODUCER_TOKEN: undefined } });
  const res = await fetch(`${app.base}/internal/audit`, { headers: { authorization: `Bearer ${'p'.repeat(40)}` } });
  assert.equal(res.status, 503);
  assert.equal((await post(app.base, '/internal/produce-block', {}, { authorization: 'Bearer anything' })).status, 503);
});

it('CORS is off by default and limited to configured origins', async () => {
  const closed = await startApp({});
  const noCors = await rawGet(closed.base, '/health', { origin: 'https://evil.example' });
  assert.equal(noCors.headers['access-control-allow-origin'], undefined);

  const open = await startApp({ env: { CORS_ORIGINS: 'https://app.example' } });
  const allowed = await rawGet(open.base, '/health', { origin: 'https://app.example' });
  assert.equal(allowed.headers['access-control-allow-origin'], 'https://app.example');
  const denied = await rawGet(open.base, '/health', { origin: 'https://evil.example' });
  assert.equal(denied.headers['access-control-allow-origin'], undefined);
});

it('rate limits transaction submissions', async () => {
  const app = await startApp({ env: { TX_RATE_LIMIT_PER_MINUTE: '2' } });
  const statuses = [];
  for (let i = 0; i < 3; i += 1) statuses.push((await post(app.base, '/v1/transactions', {})).status);
  assert.deepEqual(statuses, [400, 400, 429]);
});
