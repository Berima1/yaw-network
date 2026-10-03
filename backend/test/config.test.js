import test from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.js';
import { generateKeyPair } from '../src/crypto.js';

const key = generateKeyPair().privateKey;
const base = { OPERATOR_PRIVATE_KEY: key };
const addr = (i) => 'yaw' + i.toString(16).padStart(40, '0');

test('loads sane defaults', () => {
  const c = loadConfig(base);
  assert.equal(c.port, 8080);
  assert.equal(c.chainId, 'yaw-testnet-1');
  assert.equal(c.instantBlocks, true);
  assert.equal(c.maxTxPerBlock, 50);
  assert.equal(c.minFee, 0);
  assert.equal(c.producerToken, undefined);
  assert.deepEqual(c.corsOrigins, []);
  assert.deepEqual(c.genesisAllocations, {});
});

test('the operator key is required and must be 32-byte lowercase hex', () => {
  assert.throws(() => loadConfig({}), /OPERATOR_PRIVATE_KEY/);
  assert.throws(() => loadConfig({ OPERATOR_PRIVATE_KEY: 'abc' }), /OPERATOR_PRIVATE_KEY/);
  assert.throws(() => loadConfig({ OPERATOR_PRIVATE_KEY: key.toUpperCase() }), /OPERATOR_PRIVATE_KEY/);
});

test('there must be a way to produce blocks', () => {
  assert.throws(() => loadConfig({ ...base, INSTANT_BLOCKS: 'false' }), /no block production path/);
  assert.doesNotThrow(() => loadConfig({ ...base, INSTANT_BLOCKS: 'false', PRODUCER_TOKEN: 'p'.repeat(32) }));
  assert.throws(() => loadConfig({ ...base, PRODUCER_TOKEN: 'short' }), /PRODUCER_TOKEN/);
});

test('limits are enforced', () => {
  assert.throws(() => loadConfig({ ...base, MAX_TX_PER_BLOCK: '81' }), /MAX_TX_PER_BLOCK/);
  assert.throws(() => loadConfig({ ...base, MAX_TX_PER_BLOCK: '0' }), /MAX_TX_PER_BLOCK/);
  assert.throws(() => loadConfig({ ...base, CHAIN_ID: 'Bad Chain' }), /CHAIN_ID/);
  assert.throws(() => loadConfig({ ...base, INSTANT_BLOCKS: 'yes' }), /INSTANT_BLOCKS/);
});

test('genesis allocations are validated', () => {
  assert.throws(() => loadConfig({ ...base, GENESIS_ALLOCATIONS: '{nope' }), /valid JSON/);
  assert.throws(() => loadConfig({ ...base, GENESIS_ALLOCATIONS: '[]' }), /JSON object/);
  assert.throws(() => loadConfig({ ...base, GENESIS_ALLOCATIONS: JSON.stringify({ bob: 5 }) }), /bad genesis address/);
  assert.throws(() => loadConfig({ ...base, GENESIS_ALLOCATIONS: JSON.stringify({ [addr(1)]: 1.5 }) }), /positive safe integer/);
  assert.throws(() => loadConfig({ ...base, GENESIS_ALLOCATIONS: JSON.stringify({ [addr(1)]: 0 }) }), /positive safe integer/);
  assert.throws(
    () => loadConfig({ ...base, GENESIS_ALLOCATIONS: JSON.stringify({ [addr(1)]: 2 ** 52, [addr(2)]: 2 ** 52 }) }),
    /safe integer range/,
  );
  const tooMany = Object.fromEntries(Array.from({ length: 401 }, (_, i) => [addr(i + 1), 1]));
  assert.throws(() => loadConfig({ ...base, GENESIS_ALLOCATIONS: JSON.stringify(tooMany) }), /more than 400/);
  const ok = loadConfig({ ...base, GENESIS_ALLOCATIONS: JSON.stringify({ [addr(1)]: 1000 }) });
  assert.equal(ok.genesisAllocations[addr(1)], 1000);
});

test('cors origins are parsed', () => {
  const c = loadConfig({ ...base, CORS_ORIGINS: 'https://a.example, https://b.example ,' });
  assert.deepEqual(c.corsOrigins, ['https://a.example', 'https://b.example']);
});
