import { randomBytes } from 'node:crypto';
import { Firestore } from '@google-cloud/firestore';
import pino from 'pino';
import { loadConfig } from '../src/config.js';
import { Ledger } from '../src/ledger.js';
import { generateKeyPair } from '../src/crypto.js';

export const silent = pino({ level: 'silent' });

// In CI the emulator is mandatory: a missing emulator must fail loudly, never skip silently.
export function emulatorReady() {
  if (process.env.FIRESTORE_EMULATOR_HOST) return true;
  if (process.env.REQUIRE_EMULATOR === 'true') {
    throw new Error('REQUIRE_EMULATOR=true but FIRESTORE_EMULATOR_HOST is not set');
  }
  return false;
}

const opened = [];
export async function closeAll() {
  await Promise.allSettled(opened.splice(0).map((db) => db.terminate()));
}

// Every call gets its own collection prefix, so tests never see each other's data.
export async function makeLedger({ allocations = {}, env = {} } = {}) {
  process.env.GCLOUD_PROJECT ||= 'demo-yaw';
  const operator = generateKeyPair();
  const fullEnv = {
    OPERATOR_PRIVATE_KEY: operator.privateKey,
    COLLECTION_PREFIX: `t${randomBytes(5).toString('hex')}_`,
    GENESIS_ALLOCATIONS: JSON.stringify(allocations),
    INSTANT_BLOCKS: 'false',
    PRODUCER_TOKEN: 'p'.repeat(40),
    LOG_LEVEL: 'silent',
    ...env,
  };
  const config = loadConfig(fullEnv);
  const db = new Firestore({ projectId: process.env.GCLOUD_PROJECT, ignoreUndefinedProperties: true });
  opened.push(db);
  const ledger = new Ledger({ db, config, log: silent });
  await ledger.init();
  return { ledger, db, config, env: fullEnv, operator };
}
