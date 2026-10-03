import { z } from 'zod';
import { ADDRESS_RE } from './crypto.js';

const bool = (fallback) => z.enum(['true', 'false']).default(fallback).transform((v) => v === 'true');

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(8080),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  CHAIN_ID: z.string().regex(/^[a-z0-9-]{3,32}$/, 'lowercase letters, digits and dashes, 3-32 chars').default('yaw-testnet-1'),
  COLLECTION_PREFIX: z.string().regex(/^[a-z0-9_]{0,24}$/, 'lowercase letters, digits, underscore, max 24').default(''),
  OPERATOR_PRIVATE_KEY: z.string().regex(/^[0-9a-f]{64}$/, 'must be 64 lowercase hex characters'),
  FEE_RECIPIENT: z.string().regex(ADDRESS_RE, 'must be a yaw address').optional(),
  MIN_FEE: z.coerce.number().int().min(0).default(0),
  MAX_TX_PER_BLOCK: z.coerce.number().int().min(1).max(80).default(50),
  INSTANT_BLOCKS: bool('true'),
  PRODUCER_TOKEN: z.string().min(32).optional(),
  GENESIS_ALLOCATIONS: z.string().default('{}'),
  CORS_ORIGINS: z.string().default(''),
  RATE_LIMIT_PER_MINUTE: z.coerce.number().int().min(1).default(120),
  TX_RATE_LIMIT_PER_MINUTE: z.coerce.number().int().min(1).default(30),
});

export const MAX_GENESIS_ACCOUNTS = 400;

function parseAllocations(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('Invalid configuration: GENESIS_ALLOCATIONS must be valid JSON');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Invalid configuration: GENESIS_ALLOCATIONS must be a JSON object of address -> amount');
  }
  const entries = Object.entries(parsed);
  if (entries.length > MAX_GENESIS_ACCOUNTS) {
    throw new Error(`Invalid configuration: GENESIS_ALLOCATIONS has more than ${MAX_GENESIS_ACCOUNTS} accounts`);
  }
  let total = 0;
  for (const [address, amount] of entries) {
    if (!ADDRESS_RE.test(address)) throw new Error(`Invalid configuration: bad genesis address ${address}`);
    if (!Number.isSafeInteger(amount) || amount < 1) {
      throw new Error(`Invalid configuration: genesis amount for ${address} must be a positive safe integer`);
    }
    total += amount;
    if (!Number.isSafeInteger(total)) throw new Error('Invalid configuration: genesis total supply exceeds the safe integer range');
  }
  return parsed;
}

export function loadConfig(env = process.env) {
  const result = envSchema.safeParse(env);
  if (!result.success) {
    const lines = result.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`);
    throw new Error(`Invalid configuration:\n${lines.join('\n')}`);
  }
  const e = result.data;
  const genesisAllocations = parseAllocations(e.GENESIS_ALLOCATIONS);

  if (!e.INSTANT_BLOCKS && !e.PRODUCER_TOKEN) {
    throw new Error('Invalid configuration: no block production path (set INSTANT_BLOCKS=true or PRODUCER_TOKEN)');
  }

  return {
    nodeEnv: e.NODE_ENV,
    port: e.PORT,
    logLevel: e.LOG_LEVEL,
    chainId: e.CHAIN_ID,
    collectionPrefix: e.COLLECTION_PREFIX,
    operatorPrivateKey: e.OPERATOR_PRIVATE_KEY,
    feeRecipient: e.FEE_RECIPIENT,
    minFee: e.MIN_FEE,
    maxTxPerBlock: e.MAX_TX_PER_BLOCK,
    instantBlocks: e.INSTANT_BLOCKS,
    producerToken: e.PRODUCER_TOKEN,
    genesisAllocations,
    corsOrigins: e.CORS_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean),
    rateLimitPerMinute: e.RATE_LIMIT_PER_MINUTE,
    txRateLimitPerMinute: e.TX_RATE_LIMIT_PER_MINUTE,
  };
}
