import { createHash, timingSafeEqual } from 'node:crypto';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { ApiError } from './errors.js';
import { ADDRESS_RE, HEX64_RE } from './crypto.js';

const hex = (length) => z.string().length(length).regex(/^[0-9a-f]+$/, 'lowercase hex');
const uint = z.string().regex(/^(0|[1-9][0-9]{0,15})$/, 'non-negative integer as a decimal string');

const submitSchema = z
  .object({
    publicKey: hex(66),
    to: z.string().regex(ADDRESS_RE, 'yaw address'),
    amount: uint,
    fee: uint,
    nonce: uint,
    signature: hex(128),
  })
  .strict();

const blocksQuery = z.object({
  from: z.coerce.number().int().min(0).default(0),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});

const sha = (s) => createHash('sha256').update(s).digest();
const tokenMatches = (provided, expected) => timingSafeEqual(sha(provided), sha(expected));
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

export function createApp({ ledger, config, log }) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1); // Cloud Run puts exactly one proxy in front of the container
  app.use(helmet());
  app.use(cors({ origin: config.corsOrigins.length > 0 ? config.corsOrigins : false }));
  app.use(compression());
  app.use(express.json({ limit: '16kb' }));
  app.use((req, res, next) => {
    const start = process.hrtime.bigint();
    res.on('finish', () => {
      if (req.path === '/health') return;
      log.info({ method: req.method, path: req.path, status: res.statusCode, ms: Number(process.hrtime.bigint() - start) / 1e6 }, 'request');
    });
    next();
  });

  const limiter = rateLimit({
    windowMs: 60_000,
    limit: config.rateLimitPerMinute,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: { code: 'rate_limited', message: 'too many requests' } },
  });
  const txLimiter = rateLimit({
    windowMs: 60_000,
    limit: config.txRateLimitPerMinute,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: { code: 'rate_limited', message: 'too many transactions submitted' } },
  });

  // Liveness: no dependencies. Readiness: proves Firestore is reachable and the chain exists.
  app.get('/health', (req, res) => res.json({ status: 'ok' }));
  app.get('/ready', async (req, res) => {
    try {
      await ledger.getChainInfo();
      res.json({ status: 'ready' });
    } catch (err) {
      log.error({ err }, 'readiness check failed');
      res.status(503).json({ status: 'unavailable' });
    }
  });

  const api = express.Router();
  api.get('/chain', wrap(async (req, res) => res.json(await ledger.getChainInfo())));
  api.get('/accounts/:address', wrap(async (req, res) => res.json(await ledger.getAccount(req.params.address))));
  api.get('/blocks', wrap(async (req, res) => {
    const { from, limit } = blocksQuery.parse(req.query);
    res.json({ blocks: await ledger.listBlocks(from, limit) });
  }));
  api.get('/blocks/:height', wrap(async (req, res) => {
    if (!/^\d{1,12}$/.test(req.params.height)) throw new ApiError(400, 'invalid_height', 'height must be a non-negative integer');
    res.json(await ledger.getBlock(Number(req.params.height)));
  }));
  api.get('/transactions/:id', wrap(async (req, res) => {
    if (!HEX64_RE.test(req.params.id)) throw new ApiError(400, 'invalid_transaction_id', 'transaction id must be 64 lowercase hex characters');
    res.json(await ledger.getTransaction(req.params.id));
  }));
  api.post('/transactions', txLimiter, wrap(async (req, res) => {
    const body = submitSchema.parse(req.body);
    const { id } = await ledger.submitTransaction(body);
    if (config.instantBlocks) {
      try {
        await ledger.produceBlock();
      } catch (err) {
        log.error({ err }, 'instant block production failed; transaction stays pending');
      }
    }
    const tx = await ledger.getTransaction(id);
    res.status(tx.status === 'pending' ? 202 : 201).json(tx);
  }));
  app.use('/v1', limiter, api);

  // Operator endpoints. Fail closed: disabled unless PRODUCER_TOKEN is configured.
  const internal = express.Router();
  internal.use((req, res, next) => {
    if (!config.producerToken) return next(new ApiError(503, 'disabled', 'internal endpoints are disabled'));
    const match = /^Bearer (.+)$/.exec(req.get('authorization') || '');
    if (!match || !tokenMatches(match[1], config.producerToken)) return next(new ApiError(401, 'unauthorized', 'invalid token'));
    next();
  });
  internal.post('/produce-block', wrap(async (req, res) => {
    const block = await ledger.produceBlock();
    res.json({ produced: block !== null, block });
  }));
  internal.get('/audit', wrap(async (req, res) => {
    const [supply, chain] = await Promise.all([ledger.auditSupply(), ledger.verifyChain({ deep: true })]);
    res.json({ ok: supply.ok && chain.ok, supply, chain });
  }));
  app.use('/internal', limiter, internal);

  app.use((req, res, next) => next(new ApiError(404, 'not_found', 'route not found')));

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err instanceof ApiError) {
      return res.status(err.status).json({ error: { code: err.code, message: err.message, details: err.details } });
    }
    if (err instanceof z.ZodError) {
      return res.status(400).json({
        error: {
          code: 'invalid_request',
          message: 'request validation failed',
          details: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
        },
      });
    }
    if (err?.type === 'entity.parse.failed') return res.status(400).json({ error: { code: 'invalid_json', message: 'body is not valid JSON' } });
    if (err?.type === 'entity.too.large') return res.status(413).json({ error: { code: 'too_large', message: 'body too large' } });
    log.error({ err }, 'unhandled error');
    return res.status(500).json({ error: { code: 'internal', message: 'internal error' } });
  });

  return app;
}
