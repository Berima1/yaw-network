import { loadConfig } from './config.js';
import { createLogger } from './logger.js';
import { createFirestore } from './firestore.js';
import { Ledger } from './ledger.js';
import { createApp } from './app.js';

let log = createLogger('info');

try {
  const config = loadConfig(process.env);
  log = createLogger(config.logLevel);

  const ledger = new Ledger({ db: createFirestore(), config, log });
  await ledger.init();

  const app = createApp({ ledger, config, log });
  const server = app.listen(config.port, '0.0.0.0', () => {
    log.info({ port: config.port, chainId: config.chainId, operator: ledger.operatorAddress, instantBlocks: config.instantBlocks }, 'yaw ledger api listening');
  });

  const shutdown = (signal) => {
    log.info({ signal }, 'shutting down');
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('unhandledRejection', (err) => {
    log.fatal({ err }, 'unhandled rejection');
    process.exit(1);
  });
} catch (err) {
  log.fatal({ err }, 'failed to start');
  process.exit(1);
}
