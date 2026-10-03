import pino from 'pino';

// Cloud Logging reads `severity` and `message` from JSON log lines.
const SEVERITY = { trace: 'DEBUG', debug: 'DEBUG', info: 'INFO', warn: 'WARNING', error: 'ERROR', fatal: 'CRITICAL' };

export function createLogger(level = 'info') {
  return pino({
    level,
    base: null,
    messageKey: 'message',
    timestamp: pino.stdTimeFunctions.isoTime,
    formatters: { level: (label) => ({ severity: SEVERITY[label] ?? 'DEFAULT' }) },
  });
}
