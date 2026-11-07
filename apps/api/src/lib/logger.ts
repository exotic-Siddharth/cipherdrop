/**
 * pino logger + pino-http (spec sections 12 and 15). Zero-knowledge logging rules:
 * - request logs carry ONLY {id, method, path (no query), ipPrefix} and the status code;
 * - headers, bodies, cookies and tokens are never serialised; the redact list is a second line of defence.
 * NEVER log request bodies, authKeys, tokens, manifests or wrapped keys.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { pino, type DestinationStream, type Logger, type LoggerOptions } from 'pino';
import { pinoHttp, type HttpLogger } from 'pino-http';
import { env } from '../config/env';
import { ipPrefix } from './ip';

export type { Logger } from 'pino';

export const REDACT_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["x-owner-token"]',
  'res.headers["set-cookie"]',
  'req.body',
  'res.body',
  'body',
  'headers.authorization',
  'headers.cookie',
  '*.authKey',
  '*.currentAuthKey',
  '*.newAuthKey',
  '*.recoveryAuthKey',
  '*.password',
  '*.accessToken',
  '*.refreshToken',
  '*.ownerToken',
  '*.uploadToken',
  '*.downloadToken',
  '*.mfaToken',
  '*.recoveryToken',
  '*.wrappedAccountKey',
  '*.wrappedAccountKeyRecovery',
  '*.wrappedDropKey',
  '*.ownerWrappedKey',
  '*.encryptedManifest',
  '*.decryptionKey',
  '*.providedKey',
  '*.secret',
  '*.code',
];

export interface CreateLoggerOptions {
  level?: LoggerOptions['level'];
  /** e.g. a memory stream in tests that assert nothing sensitive is logged. */
  destination?: DestinationStream;
  pretty?: boolean;
}

export function createLogger(options: CreateLoggerOptions = {}): Logger {
  const opts: LoggerOptions = {
    level: options.level ?? env.LOG_LEVEL,
    base: { service: 'cipherdrop-api' },
    redact: { paths: REDACT_PATHS, censor: '[REDACTED]' },
  };
  if (options.destination) return pino(opts, options.destination);
  if (options.pretty ?? env.LOG_PRETTY) {
    return pino({ ...opts, transport: { target: 'pino-pretty', options: { colorize: true } } });
  }
  return pino(opts);
}

/** Default process logger. */
export const logger: Logger = createLogger();

const pathOnly = (url: string | undefined) => (url ?? '').split('?')[0] ?? '';

/** HTTP access log middleware with privacy-preserving serializers. */
export function createHttpLogger(log: Logger): HttpLogger {
  return pinoHttp({
    logger: log,
    genReqId: (req: IncomingMessage) => (req as IncomingMessage & { id?: string }).id ?? '',
    quietReqLogger: true,
    autoLogging: {
      ignore: (req: IncomingMessage) => {
        const p = pathOnly(req.url);
        return p === '/healthz' || p === '/readyz' || p === '/metrics';
      },
    },
    customLogLevel: (_req: IncomingMessage, res: ServerResponse, err?: Error) =>
      err || res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info',
    serializers: {
      req: (req: { id?: string; method?: string; url?: string; raw?: { ip?: string } }) => ({
        id: req.id,
        method: req.method,
        path: pathOnly(req.url),
        ipPrefix: ipPrefix(req.raw?.ip),
      }),
      res: (res: { statusCode?: number }) => ({ statusCode: res.statusCode }),
    },
  });
}
