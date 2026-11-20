/**
 * pino logger + pino-http (spec sections 12 and 15). Zero-knowledge logging rules:
 * - request logs carry ONLY {id, method, path (no query), ipPrefix} and the status code;
 * - headers, bodies, cookies and tokens are never serialised; the redact list is a second line of defence;
 * - Prisma errors are logged as safe fields only (their messages can carry query arguments, see below).
 * NEVER log request bodies, authKeys, tokens, manifests or wrapped keys.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Prisma } from '@prisma/client';
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

/**
 * Prisma renders the arguments of a failed call (a reporter's decryption key, a manifest, a token hash) into
 * the message, and so the stack, of a PrismaClientValidationError, even with errorFormat 'minimal'; a failed
 * raw query carries the database's own message, values included, in `meta`. Redaction works on paths, not on
 * text inside a message, so a Prisma error is logged as safe fields only: its class, its code, the schema
 * names in `meta` and the stack frames without the message.
 */
const PRISMA_ERRORS = [
  Prisma.PrismaClientKnownRequestError,
  Prisma.PrismaClientValidationError,
  Prisma.PrismaClientUnknownRequestError,
  Prisma.PrismaClientRustPanicError,
  Prisma.PrismaClientInitializationError,
];
const PRISMA_META_KEYS = ['modelName', 'target', 'constraint', 'field_name'];

function isPrismaError(err: Error): boolean {
  // The name test also covers errors of another copy of the client (e.g. a CLI script's).
  return PRISMA_ERRORS.some((C) => err instanceof C) || /^PrismaClient\w*Error$/.test(err.name);
}

/** The `at ...` lines of the stack, without the message lines in front of them. */
function stackFrames(err: Error): string {
  const stack = err.stack ?? '';
  const header = `${err.name}: ${err.message}`;
  const frames = stack.startsWith(header) ? stack.slice(header.length) : stack;
  return frames
    .split('\n')
    .filter((line) => /^\s+at /.test(line))
    .join('\n');
}

function prismaErrorFields(err: Error): Record<string, unknown> {
  const { code, errorCode, meta } = err as Error & {
    code?: unknown;
    errorCode?: unknown;
    meta?: unknown;
  };
  const safeMeta: Record<string, unknown> = {};
  if (meta && typeof meta === 'object') {
    for (const key of PRISMA_META_KEYS) {
      const v = (meta as Record<string, unknown>)[key];
      const names = Array.isArray(v) && v.every((x) => typeof x === 'string');
      if (typeof v === 'string' || names) safeMeta[key] = v;
    }
  }
  const prismaCode = code ?? errorCode;
  return {
    type: err.name,
    // Not `code`: REDACT_PATHS censors every `*.code` (TOTP codes).
    ...(typeof prismaCode === 'string' ? { prismaCode } : {}),
    ...(Object.keys(safeMeta).length > 0 ? { meta: safeMeta } : {}),
    stack: stackFrames(err),
  };
}

const causeOf = (err: Error): unknown => (err as { cause?: unknown }).cause;

function involvesPrisma(err: Error, depth = 0): boolean {
  if (isPrismaError(err)) return true;
  const cause = causeOf(err);
  return depth < 8 && cause instanceof Error && involvesPrisma(cause, depth + 1);
}

/**
 * The `err` serializer of every logger createLogger() builds: pino's standard one, except for Prisma errors
 * (above) and errors caused by one (pino's serializer would fold the cause's message and stack into theirs).
 */
export function serializeError(err: unknown): unknown {
  if (!(err instanceof Error) || !involvesPrisma(err)) {
    return pino.stdSerializers.err(err as Error);
  }
  if (isPrismaError(err)) return prismaErrorFields(err);
  return {
    type: err.name,
    message: err.message,
    stack: err.stack,
    cause: serializeError(causeOf(err)),
  };
}

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
    serializers: { err: serializeError },
    hooks: {
      // log.error(err) without a message makes pino copy err.message into `msg`, past the serializer.
      logMethod(args, method) {
        const [first, second] = args as unknown[];
        if (first instanceof Error && involvesPrisma(first) && typeof second !== 'string') {
          method.apply(this, [first, first.name]);
          return;
        }
        method.apply(this, args);
      },
    },
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
