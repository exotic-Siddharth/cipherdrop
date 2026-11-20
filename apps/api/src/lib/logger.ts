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
 * raw query carries the database's own message, values included, in its message and `meta`. Redaction works
 * on paths, not on text inside a message, so a Prisma error is logged as safe fields only: its class, its
 * code, the schema names in `meta` and the stack frames without the message.
 */
const PRISMA_ERRORS = [
  Prisma.PrismaClientKnownRequestError,
  Prisma.PrismaClientValidationError,
  Prisma.PrismaClientUnknownRequestError,
  Prisma.PrismaClientRustPanicError,
  Prisma.PrismaClientInitializationError,
];
const PRISMA_ERROR_NAME = /^PrismaClient\w*Error$/;
const PRISMA_META_KEYS = ['modelName', 'target', 'constraint', 'field_name'];
/**
 * Except the message of an initialization error: it says why the client could not start or connect (server
 * unreachable, bad credentials, missing engine), which is the reason a failed start needs, and it is written
 * before or outside any call, so it never holds a call's arguments.
 */
const KEEPS_MESSAGE = new Set(['PrismaClientInitializationError']);

/** An Error, or what pino-std-serializers made of one: a plain object with the class name in `type`. */
interface ErrorLike {
  name?: unknown;
  type?: unknown;
  message?: unknown;
  stack?: unknown;
  code?: unknown;
  errorCode?: unknown;
  meta?: unknown;
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null;

/** The class name of an Error, or the `type` of a serialized one. */
function errorName(err: ErrorLike): string | undefined {
  if (err instanceof Error) return err.name;
  return typeof err.type === 'string' ? err.type : undefined;
}

function isPrismaError(err: unknown): err is ErrorLike {
  if (err instanceof Error && PRISMA_ERRORS.some((C) => err instanceof C)) return true;
  // The name test also covers errors of another copy of the client (e.g. a CLI script's) and errors that
  // were already serialized (pino-http runs pino's own err serializer before this one).
  const name = isRecord(err) ? errorName(err) : undefined;
  return name !== undefined && PRISMA_ERROR_NAME.test(name);
}

/** pino-std-serializers keeps the error it serialized as the non-enumerable `raw` of its output. */
function rawError(value: unknown): Error | undefined {
  if (!isRecord(value) || value instanceof Error) return undefined;
  const raw = (value as { raw?: unknown }).raw;
  return raw instanceof Error ? raw : undefined;
}

/** The `at ...` lines of the stack, without the message lines in front of them. */
function stackFrames(err: ErrorLike, name: string): string {
  const stack = typeof err.stack === 'string' ? err.stack : '';
  const header = `${name}: ${typeof err.message === 'string' ? err.message : ''}`;
  const frames = stack.startsWith(header) ? stack.slice(header.length) : stack;
  return frames
    .split('\n')
    .filter((line) => /^\s+at /.test(line))
    .join('\n');
}

function prismaErrorFields(err: ErrorLike): Record<string, unknown> {
  const { code, errorCode, meta, message } = err;
  const type = errorName(err) ?? 'PrismaClientError';
  const safeMeta: Record<string, unknown> = {};
  if (isRecord(meta)) {
    for (const key of PRISMA_META_KEYS) {
      const v = meta[key];
      const names = Array.isArray(v) && v.every((x) => typeof x === 'string');
      if (typeof v === 'string' || names) safeMeta[key] = v;
    }
  }
  const prismaCode = code ?? errorCode;
  return {
    type,
    ...(KEEPS_MESSAGE.has(type) && typeof message === 'string' ? { message } : {}),
    // Not `code`: REDACT_PATHS censors every `*.code` (TOTP codes).
    ...(typeof prismaCode === 'string' ? { prismaCode } : {}),
    ...(Object.keys(safeMeta).length > 0 ? { meta: safeMeta } : {}),
    stack: stackFrames(err, type),
  };
}

/**
 * The errors an error carries, each of which pino would serialize with its own serializer: the cause, the
 * errors of an AggregateError and errors held in its own properties.
 */
function nestedErrors(err: Error): unknown[] {
  const { cause, errors } = err as { cause?: unknown; errors?: unknown };
  return [
    ...(cause === undefined ? [] : [cause]),
    ...(Array.isArray(errors) ? (errors as unknown[]) : []),
    ...Object.values(err).filter((v) => v instanceof Error),
  ];
}

function involvesPrisma(err: unknown, seen = new Set<unknown>()): boolean {
  if (isPrismaError(err)) return true;
  if (!(err instanceof Error) || seen.has(err)) return false;
  seen.add(err);
  return nestedErrors(err).some((e) => involvesPrisma(e, seen));
}

function serialize(err: unknown, seen: Set<unknown>): unknown {
  if (isPrismaError(err)) return prismaErrorFields(err);
  if (!(err instanceof Error) || !involvesPrisma(err)) {
    return pino.stdSerializers.err(err as Error);
  }
  if (seen.has(err)) return '[Circular]';
  seen.add(err);
  // What pino's serializer makes of it, except that pino would fold the cause's message and stack into this
  // error's and serialize every nested error with itself, past the Prisma rules above.
  const out: Record<string, unknown> = { type: err.name, message: err.message, stack: err.stack };
  for (const [key, value] of Object.entries(err)) {
    if (key in out || key === 'cause' || key === 'errors') continue;
    out[key] = value instanceof Error ? serialize(value, seen) : value;
  }
  const { cause, errors } = err as { cause?: unknown; errors?: unknown };
  if (Array.isArray(errors)) out.aggregateErrors = errors.map((e: unknown) => serialize(e, seen));
  if (cause !== undefined) out.cause = serialize(cause, seen);
  return out;
}

/**
 * The `err` serializer of every logger createLogger() and createHttpLogger() build: pino's standard one,
 * except for Prisma errors (above) and errors that carry one. pino-http hands it pino's own serialization of
 * the error, so that is traced back to the error it came from.
 */
export function serializeError(err: unknown): unknown {
  const raw = rawError(err);
  if (raw) return involvesPrisma(raw) ? serialize(raw, new Set()) : err;
  return serialize(err, new Set());
}

/**
 * The error whose message pino would copy into `msg` for these log arguments, past the serializer: the error
 * itself in log.error(err), the `err` of log.error({ err }), when no message string follows.
 */
function errorBehindMessage(args: unknown[]): unknown {
  const [first, second] = args;
  if (typeof second === 'string') return undefined;
  if (first instanceof Error) return first;
  return isRecord(first) && first.msg === undefined ? first.err : undefined;
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
      logMethod(args, method) {
        const behind = errorBehindMessage(args);
        const err = rawError(behind) ?? behind;
        if (isPrismaError(err)) {
          // The class name stands in for the message.
          method.apply(this, [args[0], errorName(err) ?? 'Prisma error']);
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
      // Without it, pino-http's child logger (req.log, res.err) would use pino's own err serializer.
      err: serializeError,
    },
  });
}
